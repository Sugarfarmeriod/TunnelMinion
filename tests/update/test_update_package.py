"""下载、整包校验、安全解包和放进版本目录的测试。"""

from __future__ import annotations

import hashlib
import os
import tarfile
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from tests.update.conftest import build_archive, build_package, tar_with

from tunnelminion.runtime.install import RuntimePackageInstaller
from tunnelminion.update import package as package_module
from tunnelminion.update.package import (
    UpdatePackageError,
    download_asset,
    extract_package,
    stage_archive,
)
from tunnelminion.update.release import ReleaseAsset

BODY = b"0123456789" * 50


def _asset(body: bytes = BODY, *, url: str = "https://dl.example.test/a.tar.gz") -> ReleaseAsset:
    return ReleaseAsset(
        name="a.tar.gz",
        url=url,
        size=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )


def _transport(body: bytes, status: int = 200) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, content=body))


def test_download_checks_size_and_digest_and_reports_progress(tmp_path: Path) -> None:
    progress: list[tuple[int, int]] = []
    target = download_asset(
        _asset(),
        tmp_path / "dl" / "a.tar.gz",
        transport=_transport(BODY),
        progress=lambda received, total: progress.append((received, total)),
    )
    assert target.read_bytes() == BODY
    assert progress[-1] == (len(BODY), len(BODY))
    assert not (tmp_path / "dl" / "a.tar.gz.part").exists()


def test_download_without_progress_callback(tmp_path: Path) -> None:
    target = download_asset(_asset(), tmp_path / "a.tar.gz", transport=_transport(BODY))
    assert target.read_bytes() == BODY


@pytest.mark.parametrize(
    ("served", "status", "code"),
    [
        (BODY + b"extra", 200, "size_mismatch"),
        (BODY[:-1], 200, "download_incomplete"),
        (BODY[::-1], 200, "checksum_mismatch"),
        (BODY, 404, "download_failed"),
    ],
)
def test_download_failures_leave_no_partial_file(
    tmp_path: Path, served: bytes, status: int, code: str
) -> None:
    destination = tmp_path / "a.tar.gz"
    with pytest.raises(UpdatePackageError) as caught:
        download_asset(_asset(), destination, transport=_transport(served, status))
    assert caught.value.code == code
    assert list(tmp_path.iterdir()) == []


class _BrokenStream(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield BODY[:100]
        raise httpx.ReadError("connection reset")


def test_interrupted_download_is_removed(tmp_path: Path) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=_BrokenStream()))
    with pytest.raises(UpdatePackageError) as caught:
        download_asset(_asset(), tmp_path / "a.tar.gz", transport=transport)
    assert caught.value.code == "download_failed"
    assert list(tmp_path.iterdir()) == []


def test_download_rejects_plain_http_and_http_redirects(tmp_path: Path) -> None:
    with pytest.raises(UpdatePackageError) as caught:
        download_asset(_asset(url="http://dl.example.test/a"), tmp_path / "a")
    assert caught.value.code == "download_url_rejected"

    def redirect(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"Location": "http://dl.example.test/a"})
        return httpx.Response(200, content=BODY)

    with pytest.raises(UpdatePackageError) as caught:
        download_asset(_asset(), tmp_path / "a", transport=httpx.MockTransport(redirect))
    assert caught.value.code == "download_url_rejected"
    assert list(tmp_path.iterdir()) == []


def test_download_allows_loopback_http_only_in_test_source_mode(tmp_path: Path) -> None:
    asset = _asset(url="http://127.0.0.1:9/a.tar.gz")
    target = download_asset(
        asset, tmp_path / "a", allow_loopback_http=True, transport=_transport(BODY)
    )
    assert target.read_bytes() == BODY


def test_extract_and_stage_a_real_archive(tmp_path: Path) -> None:
    package = build_package(tmp_path / "src", "pkg-new", b"new")
    os.chmod(package / "app.bin", 0o755)
    archive = build_archive(package, tmp_path / "pkg.tar.gz")
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    staged = stage_archive(installer, archive, tmp_path / "work", release_tag="build-9")
    assert staged.package_id == "pkg-new"
    assert staged.release_tag == "build-9"
    assert staged.entrypoint == "app.bin"
    assert installer.executable("pkg-new").read_bytes() == b"new"
    assert list((tmp_path / "work").iterdir()) == []


def test_stage_rejects_tampered_file_inside_archive(tmp_path: Path) -> None:
    package = build_package(tmp_path / "src", "pkg-bad", b"good")
    (package / "app.bin").write_bytes(b"evil")
    archive = build_archive(package, tmp_path / "pkg.tar.gz")
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    with pytest.raises(UpdatePackageError) as caught:
        stage_archive(installer, archive, tmp_path / "work")
    assert caught.value.code == "package_invalid"
    assert installer.load().packages == ()
    assert list((tmp_path / "work").iterdir()) == []


def test_stage_rejects_extra_file_inside_archive(tmp_path: Path) -> None:
    package = build_package(tmp_path / "src", "pkg-extra", b"good")
    (package / "dropper.bin").write_bytes(b"extra")
    archive = build_archive(package, tmp_path / "pkg.tar.gz")
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    with pytest.raises(UpdatePackageError) as caught:
        stage_archive(installer, archive, tmp_path / "work")
    assert caught.value.code == "package_invalid"


def _file(name: str) -> tarfile.TarInfo:
    return tarfile.TarInfo(name)


def _special(name: str, kind: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = "package/app.bin"
    return info


@pytest.mark.parametrize(
    ("members", "code"),
    [
        ([(_file("/package/app.bin"), b"x")], "archive_invalid"),
        ([(_file("package/../escape.bin"), b"x")], "archive_invalid"),
        ([(_file("other/app.bin"), b"x")], "archive_invalid"),
        ([(_file("package\\app.bin"), b"x")], "archive_invalid"),
        ([(_file("package/C:evil"), b"x")], "archive_invalid"),
        ([(_file("."), b"x")], "archive_invalid"),
        ([(_special("package/link", tarfile.SYMTYPE), None)], "archive_invalid"),
        ([(_special("package/hard", tarfile.LNKTYPE), None)], "archive_invalid"),
        ([(_special("package/fifo", tarfile.FIFOTYPE), None)], "archive_invalid"),
        ([(_file("package/app.bin"), b"x"), (_file("package/app.bin"), b"y")], "archive_invalid"),
        ([(_file("package/app.bin"), b"x")], "archive_invalid"),
    ],
    ids=[
        "absolute",
        "parent",
        "outside-root",
        "backslash",
        "drive",
        "dot",
        "symlink",
        "hardlink",
        "fifo",
        "duplicate",
        "no-manifest",
    ],
)
def test_extract_rejects_unsafe_archives(
    tmp_path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]], code: str
) -> None:
    archive = tmp_path / "bad.tar.gz"
    archive.write_bytes(tar_with(members))
    with pytest.raises(UpdatePackageError) as caught:
        extract_package(archive, tmp_path / "out")
    assert caught.value.code == code
    assert not (tmp_path / "escape.bin").exists()


def test_extract_rejects_corrupt_and_oversized_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corrupt = tmp_path / "corrupt.tar.gz"
    corrupt.write_bytes(b"\x1f\x8bnot really gzip")
    with pytest.raises(UpdatePackageError) as caught:
        extract_package(corrupt, tmp_path / "out")
    assert caught.value.code == "archive_invalid"

    big = tmp_path / "big.tar.gz"
    big.write_bytes(tar_with([(_file("package/a.bin"), b"x" * 20)]))
    monkeypatch.setattr(package_module, "MAX_EXTRACTED_BYTES", 10)
    with pytest.raises(UpdatePackageError) as caught:
        extract_package(big, tmp_path / "out-big")
    assert caught.value.code == "archive_too_large"
