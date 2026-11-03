"""下载、校验并解开一个发布版运行包，放进版本目录。"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import httpx
from jsonschema.exceptions import SchemaError, ValidationError

from tunnelminion.runtime.install import (
    PACKAGE_MANIFEST_FILE,
    InstalledPackage,
    RuntimePackageInstaller,
)
from tunnelminion.update.release import ReleaseAsset, ReleaseFeedError, require_download_url

MAX_EXTRACTED_BYTES = 4 << 30
_PACKAGE_ROOT = "package"
_CHUNK = 1024 * 1024

Progress = Callable[[int, int], None]


class UpdatePackageError(RuntimeError):
    """下载或校验失败的稳定错误码。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def download_asset(
    asset: ReleaseAsset,
    destination: Path,
    *,
    allow_loopback_http: bool = False,
    transport: httpx.BaseTransport | None = None,
    progress: Progress | None = None,
    timeout_seconds: float = 60.0,
) -> Path:
    """下载到 `.part` 临时文件，大小和 sha256 都对上才改成正式文件名。

    中途断开、多出或少了字节、摘要不符，都删掉临时文件并报错，不留半个包。
    """
    try:
        require_download_url(asset.url, allow_loopback_http=allow_loopback_http)
    except ReleaseFeedError as exc:
        raise UpdatePackageError(exc.code) from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(f"{destination.name}.part")
    partial.unlink(missing_ok=True)
    digest = hashlib.sha256()
    received = 0
    try:
        with (
            httpx.Client(
                transport=transport,
                trust_env=not allow_loopback_http,
                follow_redirects=True,
                timeout=timeout_seconds,
                headers={"User-Agent": "TunnelMinion-updater"},
            ) as client,
            client.stream("GET", asset.url) as response,
        ):
            if response.status_code != 200:
                raise UpdatePackageError("download_failed")
            try:
                require_download_url(str(response.url), allow_loopback_http=allow_loopback_http)
            except ReleaseFeedError as exc:
                raise UpdatePackageError(exc.code) from exc
            with partial.open("wb") as stream:
                for chunk in response.iter_bytes(_CHUNK):
                    received += len(chunk)
                    if received > asset.size:
                        raise UpdatePackageError("size_mismatch")
                    digest.update(chunk)
                    stream.write(chunk)
                    if progress is not None:
                        progress(received, asset.size)
        if received != asset.size:
            raise UpdatePackageError("download_incomplete")
        if digest.hexdigest() != asset.sha256:
            raise UpdatePackageError("checksum_mismatch")
        os.replace(partial, destination)
    except httpx.HTTPError as exc:
        partial.unlink(missing_ok=True)
        raise UpdatePackageError("download_failed") from exc
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return destination


def _member_path(name: str) -> PurePosixPath:
    """只接受 `package/` 下不含跳转的相对路径。"""
    if "\\" in name or ":" in name:
        raise UpdatePackageError("archive_invalid")
    path = PurePosixPath(name)
    parts = [part for part in path.parts if part not in {"", "."}]
    if path.is_absolute() or not parts or parts[0] != _PACKAGE_ROOT or ".." in parts:
        raise UpdatePackageError("archive_invalid")
    return PurePosixPath(*parts)


def extract_package(archive: Path, destination: Path) -> Path:
    """解开运行包压缩包，只允许普通文件和目录；返回其中的 `package/` 目录。"""
    root = destination.resolve()
    total = 0
    try:
        with tarfile.open(archive, "r:*") as bundle:
            for member in bundle:
                relative = _member_path(member.name)
                target = root.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isreg():
                    raise UpdatePackageError("archive_invalid")
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise UpdatePackageError("archive_too_large")
                source = bundle.extractfile(member)
                if source is None:  # pragma: no cover - 普通文件总能读出内容
                    raise UpdatePackageError("archive_invalid")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as stream:
                    shutil.copyfileobj(source, stream, _CHUNK)
                # Windows 上 chmod 只影响只读标记，两种取值都保持可写
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    except (tarfile.TarError, EOFError, FileExistsError) as exc:
        raise UpdatePackageError("archive_invalid") from exc
    package_root = root / _PACKAGE_ROOT
    if not (package_root / PACKAGE_MANIFEST_FILE).is_file():
        raise UpdatePackageError("archive_invalid")
    return package_root


def stage_archive(
    installer: RuntimePackageInstaller,
    archive: Path,
    work_dir: Path,
    *,
    release_tag: str | None = None,
) -> InstalledPackage:
    """解包到临时目录、逐文件校验后放进版本目录；临时目录无论成败都删掉。"""
    work_dir.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".extract-", dir=work_dir))
    try:
        package_root = extract_package(archive, temporary)
        try:
            return installer.stage(
                package_root,
                package_root / PACKAGE_MANIFEST_FILE,
                release_tag=release_tag,
            )
        except (KeyError, ValueError, ValidationError, SchemaError) as exc:
            raise UpdatePackageError("package_invalid") from exc
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
