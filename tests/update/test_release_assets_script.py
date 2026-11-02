"""CI 发布附件脚本的测试：生成的 `release.json` 必须能被更新程序原样接受。"""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest
from scripts.build_release_assets import build_release_assets, main
from tests.update.conftest import build_package

from tunnelminion.update.package import extract_package
from tunnelminion.update.release import ReleaseMetadata


def _artifacts(tmp_path: Path) -> Path:
    root = tmp_path / "artifacts"
    for target in ("windows-amd64", "macos-arm64"):
        package = build_package(tmp_path / target, f"pkg-{target}", target.encode())
        directory = root / f"runtime-package-{target}"
        directory.mkdir(parents=True)
        with tarfile.open(directory / "runtime-package.tar", "w") as bundle:
            bundle.add(package, arcname="package")
    return root


def test_release_assets_round_trip_through_updater(tmp_path: Path) -> None:
    output = tmp_path / "out"
    metadata = build_release_assets(
        _artifacts(tmp_path), output, tag="build-12", source_revision="f" * 40
    )
    parsed = ReleaseMetadata.model_validate_json((output / "release.json").read_bytes())
    assert parsed.tag == "build-12" and set(parsed.assets) == {"windows-amd64", "macos-arm64"}
    for target, asset in parsed.assets.items():
        archive = output / asset.name
        assert archive.stat().st_size == asset.size
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == asset.sha256
        package = extract_package(archive, tmp_path / f"x-{target}")
        assert (package / "app.bin").read_bytes() == target.encode()
    # 同一份 tar 再压一次，字节完全相同
    again = tmp_path / "again"
    build_release_assets(tmp_path / "artifacts", again, tag="build-12", source_revision="f" * 40)
    for name in ("tunnelminion-windows-amd64.tar.gz", "release.json"):
        assert (again / name).read_bytes() == (output / name).read_bytes()
    assert metadata["source_revision"] == "f" * 40


def test_release_assets_reject_bad_input(tmp_path: Path) -> None:
    root = _artifacts(tmp_path)
    with pytest.raises(ValueError, match="Release"):
        build_release_assets(root, tmp_path / "o", tag="bad tag", source_revision="f" * 40)
    with pytest.raises(ValueError, match="提交号"):
        build_release_assets(root, tmp_path / "o", tag="build-1", source_revision="main")
    (root / "runtime-package-macos-arm64" / "runtime-package.tar").unlink()
    with pytest.raises(FileNotFoundError, match="macos-arm64"):
        build_release_assets(root, tmp_path / "o", tag="build-1", source_revision="f" * 40)


def test_main_prints_metadata(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _artifacts(tmp_path)
    assert (
        main(
            [
                "--artifacts-root",
                str(root),
                "--output-dir",
                str(tmp_path / "out"),
                "--tag",
                "build-3",
                "--source-revision",
                "a" * 40,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["tag"] == "build-3"
