"""生成物秘密扫描的 fail-closed 契约。"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.security_scan import artifact_files, scan_files


def test_artifact_scan_reads_ignored_source_map_and_hides_secret(tmp_path: Path) -> None:
    artifact = tmp_path / "dist"
    artifact.mkdir()
    source_map = artifact / "app.js.map"
    secret = "tmn_abcdefghijklmnopqrstuvwxyz1234567890"
    source_map.write_bytes(b"\xff\xfe" + secret.encode())

    findings = scan_files(artifact_files(tmp_path, (Path("dist"),)), allow_placeholders=False)

    assert [(item.path, item.line, item.pattern) for item in findings] == [
        (source_map, 1, "gateway-token")
    ]
    assert secret not in repr(findings)


def test_artifact_paths_must_exist_and_stay_inside_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-artifact"
    outside.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="不存在"):
        artifact_files(tmp_path, (Path("missing"),))
    with pytest.raises(ValueError, match="逃出仓库"):
        artifact_files(tmp_path, (outside,))


def test_artifact_disables_source_placeholder_exemption(tmp_path: Path) -> None:
    artifact = tmp_path / "dist"
    artifact.mkdir()
    path = artifact / "example.js"
    path.write_text("const example = 'sk-abcdefghijklmnop1234';", encoding="utf-8")

    assert scan_files((path,)) == ()
    assert scan_files((path,), allow_placeholders=False)[0].pattern == "openai-style-key"
