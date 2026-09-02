"""Python 依赖证据生成器契约。"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from scripts.dependency_evidence import (
    audit_vulnerability_count,
    generate_evidence,
    normalize_licenses,
)


def test_license_normalization_removes_extra_content_and_rejects_unknown() -> None:
    normalized = normalize_licenses(
        [
            {
                "Name": "Example",
                "Version": "1.0",
                "License": "MIT",
                "URL": "https://example.test",
                "LicenseText": "must-not-be-uploaded",
            }
        ]
    )
    assert normalized == [
        {
            "Name": "Example",
            "Version": "1.0",
            "License": "MIT",
            "URL": "https://example.test",
        }
    ]
    with pytest.raises(ValueError, match="未接受许可证"):
        normalize_licenses([{"Name": "Bad", "Version": "1", "License": "UNKNOWN", "URL": ""}])


def test_audit_requires_dependency_and_vulnerability_lists() -> None:
    assert audit_vulnerability_count({"dependencies": [{"name": "a", "vulns": []}]}) == 0
    assert audit_vulnerability_count({"dependencies": [{"name": "a", "vulns": [{}]}]}) == 1
    with pytest.raises(ValueError, match="完整依赖列表"):
        audit_vulnerability_count({})


def test_generate_evidence_writes_normalized_reports(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "uv.lock").write_text("version = 1", encoding="utf-8")
    output = root / "build" / "evidence"

    def run(command: Sequence[str], _cwd: Path) -> subprocess.CompletedProcess[str]:
        if command[:2] == ("uv", "export"):
            Path(command[-1]).write_text("example==1.0", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        if "pip-audit" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({"dependencies": [{"name": "example", "vulns": []}]}),
                "",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                [
                    {
                        "Name": "Example",
                        "Version": "1.0",
                        "License": "MIT",
                        "URL": "https://example.test",
                    }
                ]
            ),
            "",
        )

    generate_evidence(root, output, run)

    assert json.loads((output / "python-audit.json").read_text(encoding="utf-8"))["status"] == (
        "clean"
    )
    licenses = json.loads((output / "python-licenses.json").read_text(encoding="utf-8"))
    assert licenses["packageCount"] == 1
    assert "LicenseText" not in json.dumps(licenses)
