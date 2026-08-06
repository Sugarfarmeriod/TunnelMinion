"""独立 peer acceptance runner 的只读输出测试。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import httpx
import pytest
from scripts import run_runtime_health_peer_acceptance as runner

from tunnelminion.runtime.acceptance import PeerAcceptanceProbe


def _manifest() -> dict[str, object]:
    return {
        "candidate": {
            "id": "tunnelminion-test-win32-amd64",
            "application_version": "0.1.0",
            "platform": "win32",
            "architecture": "amd64",
        },
        "entrypoint": "tunnelminion.exe",
        "entrypoint_args": [],
        "files": [{"path": "tunnelminion.exe", "sha256": "a" * 64, "size": 1}],
    }


def test_runner_returns_independent_redacted_peer_result(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/capabilities"
        assert "authorization" not in request.headers
        return httpx.Response(401, request=request, text="unauthorized")

    report = runner.run_acceptance(
        "http://peer.example:8787",
        manifest_path,
        probe=PeerAcceptanceProbe(transport=httpx.MockTransport(handler)),
    )

    assert report["mode"] == "independent_peer_probe"
    assert report["local_lifecycle_dependency"] is False
    assert report["runtime_state_written"] is False
    assert report["secret_store_read"] is False
    serialized = json.dumps(report)
    assert "peer.example" not in serialized
    assert "unauthorized" not in serialized
    assert cast(dict[str, object], report["peer"])["accepted"] is True


def test_runner_main_writes_report_and_propagates_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
    output = tmp_path / "report.json"
    report: dict[str, object] = {
        "peer": {"accepted": True},
        "schema_version": runner.REPORT_VERSION,
    }

    def fake_acceptance(endpoint: str, manifest: Path) -> dict[str, object]:
        del endpoint, manifest
        return report

    monkeypatch.setattr(runner, "run_acceptance", fake_acceptance)

    assert (
        runner.main(
            [
                "--endpoint",
                "http://peer.example:8787",
                "--manifest",
                str(manifest_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert json.loads(capsys.readouterr().out) == report
