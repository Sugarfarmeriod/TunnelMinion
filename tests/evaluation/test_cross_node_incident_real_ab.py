"""真实跨节点 incident 验收脚本的默认边界与固定判定测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI
from scripts.run_cross_node_incident_real_ab import (
    _stop_when_requested,  # pyright: ignore[reportPrivateUsage]
    main,
    validate_ports,
)


def test_default_mode_only_prints_zero_side_effect_manifest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["run", "--ssh-target", "10.77.0.1"]) == 0

    manifest = json.loads(capsys.readouterr().out)
    assert manifest["requires_explicit_execute_flag"] is True
    assert manifest["temporary_bindings"] == {
        "gateway": "10.77.0.1:18889",
        "loopback_service": "127.0.0.1:18888",
    }
    assert "现有 8080/8787 进程" in manifest["does_not_modify"]
    assert "操作系统 Keyring/Keychain 或任何用户秘密" in manifest["does_not_modify"]


def test_execute_mode_requires_output() -> None:
    with pytest.raises(SystemExit, match="--output"):
        main(["run", "--ssh-target", "10.77.0.1", "--execute-approved"])


def test_target_stops_only_after_its_private_marker(tmp_path: Path) -> None:
    marker = tmp_path / "stop"
    marker.touch()
    server = uvicorn.Server(uvicorn.Config(FastAPI()))

    asyncio.run(_stop_when_requested(marker, server))

    assert server.should_exit is True


@pytest.mark.parametrize("ports", [(8080, 18888), (18889, 8787), (18889, 18889)])
def test_temporary_ports_never_overlap_production_or_each_other(
    ports: tuple[int, int],
) -> None:
    with pytest.raises(ValueError):
        validate_ports(*ports)
