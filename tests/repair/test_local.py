"""修复服务接进命令行和两个平台应用的组装测试；不运行任何外部命令。"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from tunnelminion import cli
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.app import build_windows_application
from tunnelminion.domain.tools import Platform
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.repair import local
from tunnelminion.repair.contracts import REPAIR_TOOL_NAMES
from tunnelminion.repair.service import RepairService


@pytest.mark.parametrize("platform", (Platform.WINDOWS, Platform.MACOS))
def test_local_service_opens_only_local_storage(tmp_path: Path, platform: Platform) -> None:
    service = local.build_local_repair_service(tmp_path / "data", platform=platform)
    assert isinstance(service, RepairService)
    assert service.list() == ()
    assert (tmp_path / "data" / "node-id").exists()
    assert (tmp_path / "data" / "runtime.sqlite3").exists()


@pytest.mark.parametrize(("system", "expected"), (("darwin", "MacOS"), ("win32", "Psutil")))
def test_local_service_defaults_follow_this_computer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, system: str, expected: str
) -> None:
    readers: list[str] = []
    original = local.build_node_repair_service

    def capture(**kwargs: Any) -> RepairService:
        readers.append(type(kwargs["system_reader"]).__name__)
        return original(**kwargs)

    monkeypatch.setattr(local.sys, "platform", system)
    monkeypatch.setattr(local, "build_node_repair_service", capture)
    monkeypatch.setattr(
        "tunnelminion.runtime.profile.default_runtime_data_dir", lambda: tmp_path / "default"
    )
    local.build_local_repair_service()
    assert readers[0].startswith(expected)
    assert (tmp_path / "default" / "node-id").exists()


def test_cli_default_factory_uses_local_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path | None] = []
    sentinel = cast(RepairService, object())

    def build(data_dir: Path | None) -> RepairService:
        calls.append(data_dir)
        return sentinel

    monkeypatch.setattr(local, "build_local_repair_service", build)
    assert cli._local_repair_service(tmp_path) is sentinel  # pyright: ignore[reportPrivateUsage]
    assert calls == [tmp_path]


def _observer_kwargs(monkeypatch: pytest.MonkeyPatch, module: str) -> list[dict[str, Any]]:
    captured: list[dict[str, Any]] = []

    class Recording(DeterministicServiceObserver):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.append(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(f"{module}.DeterministicServiceObserver", Recording)
    return captured


@pytest.mark.parametrize("preview", (False, True))
def test_both_applications_expose_local_repairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, preview: bool
) -> None:
    def no_password(*_args: object) -> None:
        return None

    monkeypatch.setattr("keyring.get_password", no_password)
    windows_kwargs = _observer_kwargs(monkeypatch, "tunnelminion.app")
    macos_kwargs = _observer_kwargs(monkeypatch, "tunnelminion.macos_app")
    windows = build_windows_application(tmp_path / "windows", read_only_preview=preview)
    macos = build_macos_local_application(tmp_path / "macos", read_only_preview=preview)

    for kwargs in (windows_kwargs, macos_kwargs):
        assert (kwargs[0]["launch_recorder"] is None) is preview
    registries = (
        (windows.tool_registry, Platform.WINDOWS),
        (macos.node.tool_registry, Platform.MACOS),
    )
    for registry, platform in registries:
        capabilities = {item.name for item in registry.capabilities(platform)}
        model_tools = {item.name for item in registry.model_tools(platform)}
        assert set(REPAIR_TOOL_NAMES.values()) <= capabilities
        assert not set(REPAIR_TOOL_NAMES.values()) & model_tools

    for bundle in (windows, macos):
        assert bundle.repair_service.list() == ()
        client: Any = TestClient(bundle.app, base_url="http://127.0.0.1")
        assert client.get("/api/repairs").json() == {"repairs": []}
        missing = "/api/repairs/operation_" + "0" * 32 + "/approve"
        assert client.post(missing, headers={"Origin": "https://evil.example"}).status_code == 403
        remote: Any = TestClient(bundle.app, base_url="http://192.0.2.10")
        assert remote.get("/api/repairs").status_code == 403
