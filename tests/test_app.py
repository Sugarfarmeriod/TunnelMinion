"""真实 Windows 应用组装、稳定 Node ID 与启动命令测试。"""

from __future__ import annotations

import asyncio
import io
import json
import runpy
from pathlib import Path
from typing import Any

import pytest
from keyring.errors import KeyringError
from pydantic import JsonValue

from tunnelminion import cli
from tunnelminion.agent.conversation import StartRunInput
from tunnelminion.app import (
    WindowsApplication,
    build_windows_application,
    create_app,
    default_data_dir,
    load_or_create_node_id,
)
from tunnelminion.domain.identifiers import RunId, ThreadId
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
)
from tunnelminion.platforms.windows.models import InterfaceSnapshot
from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest


class AppProvider:
    """应用组装测试使用的最小模型 Provider。"""

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del request, cancellation
        return ModelResponse(content="ok")


def execute_node_summary(bundle: WindowsApplication) -> dict[str, JsonValue]:
    """通过真实 Runtime 执行节点摘要。"""
    result = asyncio.run(
        bundle.tool_runtime.execute(
            ToolExecutionRequest(
                context=ToolCallContext(
                    thread_id=ThreadId.new(),
                    run_id=RunId.new(),
                    caller_node_id=bundle.node_id,
                    execution_node_id=bundle.node_id,
                ),
                tool_name="get_node_summary",
            )
        )
    )
    assert isinstance(result.output, dict)
    return result.output


def test_node_id_is_created_once_and_application_is_composed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "nested" / "node-id"
    first = load_or_create_node_id(path)
    second = load_or_create_node_id(path)
    assert first == second
    assert path.read_text(encoding="utf-8") == str(first)

    def no_password(service: str, name: str) -> None:
        del service, name
        return None

    async def wg_permission_denied(
        self: object, command: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        del self, command, timeout_seconds
        return CommandResult(returncode=1, stdout="", stderr="Permission denied")

    def interface(self: object, name: str) -> InterfaceSnapshot:
        del self
        return InterfaceSnapshot(name=name, is_up=True, addresses=("10.77.0.2",))

    monkeypatch.setattr("keyring.get_password", no_password)
    monkeypatch.setattr(
        "tunnelminion.platforms.windows.system.SubprocessCommandRunner.run",
        wg_permission_denied,
    )
    monkeypatch.setattr(
        "tunnelminion.platforms.windows.system.PsutilSystemReader.interface",
        interface,
    )
    bundle = build_windows_application(tmp_path / "app")
    paths = set(bundle.app.openapi()["paths"])
    assert "/api/model-config" in paths
    assert "/api/resources/node-summary" in paths
    assert "/api/threads" in paths
    assert "/api/runs/{value}/events" in paths
    assert "/resources" in paths
    assert bundle.node_id
    assert bundle.audit_sink.records == []
    assert bundle.tool_runtime
    assert bundle.tool_registry
    assert execute_node_summary(bundle)["model_status"] == "unconfigured"

    def create_provider(_self: ModelConfigurationService) -> AppProvider:
        return AppProvider()

    monkeypatch.setattr(ModelConfigurationService, "create_provider", create_provider)
    assert bundle.create_read_only_agent()

    async def conversation_scenario() -> ThreadId:
        thread = bundle.conversation_service.create_thread()
        started = await bundle.conversation_service.start_run(
            thread.thread_id,
            StartRunInput(question="概括状态", tool_names=("get_node_summary",)),
        )
        _ = [event async for event in bundle.conversation_service.stream_events(started.run_id)]
        return thread.thread_id

    persisted_thread_id = asyncio.run(conversation_scenario())
    restarted = build_windows_application(tmp_path / "app")
    assert restarted.conversation_service.get_thread(persisted_thread_id).thread.message_count == 2

    def keyring_failure(service: str, name: str) -> None:
        del service, name
        raise KeyringError("unavailable")

    monkeypatch.setattr("keyring.get_password", keyring_failure)
    assert execute_node_summary(bundle)["model_status"] == "unconfigured"


def test_default_app_factory_and_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tunnelminion.app.default_data_dir", lambda: tmp_path)
    app = create_app()
    assert app.title == "TunnelMinion"
    assert isinstance(default_data_dir(), Path)


def test_cli_always_binds_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    assert cli.main(["--port", "9000"]) == 0
    assert captured["app"] == "tunnelminion.app:create_app"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9000
    assert captured["factory"] is True

    monkeypatch.setattr("sys.platform", "darwin")
    assert cli.main(["--port", "9002"]) == 0
    assert captured["app"] == "tunnelminion.macos_app:create_macos_app"
    assert captured["host"] == "127.0.0.1"

    monkeypatch.setattr("sys.argv", ["tunnelminion", "--port", "9001"])
    assert cli.main() == 0
    assert captured["port"] == 9001


def test_cli_local_data_dir_builds_platform_application(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """显式数据目录会传入对应平台应用，仍只绑定环回地址。"""
    captured: list[tuple[object, dict[str, object]]] = []
    windows_app = object()
    macos_app = object()

    class Bundle:
        def __init__(self, app: object) -> None:
            self.app = app

    def build_windows(path: Path) -> Bundle:
        assert path == tmp_path
        return Bundle(windows_app)

    def build_macos(path: Path) -> Bundle:
        assert path == tmp_path
        return Bundle(macos_app)

    def run_server(app: object, **kwargs: object) -> None:
        captured.append((app, kwargs))

    monkeypatch.setattr("tunnelminion.app.build_windows_application", build_windows)
    monkeypatch.setattr("tunnelminion.macos_app.build_macos_local_application", build_macos)
    monkeypatch.setattr("uvicorn.run", run_server)

    assert cli.main(["--data-dir", str(tmp_path), "--port", "9010"]) == 0
    monkeypatch.setattr("sys.platform", "darwin")
    assert cli.main(["--data-dir", str(tmp_path), "--port", "9011"]) == 0
    assert captured == [
        (windows_app, {"host": "127.0.0.1", "port": 9010}),
        (macos_app, {"host": "127.0.0.1", "port": 9011}),
    ]


def test_export_and_uninstall_cli_delegate_with_explicit_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """运维子命令使用明确目录，并要求不可误触的卸载确认词。"""
    exported: list[tuple[Path, Path]] = []
    removed: list[Path] = []

    def write_export(root: Path, output: Path) -> None:
        exported.append((root, output))

    def uninstall(root: Path) -> tuple[Path, ...]:
        removed.append(root)
        return (root / "node-id",)

    monkeypatch.setattr(
        "tunnelminion.operations.write_safe_export",
        write_export,
    )
    monkeypatch.setattr(
        "tunnelminion.operations.uninstall_owned_data",
        uninstall,
    )
    output = tmp_path / "export.json"
    assert cli.main(["export", "--data-dir", str(tmp_path), "--output", str(output)]) == 0
    assert exported == [(tmp_path, output)]
    assert json.loads(capsys.readouterr().out)["status"] == "exported"

    with pytest.raises(SystemExit):
        cli.main(["uninstall", "--data-dir", str(tmp_path), "--confirm", "wrong"])
    assert (
        cli.main(
            [
                "uninstall",
                "--data-dir",
                str(tmp_path),
                "--confirm",
                "DELETE-TUNNELMINION-DATA",
            ]
        )
        == 0
    )
    assert removed == [tmp_path]
    assert json.loads(capsys.readouterr().out)["removed_entries"] == 1


def test_gateway_cli_uses_validated_wireguard_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """gateway 子命令从已验证配置读取 host/port，不接受命令行通配覆盖。"""
    captured: dict[str, object] = {}

    class Bundle:
        app = object()
        bind = GatewayBindConfig(host="10.77.0.1", port=8787)

    def build(path: Path | None) -> Bundle:
        assert path == tmp_path
        return Bundle()

    def fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("tunnelminion.macos_app.build_macos_gateway_application", build)
    monkeypatch.setattr("uvicorn.run", fake_run)

    assert cli.main(["gateway", "--data-dir", str(tmp_path)]) == 0
    assert captured == {"app": Bundle.app, "host": "10.77.0.1", "port": 8787}


def test_gateway_configure_cli_reads_token_from_stdin_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """配置命令只输出脱敏视图，秘密由标准输入进入密钥存储。"""
    token = "tmn_gateway-cli-token-with-more-than-32-characters"
    monkeypatch.setattr("sys.stdin", io.StringIO(token))
    peer = str(load_or_create_node_id(tmp_path / "peer-node-id"))

    assert (
        cli.main(
            [
                "gateway-configure",
                "--data-dir",
                str(tmp_path / "gateway"),
                "--bind-host",
                "10.77.0.1",
                "--peer-node-id",
                peer,
                "--peer-host",
                "10.77.0.2",
                "--secret-store",
                "restricted-file",
                "--allowed-tool",
                "get_node_summary",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    body = json.loads(output)
    assert body["gateway"]["configured"] is True
    assert body["gateway"]["peers"][0]["allowed_tools"] == ["get_node_summary"]
    assert token not in output


def test_module_entrypoint_propagates_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tunnelminion.cli.main", lambda: 7)
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("tunnelminion.__main__", run_name="__main__")
    assert caught.value.code == 7
