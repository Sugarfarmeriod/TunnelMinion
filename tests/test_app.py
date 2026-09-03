"""真实 Windows 应用组装、稳定 Node ID 与启动命令测试。"""

from __future__ import annotations

import asyncio
import io
import json
import runpy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from keyring.errors import KeyringError
from pydantic import JsonValue

from tunnelminion import cli
from tunnelminion.agent.conversation import StartRunInput
from tunnelminion.agent.managed_application import ManagedNodeApplication
from tunnelminion.agent.managed_node import ManagedNodeConfig, ManagedNodeState, ManagedNodeStatus
from tunnelminion.app import (
    WindowsApplication,
    build_windows_application,
    create_app,
    default_data_dir,
    load_or_create_node_id,
)
from tunnelminion.coordinator.contracts import GatewayEndpoint
from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.macos_app import SafeSharingGatewaySettings
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
)
from tunnelminion.network.contracts import ProviderKind
from tunnelminion.network.path_controller import (
    DirectPathEvidence,
    NetworkPathType,
    PathSelection,
)
from tunnelminion.network.path_status import (
    ManagedPathAuthorizationState,
    ManagedPathFreshness,
    ManagedPathStatus,
    source_category,
)
from tunnelminion.platforms.windows.models import InterfaceSnapshot
from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest
from tunnelminion.web.application_views import NetworkPathViewBindings
from tunnelminion.web.operations import PreauthorizationInput

PATH_NOW = datetime(2026, 8, 10, 8, 0, tzinfo=UTC)


def configured_managed_application(
    node_id: NodeId,
    platform: Platform,
) -> ManagedNodeApplication:
    """构造不启动后台循环的已配置装配事实。"""
    config = ManagedNodeConfig(
        enabled=True,
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId("network_0123456789abcdef0123456789abcdef"),
        node_id=node_id,
        display_name="本机测试节点",
        platform=platform,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
    )
    return ManagedNodeApplication(
        config=config,
        enrollment=ManagedNodeStatus(
            configured=True,
            enabled=True,
            state=ManagedNodeState.READY,
            schema_version=config.schema_version,
            network_id=config.network_id,
            node_id=node_id,
            platform=platform,
            credential_configured=True,
        ),
    )


def real_path_bindings(
    platform: Platform,
    node_id: NodeId | None = None,
) -> NetworkPathViewBindings:
    """生成 endpoint、route 与秘密均已脱敏的真实路径事实。"""
    provider = ProviderKind(platform.value)
    network_id = NetworkId("network_0123456789abcdef0123456789abcdef")
    current_node_id = node_id or NodeId("node_0123456789abcdef0123456789abcdef")
    selection = PathSelection(
        network_id=network_id,
        node_id=current_node_id,
        plan_hash="sha256:" + "a" * 64,
        authorization_revision=3,
        path_type=NetworkPathType.DIRECT,
        provider=provider,
        revision=3,
        last_known_good_revision=3,
        candidate_count=1,
        consecutive_failures=0,
        consecutive_successes=2,
        selected_at=PATH_NOW,
        last_evidence_at=PATH_NOW,
        target_host_hash="sha256:" + "c" * 64,
        target_port=8787,
        route_identity_hash="sha256:" + "d" * 64,
        expires_at=PATH_NOW + timedelta(seconds=180),
    )
    evidence = DirectPathEvidence(
        network_id=network_id,
        node_id=current_node_id,
        plan_hash="sha256:" + "a" * 64,
        authorization_revision=3,
        provider=provider,
        revision=3,
        target_host_hash="sha256:" + "c" * 64,
        target_port=8787,
        route_identity_hash="sha256:" + "d" * 64,
        candidate_count=1,
        selected_candidate_hash="sha256:" + "b" * 64,
        endpoint_probe_at=PATH_NOW,
        endpoint_probe_succeeded=True,
        last_handshake_at=PATH_NOW,
        handshake_fresh=True,
        host_route_present=True,
        target_probe_at=PATH_NOW,
        target_probe_succeeded=True,
        verified=True,
        source="fake",
        observed_at=PATH_NOW,
        expires_at=PATH_NOW + timedelta(seconds=180),
    )
    return NetworkPathViewBindings(
        selection=lambda: selection,
        evidence=lambda: evidence,
        authorization=lambda: "authorized-l3",
    )


def real_managed_path_status(node_id: NodeId, platform: Platform) -> ManagedPathStatus:
    """把同一组脱敏路径事实包装为受管路径持久化状态。"""
    bindings = real_path_bindings(platform, node_id)
    selection = bindings.selection()
    evidence = bindings.evidence()
    assert selection is not None
    assert evidence is not None
    assert selection.network_id is not None
    assert selection.plan_hash is not None
    assert selection.authorization_revision is not None
    return ManagedPathStatus(
        network_id=selection.network_id,
        node_id=node_id,
        revision=selection.revision,
        plan_hash=selection.plan_hash,
        authorization_revision=selection.authorization_revision,
        provider=selection.provider,
        authorization_state=ManagedPathAuthorizationState.AUTHORIZED,
        authorization_id=AuthorizationId("authorization_" + "e" * 32),
        path_type=selection.path_type,
        selection=selection,
        evidence=evidence,
        source=source_category(evidence.source),
        freshness=ManagedPathFreshness.FRESH,
        candidate_count=evidence.candidate_count,
        last_known_good_revision=selection.last_known_good_revision,
        observed_at=evidence.observed_at,
        refreshed_at=evidence.observed_at,
        expires_at=evidence.expires_at,
        journal_sequence=1,
        updated_at=PATH_NOW,
    )


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
    assert "/api/resources/managed-node" in paths
    assert "/api/resources/overview" in paths
    assert "/api/incidents/{value}" in paths
    assert "/api/incidents/{value}/follow-up" in paths
    assert "/api/diagnostics/export" in paths
    assert "/api/threads" in paths
    assert "/api/runs/{value}/events" in paths
    assert "/api/operations" in paths
    assert "/api/preauthorizations" in paths
    for original, legacy in (
        ("/chat", "/legacy/chat"),
        ("/resources", "/legacy/resources"),
        ("/operations", "/legacy/operations"),
        ("/memories", "/legacy/memories"),
    ):
        assert original in paths
        assert legacy in paths
    assert "/" in paths
    assert "/app/{route_path}" in paths
    assert "/app-assets/{asset_path}" in paths
    assert bundle.node_id
    assert bundle.audit_sink.records == []
    assert bundle.tool_runtime
    assert bundle.tool_registry
    assert bundle.managed_node.enrollment.state.value == "unconfigured"
    assert execute_node_summary(bundle)["model_status"] == "unconfigured"

    local_client: Any = TestClient(bundle.app, base_url="http://127.0.0.1")
    overview = local_client.get("/api/resources/overview")
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["local"]["readiness"] == "ready"
    assert overview_body["model"]["status"] == "unconfigured"
    assert overview_body["coordinator"]["state"] == "unconfigured"
    assert overview_body["network_path"]["state"] == "unconfigured"
    assert overview_body["network_path"]["handshake"]["status"] == "missing"
    diagnostics = local_client.get("/api/diagnostics/export")
    assert diagnostics.status_code == 200
    assert diagnostics.headers["content-disposition"].startswith(
        'attachment; filename="tunnelminion-diagnostics-'
    )
    diagnostics_body = diagnostics.json()
    assert diagnostics_body["schema_version"] == "diagnostics-export/v1"
    assert diagnostics_body["overview"]["runtime"]["platform"] == "windows"
    assert [item["status"] for item in diagnostics_body["optional_sources"]] == [
        "unavailable",
        "unavailable",
    ]

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


def test_windows_factory_binds_configured_coordinator_and_real_path_views(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_managed(
        _data_dir: Path,
        node_id: NodeId,
        platform: Platform,
        *_dependencies: object,
        **_transports: object,
    ) -> ManagedNodeApplication:
        return configured_managed_application(node_id, platform)

    monkeypatch.setattr("tunnelminion.app.build_managed_node_application", fake_managed)
    bundle = build_windows_application(
        tmp_path / "windows-bindings",
        network_path=real_path_bindings(Platform.WINDOWS),
    )
    client: Any = TestClient(bundle.app, base_url="http://127.0.0.1")

    coordinator = client.get("/api/resources/coordinator").json()
    path = client.get("/api/resources/network-path").json()
    overview = client.get("/api/resources/overview").json()
    assert coordinator["configured"] is True
    assert coordinator["state"] == "connecting"
    assert path["configured"] is True
    assert path["path_type"] == "direct"
    assert path["authorization_state"] == "authorized-l3"
    assert overview["coordinator"]["state"] == "sync_not_started"
    assert overview["network_path"]["state"] == "direct"
    assert overview["network_path"]["handshake"]["status"] == "passed"


def test_windows_factory_prefers_managed_path_status_in_overview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status: ManagedPathStatus | None = None

    def fake_managed(
        _data_dir: Path,
        node_id: NodeId,
        platform: Platform,
        *_dependencies: object,
        **_transports: object,
    ) -> ManagedNodeApplication:
        nonlocal status
        status = real_managed_path_status(node_id, platform)
        return configured_managed_application(node_id, platform)

    monkeypatch.setattr("tunnelminion.app.build_managed_node_application", fake_managed)

    def current_managed_path_status(_self: ManagedNodeApplication) -> ManagedPathStatus | None:
        return status

    monkeypatch.setattr(
        ManagedNodeApplication,
        "current_managed_path_status",
        current_managed_path_status,
    )
    bundle = build_windows_application(
        tmp_path / "windows-managed-path",
        network_path=real_path_bindings(Platform.MACOS),
    )
    client: Any = TestClient(bundle.app, base_url="http://127.0.0.1")

    path = client.get("/api/resources/network-path").json()
    overview = client.get("/api/resources/overview").json()
    assert path["provider"] == "windows"
    assert overview["network_path"]["provider"] == "windows"
    assert overview["network_path"]["state"] == "direct"
    assert overview["network_path"]["probe"]["status"] == "passed"


def test_regular_windows_and_macos_apps_survive_invalid_managed_config(
    tmp_path: Path,
) -> None:
    """损坏或夹带秘密字段的 managed 配置只降级 managed 域。"""
    from tunnelminion.agent.managed_node import ManagedNodeState
    from tunnelminion.macos_app import build_macos_local_application

    roots = (tmp_path / "windows-invalid", tmp_path / "macos-invalid")
    for root in roots:
        root.mkdir()
        (root / "managed-node.json").write_text(
            '{"refresh_credential":"forbidden"}',
            encoding="utf-8",
        )
    windows = build_windows_application(roots[0])
    macos = build_macos_local_application(roots[1])
    for managed in (windows.managed_node, macos.managed_node):
        assert managed.enrollment.state is ManagedNodeState.UNAVAILABLE
        assert managed.enrollment.last_error_code == "managed_config_invalid"
        assert managed.runtime is None
        assert "forbidden" not in str(managed.resource_payload())


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
    monkeypatch.setattr("sys.platform", "win32")
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
    monkeypatch.setattr("sys.platform", "win32")

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

    def build(
        path: Path | None,
        *,
        safe_sharing: object | None = None,
    ) -> Bundle:
        assert path == tmp_path
        assert safe_sharing is None
        return Bundle()

    def fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("tunnelminion.macos_app.build_macos_gateway_application", build)
    monkeypatch.setattr("uvicorn.run", fake_run)

    assert cli.main(["gateway", "--data-dir", str(tmp_path)]) == 0
    assert captured == {"app": Bundle.app, "host": "10.77.0.1", "port": 8787}


def test_gateway_cli_passes_explicit_safe_sharing_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class Bundle:
        app = object()
        bind = GatewayBindConfig(host="10.77.0.1", port=18_883)

    def build(
        path: Path | None,
        *,
        safe_sharing: object | None = None,
    ) -> Bundle:
        captured["path"] = path
        captured["settings"] = safe_sharing
        return Bundle()

    monkeypatch.setattr("tunnelminion.macos_app.build_macos_gateway_application", build)

    def fake_run(app: object, **kwargs: object) -> None:
        captured.update({"app": app, **kwargs})

    monkeypatch.setattr("uvicorn.run", fake_run)

    assert (
        cli.main(
            [
                "gateway",
                "--data-dir",
                str(tmp_path),
                "--enable-safe-sharing",
                "--sharing-min-port",
                "18880",
                "--sharing-max-port",
                "18889",
                "--sharing-max-duration",
                "120",
                "--sharing-gateway-port",
                "18883",
            ]
        )
        == 0
    )
    settings = captured["settings"]
    assert isinstance(settings, SafeSharingGatewaySettings)
    assert settings.minimum_port == 18_880
    assert settings.maximum_port == 18_889
    assert settings.maximum_duration_seconds == 120
    assert captured["host"] == "10.77.0.1"
    assert captured["port"] == 18_883


def test_local_operation_cli_uses_target_control_service(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, object] = {}

    class Result:
        def model_dump_json(self) -> str:
            return '{"status":"ok"}'

    class Service:
        def approve(self, operation_id: object, payload: object) -> Result:
            captured["operation_id"] = operation_id
            captured["approve"] = payload
            return Result()

        def create_preauthorization(self, payload: object) -> Result:
            captured["preauthorization"] = payload
            return Result()

    class Bundle:
        operation_control_service = Service()

    def build(path: Path) -> Bundle:
        assert path == tmp_path
        return Bundle()

    monkeypatch.setattr("tunnelminion.macos_app.build_macos_local_application", build)
    operation_id = "operation_0123456789abcdef0123456789abcdef"
    peer_id = "node_0123456789abcdef0123456789abcdef"
    fingerprint = f"sha256:{'a' * 64}"

    assert (
        cli.main(
            [
                "operation-approve",
                "--data-dir",
                str(tmp_path),
                "--operation-id",
                operation_id,
                "--valid-seconds",
                "60",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    assert str(captured["operation_id"]) == operation_id
    assert (
        cli.main(
            [
                "operation-preauthorize",
                "--data-dir",
                str(tmp_path),
                "--request-peer-id",
                peer_id,
                "--service-id",
                "http:127.0.0.1:18880:fixture",
                "--service-fingerprint",
                fingerprint,
                "--minimum-port",
                "18881",
                "--maximum-port",
                "18881",
                "--maximum-duration",
                "60",
                "--valid-seconds",
                "120",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    preauthorization = captured["preauthorization"]
    assert isinstance(preauthorization, PreauthorizationInput)
    assert preauthorization.confirm_peer
    assert preauthorization.confirm_validity

    with pytest.raises(SystemExit):
        cli.main(
            [
                "operation-approve",
                "--operation-id",
                operation_id,
                "--valid-seconds",
                "0",
            ]
        )
    with pytest.raises(SystemExit):
        cli.main(
            [
                "operation-preauthorize",
                "--request-peer-id",
                peer_id,
                "--service-id",
                "service",
                "--service-fingerprint",
                fingerprint,
                "--minimum-port",
                "18881",
                "--maximum-port",
                "18881",
                "--maximum-duration",
                "60",
                "--valid-seconds",
                "86401",
            ]
        )


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
                "--allowed-operation",
                "share_local_http_service",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    body = json.loads(output)
    assert body["gateway"]["configured"] is True
    assert body["gateway"]["peers"][0]["allowed_tools"] == ["get_node_summary"]
    assert body["gateway"]["peers"][0]["allowed_operations"] == ["share_local_http_service"]
    assert token not in output


def test_coordinator_enroll_cli_uses_stdin_and_outputs_only_public_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """enrollment token 不进入 argv、输出或日志，refresh 只进入秘密存储。"""
    from datetime import UTC, datetime

    from tunnelminion.agent import managed_node
    from tunnelminion.agent.managed_node import (
        FileManagedNodeConfigRepository,
        ManagedNodeConfig,
        ManagedNodeSecretStoreKind,
        managed_node_secret_store,
    )
    from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
    from tunnelminion.coordinator.contracts import GatewayEndpoint, NodeRegistrationResponse
    from tunnelminion.domain.identifiers import NetworkId, NodeId, RefreshCredentialId
    from tunnelminion.domain.tools import Platform

    root = tmp_path / "managed"
    config = ManagedNodeConfig(
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId.new(),
        node_id=NodeId.new(),
        display_name="Windows A",
        platform=Platform.WINDOWS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
        secret_store=ManagedNodeSecretStoreKind.RESTRICTED_FILE,
    )
    FileManagedNodeConfigRepository(root / "managed-node.json").save(config)
    token = f"tmne_{'e' * 43}"
    refresh = f"tmnr_{'r' * 43}"
    captured: dict[str, str] = {}

    async def fake_enroll(
        managed_config: ManagedNodeConfig,
        enrollment_token: str,
        transport: object,
        credentials: AgentRefreshCredentialStore,
    ) -> NodeRegistrationResponse:
        del transport
        captured["token"] = enrollment_token
        response = NodeRegistrationResponse(
            identity=managed_config.identity(),
            credential_id=RefreshCredentialId.new(),
            refresh_credential=refresh,
            server_revision=7,
            issued_at=datetime(2026, 7, 31, tzinfo=UTC),
        )
        credentials.save(response)
        return response

    monkeypatch.setattr(managed_node, "enroll_managed_node", fake_enroll)
    monkeypatch.setattr("sys.stdin", io.StringIO(token))
    argv = ["coordinator-enroll", "--data-dir", str(root)]

    assert cli.main(argv) == 0

    output = capsys.readouterr().out
    body = json.loads(output)
    assert body == {
        "status": "enrolled",
        "network_id": str(config.network_id),
        "node_id": str(config.node_id),
        "credential_id": body["credential_id"],
        "server_revision": 7,
    }
    assert captured == {"token": token}
    assert token not in argv
    assert token not in output
    assert refresh not in output
    credentials = AgentRefreshCredentialStore(managed_node_secret_store(root, config.secret_store))
    assert credentials.load(config.network_id, config.node_id) == refresh


def test_coordinator_enroll_cli_rejects_missing_disabled_or_empty_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """配置缺失、显式禁用或 stdin 为空时均 fail-closed。"""
    from tunnelminion.agent.managed_node import (
        FileManagedNodeConfigRepository,
        ManagedNodeConfig,
    )
    from tunnelminion.coordinator.contracts import GatewayEndpoint
    from tunnelminion.domain.identifiers import NetworkId, NodeId
    from tunnelminion.domain.tools import Platform

    with pytest.raises(SystemExit):
        cli.main(["coordinator-enroll", "--data-dir", str(tmp_path / "missing")])

    root = tmp_path / "managed"
    config = ManagedNodeConfig(
        enabled=False,
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId.new(),
        node_id=NodeId.new(),
        display_name="Windows A",
        platform=Platform.WINDOWS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
    )
    repository = FileManagedNodeConfigRepository(root / "managed-node.json")
    repository.save(config)
    with pytest.raises(SystemExit):
        cli.main(["coordinator-enroll", "--data-dir", str(root)])

    repository.save(config.model_copy(update={"enabled": True}))
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(SystemExit):
        cli.main(["coordinator-enroll", "--data-dir", str(root)])


def test_managed_status_cli_reports_stable_redacted_states(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tunnelminion.agent.managed_node import (
        FileManagedNodeConfigRepository,
        ManagedNodeConfig,
        ManagedNodeSecretStoreKind,
    )
    from tunnelminion.coordinator.contracts import GatewayEndpoint
    from tunnelminion.domain.identifiers import NetworkId, NodeId
    from tunnelminion.domain.tools import Platform

    missing = tmp_path / "missing"
    assert cli.main(["managed-status", "--data-dir", str(missing)]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "unconfigured"

    root = tmp_path / "managed-status"
    config = ManagedNodeConfig(
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId.new(),
        node_id=NodeId.new(),
        display_name="Windows A",
        platform=Platform.WINDOWS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
        secret_store=ManagedNodeSecretStoreKind.RESTRICTED_FILE,
    )
    FileManagedNodeConfigRepository(root / "managed-node.json").save(config)
    assert cli.main(["managed-status", "--data-dir", str(root)]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["state"] == "enrollment-required"
    assert "10.77" not in output
    assert "fingerprint" not in output.lower()

    (root / "managed-node.json").write_text("{}", encoding="utf-8")
    assert cli.main(["managed-status", "--data-dir", str(root)]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "unavailable",
        "error_code": "managed_config_invalid",
    }

    FileManagedNodeConfigRepository(root / "managed-node.json").save(config)

    def unavailable_store(_root: Path, _kind: object) -> object:
        raise RuntimeError("secret backend unavailable")

    monkeypatch.setattr(
        "tunnelminion.agent.managed_node.managed_node_secret_store",
        unavailable_store,
    )
    assert cli.main(["managed-status", "--data-dir", str(root)]) == 0
    unavailable = json.loads(capsys.readouterr().out)
    assert unavailable["state"] == "unavailable"
    assert unavailable["last_error_code"] == "secret_store_unavailable"


def test_module_entrypoint_propagates_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tunnelminion.cli.main", lambda: 7)
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("tunnelminion.__main__", run_name="__main__")
    assert caught.value.code == 7
