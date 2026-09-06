"""runtime 配置、控制命令和内部组件入口测试。"""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol

import httpx
import psutil
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tunnelminion import cli
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.runtime.lifecycle import (
    ComponentRuntimeState,
    ComponentRuntimeStatus,
    LifecycleReport,
    OverallRuntimeState,
)
from tunnelminion.runtime.preflight import PreflightCheck, PreflightReport, PreflightStatus
from tunnelminion.runtime.process import (
    DetachedProcessAdapter,
    ProcessRecordRepository,
    RuntimeOperationBusy,
)
from tunnelminion.runtime.profile import RuntimeComponent, RuntimePaths, RuntimeProfile


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...


class FakeManager:
    def __init__(self, report: LifecycleReport, *, busy: bool = False) -> None:
        self.report = report
        self.busy = busy
        self.calls: list[str] = []

    def _call(self, action: str) -> LifecycleReport:
        self.calls.append(action)
        if self.busy:
            raise RuntimeOperationBusy("busy")
        return self.report

    def start(self) -> LifecycleReport:
        return self._call("start")

    def status(self) -> LifecycleReport:
        return self._call("status")

    def stop(self) -> LifecycleReport:
        return self._call("stop")


class FakePreflight:
    def __init__(self, report: PreflightReport) -> None:
        self.report = report
        self.calls: list[tuple[RuntimePaths, frozenset[RuntimeComponent]]] = []

    def run(
        self,
        paths: RuntimePaths,
        *,
        active_components: frozenset[RuntimeComponent],
    ) -> PreflightReport:
        self.calls.append((paths, active_components))
        return self.report


def _report(state: ComponentRuntimeState = ComponentRuntimeState.STOPPED) -> LifecycleReport:
    return LifecycleReport(
        state=(
            OverallRuntimeState.RUNNING
            if state is ComponentRuntimeState.RUNNING
            else OverallRuntimeState.STOPPED
        ),
        components=(ComponentRuntimeStatus(component=RuntimeComponent.LOCAL, state=state),),
        exit_code=0,
    )


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _private_host_and_port() -> tuple[str, int]:
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            parsed = ipaddress.ip_address(address.address)
            if not parsed.is_private or parsed.is_loopback or parsed.is_unspecified:
                continue
            with socket.socket() as listener:
                listener.bind((address.address, 0))
                return address.address, int(listener.getsockname()[1])
    pytest.skip("当前测试机没有可绑定的非环回私网 IPv4 地址")


def test_runtime_configure_and_status_use_versioned_profile_and_safe_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "config" / "profile.json"
    data_dir = tmp_path / "data"
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile_path),
                "--data-dir",
                str(data_dir),
                "--local-port",
                "8124",
                "--enable-gateway",
            ]
        )
        == 0
    )
    configured = json.loads(capsys.readouterr().out)
    assert configured["schema_version"] == "runtime-profile/v1"
    assert configured["enabled_components"] == ["gateway", "local"]
    assert str(data_dir) not in json.dumps(configured)

    manager = FakeManager(_report())

    def build_manager(profile: RuntimeProfile, paths: RuntimePaths) -> FakeManager:
        del profile, paths
        return manager

    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_lifecycle_manager",
        build_manager,
    )
    assert cli.main(["runtime", "status", "--profile", str(profile_path)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["runtime"]["state"] == "stopped"
    assert body["model"]["status"] == "unconfigured"
    assert manager.calls == ["status"]


def test_runtime_reports_invalid_profile_and_busy_operation_without_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.json"
    assert cli.main(["runtime", "start", "--profile", str(missing)]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "runtime_profile_invalid"

    missing.write_text("{}", encoding="utf-8")
    assert cli.main(["runtime", "status", "--profile", str(missing)]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "runtime_profile_invalid"

    profile_path = tmp_path / "profile.json"
    data_dir = tmp_path / "data"
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile_path),
                "--data-dir",
                str(data_dir),
            ]
        )
        == 0
    )
    _ = capsys.readouterr()
    manager = FakeManager(_report(), busy=True)

    def build_busy_manager(profile: RuntimeProfile, paths: RuntimePaths) -> FakeManager:
        del profile, paths
        return manager

    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_lifecycle_manager",
        build_busy_manager,
    )
    assert cli.main(["runtime", "stop", "--profile", str(profile_path)]) == 2
    output = capsys.readouterr().out
    assert json.loads(output)["error_code"] == "runtime_operation_busy"
    assert str(data_dir) not in output


def test_runtime_start_blocks_global_preflight_failure_without_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "profile.json"
    data_dir = tmp_path / "data"
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile_path),
                "--data-dir",
                str(data_dir),
            ]
        )
        == 0
    )
    _ = capsys.readouterr()
    manager = FakeManager(_report())
    preflight = FakePreflight(
        PreflightReport(
            deterministic_ready=False,
            checks=(
                PreflightCheck(
                    name="package",
                    status=PreflightStatus.FAILED,
                    code="package_invalid",
                ),
            ),
        )
    )

    def build_manager(profile: RuntimeProfile, paths: RuntimePaths) -> FakeManager:
        del profile, paths
        return manager

    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_lifecycle_manager",
        build_manager,
    )
    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_runtime_preflight",
        lambda: preflight,
    )

    assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["error_code"] == "runtime_preflight_failed"
    assert output["preflight"]["checks"][0]["code"] == "package_invalid"
    assert manager.calls == ["status"]
    assert preflight.calls[0][1] == frozenset()


def test_runtime_start_reports_component_preflight_failure_but_preserves_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "profile.json"
    data_dir = tmp_path / "data"
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile_path),
                "--data-dir",
                str(data_dir),
            ]
        )
        == 0
    )
    _ = capsys.readouterr()
    manager = FakeManager(_report(ComponentRuntimeState.RUNNING))
    preflight = FakePreflight(
        PreflightReport(
            deterministic_ready=False,
            checks=(
                PreflightCheck(
                    name="local-port",
                    status=PreflightStatus.FAILED,
                    code="port_unavailable",
                    port=8123,
                ),
            ),
        )
    )

    def build_manager(profile: RuntimeProfile, paths: RuntimePaths) -> FakeManager:
        del profile, paths
        return manager

    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_lifecycle_manager",
        build_manager,
    )
    monkeypatch.setattr(
        "tunnelminion.runtime.control.build_runtime_preflight",
        lambda: preflight,
    )

    assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["runtime"]["state"] == "running"
    assert output["preflight"]["checks"][0]["code"] == "port_unavailable"
    assert manager.calls == ["status", "start"]
    assert preflight.calls[0][1] == frozenset({RuntimeComponent.LOCAL})


def test_runtime_configure_rejects_program_data_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("tunnelminion.runtime.profile.current_program_dir", lambda: tmp_path)
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(tmp_path.parent / "profile.json"),
                "--data-dir",
                str(tmp_path / "data"),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error_code"] == "runtime_profile_invalid"


def test_runtime_port_validation_keeps_help_compact(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as help_exit:
        cli.main(["runtime", "--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert len(help_text) < 2_000
    assert "65534" not in help_text

    with pytest.raises(SystemExit) as top_level_help_exit:
        cli.main(["--help"])
    assert top_level_help_exit.value.code == 0
    top_level_help = capsys.readouterr().out
    assert len(top_level_help) < 2_000
    assert "65534" not in top_level_help

    with pytest.raises(SystemExit) as invalid_exit:
        cli.main(["runtime", "configure", "--local-port", "1023"])
    assert invalid_exit.value.code == 2
    assert "1024 到 65535" in capsys.readouterr().err


def test_runtime_child_builds_local_and_gateway_without_access_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    def run(application: FastAPI, **kwargs: object) -> None:
        calls.append({"application": application, **kwargs})

    monkeypatch.setattr("uvicorn.run", run)
    local_app = FastAPI()

    def build_local(data_dir: Path) -> SimpleNamespace:
        del data_dir
        return SimpleNamespace(app=local_app)

    monkeypatch.setattr(
        "tunnelminion.macos_app.build_macos_local_application",
        build_local,
    )
    monkeypatch.setattr(
        "tunnelminion.app.build_windows_application",
        build_local,
    )
    identity = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(cli.sys, "platform", "win32")
    assert (
        cli.main(
            [
                "runtime-child",
                "--runtime-component=local",
                f"--runtime-instance-id={identity}",
                "--data-dir",
                str(tmp_path),
                "--local-port",
                "8125",
                "--runtime-log-file",
                str(tmp_path / "local.log"),
            ]
        )
        == 0
    )
    assert calls[-1]["application"] is local_app
    assert calls[-1]["host"] == "127.0.0.1"
    assert calls[-1]["port"] == 8125
    assert calls[-1]["access_log"] is False
    assert isinstance(calls[-1]["log_config"], dict)
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    assert (
        cli.main(
            [
                "runtime-child",
                "--runtime-component=local",
                f"--runtime-instance-id={identity}",
                "--data-dir",
                str(tmp_path),
                "--local-port",
                "8125",
                "--runtime-log-file",
                str(tmp_path / "local.log"),
            ]
        )
        == 0
    )

    gateway_app = FastAPI()

    def build_gateway(data_dir: Path) -> SimpleNamespace:
        del data_dir
        return SimpleNamespace(
            app=gateway_app,
            bind=SimpleNamespace(host="10.77.0.1", port=8787),
        )

    monkeypatch.setattr(
        "tunnelminion.macos_app.build_macos_gateway_application",
        build_gateway,
    )
    assert (
        cli.main(
            [
                "runtime-child",
                "--runtime-component=gateway",
                f"--runtime-instance-id={identity}",
                "--data-dir",
                str(tmp_path),
                "--local-port",
                "8125",
                "--runtime-log-file",
                str(tmp_path / "gateway.log"),
            ]
        )
        == 0
    )
    assert calls[-1]["host"] == "10.77.0.1"
    assert calls[-1]["port"] == 8787


def test_cli_local_entries_retain_owner_after_bundle_is_collected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """显式 data_dir 的裸 FastAPI 应用仍持有 lifecycle 与真实状态 provider。"""
    import gc
    import weakref
    from datetime import UTC, datetime
    from typing import cast

    from tunnelminion.agent.managed_application import (
        ManagedNodeApplication,
        managed_application_lifespan,
        managed_path_status_callback,
        managed_resource_payload_callback,
    )
    from tunnelminion.agent.managed_node import managed_node_status
    from tunnelminion.agent.managed_path import ManagedPathApplication
    from tunnelminion.agent.managed_runtime import ManagedNodeRuntime
    from tunnelminion.domain.identifiers import NetworkId
    from tunnelminion.domain.tools import Platform
    from tunnelminion.network.contracts import ProviderKind
    from tunnelminion.network.ledger import SQLiteManagedResourceLedger
    from tunnelminion.network.path_controller import NetworkPathType
    from tunnelminion.network.path_status import (
        ManagedPathAuthorizationState,
        ManagedPathFreshness,
        ManagedPathStatus,
    )
    from tunnelminion.tools.audit import InMemoryAuditSink
    from tunnelminion.tools.registry import ToolRegistry
    from tunnelminion.tools.runtime import ToolRuntime
    from tunnelminion.web.resources import create_resource_router

    class FakeRuntime:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.status = FakeRuntimeStatus()

        async def start(self) -> None:
            self.calls.append("start")

        async def stop(self) -> None:
            self.calls.append("stop")

    class FakeRuntimeStatus:
        def model_dump(self, *, mode: str) -> dict[str, str]:
            del mode
            return {"state": "running"}

    class FakeManagedPath:
        def __init__(self, status: ManagedPathStatus, ledger: SQLiteManagedResourceLedger) -> None:
            self.status = status
            self.ledger = ledger

        def resource_payload(self) -> dict[str, object]:
            return {
                **self.status.model_dump(mode="json"),
                "configured": True,
            }

        def current_managed_path_status(self) -> ManagedPathStatus:
            return self.status

        def close(self) -> None:
            return None

    owners: list[weakref.ReferenceType[ManagedNodeApplication]] = []
    runtimes: list[FakeRuntime] = []
    captured: list[FastAPI] = []
    managed_roots: list[Path] = []

    def build_local(data_dir: Path) -> SimpleNamespace:
        node_id = NodeId.new()
        status = ManagedPathStatus(
            network_id=NetworkId.new(),
            node_id=node_id,
            revision=1,
            plan_hash=f"sha256:{'0' * 64}",
            authorization_revision=1,
            provider=ProviderKind.WINDOWS,
            authorization_state=ManagedPathAuthorizationState.UNKNOWN,
            path_type=NetworkPathType.STATIC,
            source="none",
            freshness=ManagedPathFreshness.UNVERIFIED,
            candidate_count=0,
            journal_sequence=0,
            updated_at=datetime(2026, 8, 1, tzinfo=UTC),
        )
        ledger = SQLiteManagedResourceLedger(data_dir / "managed-network-ledger.sqlite3")
        (data_dir / "governance.sqlite3").touch()
        managed_roots.append(data_dir)
        runtime = FakeRuntime()
        managed = ManagedNodeApplication(
            config=None,
            enrollment=managed_node_status(None),
            runtime=cast(ManagedNodeRuntime, runtime),
            managed_path=cast(
                ManagedPathApplication,
                FakeManagedPath(status, ledger),
            ),
        )
        app = FastAPI(lifespan=managed_application_lifespan(managed))
        app.include_router(
            create_resource_router(
                ToolRuntime(ToolRegistry(), Platform.WINDOWS, InMemoryAuditSink()),
                node_id,
                managed_status=managed_resource_payload_callback(managed),
                managed_path_status=managed_path_status_callback(managed),
            )
        )
        owners.append(weakref.ref(managed))
        runtimes.append(runtime)
        return SimpleNamespace(app=app, managed_node=managed)

    def run(application: FastAPI, **kwargs: object) -> None:
        del kwargs
        captured.append(application)

    monkeypatch.setattr("tunnelminion.macos_app.build_macos_local_application", build_local)
    monkeypatch.setattr("tunnelminion.app.build_windows_application", build_local)
    monkeypatch.setattr("uvicorn.run", run)

    identity = "00000000-0000-0000-0000-000000000001"
    for platform, index in (("win32", 0), ("darwin", 1)):
        monkeypatch.setattr(cli.sys, "platform", platform)
        assert (
            cli.main(
                [
                    "runtime-child",
                    "--runtime-component=local",
                    f"--runtime-instance-id={identity}",
                    "--data-dir",
                    str(tmp_path / f"child-{index}"),
                    "--local-port",
                    "8125",
                    "--runtime-log-file",
                    str(tmp_path / f"child-{index}.log"),
                ]
            )
            == 0
        )
        assert (
            cli.main(
                [
                    "--data-dir",
                    str(tmp_path / f"panel-{index}"),
                    "--port",
                    str(9010 + index),
                ]
            )
            == 0
        )

    gc.collect()
    assert all(owner() is not None for owner in owners)
    assert len(captured) == len(runtimes) == 4
    for app, runtime in zip(captured, runtimes, strict=True):
        assert getattr(app.state, "managed_node", None) is not None
        test_client = TestClient(app)
        with test_client:
            client = cast(ApiClient, test_client)
            assert runtime.calls == ["start"]
            managed = client.get("/api/resources/managed-node")
            network_path = client.get("/api/resources/network-path")
            managed_body = cast(dict[str, object], managed.json())
            managed_path = cast(dict[str, object], managed_body["managed_path"])
            network_path_body = cast(dict[str, object], network_path.json())
            assert managed.status_code == 200
            assert managed_path["configured"] is True
            assert network_path.status_code == 200
            assert network_path_body["configured"] is True
        assert runtime.calls == ["start", "stop"]

    for root in managed_roots:
        for name in ("governance.sqlite3", "managed-network-ledger.sqlite3"):
            database = root / name
            database.unlink()
            assert not database.exists()


def test_runtime_child_sanitizes_invalid_identity_and_builder_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "https://user:password@model.invalid/private"

    def fail(data_dir: Path) -> SimpleNamespace:
        del data_dir
        raise RuntimeError(secret)

    monkeypatch.setattr("tunnelminion.app.build_windows_application", fail)
    result = cli.main(
        [
            "runtime-child",
            "--runtime-component=local",
            "--runtime-instance-id=invalid",
            "--data-dir",
            str(tmp_path),
            "--local-port",
            "8125",
            "--runtime-log-file",
            str(tmp_path / "local.log"),
        ]
    )
    assert result == 2
    output = capsys.readouterr().err
    assert json.loads(output)["error_code"] == "component_start_failed"
    assert secret not in output

    monkeypatch.setattr(cli.sys, "platform", "win32")
    result = cli.main(
        [
            "runtime-child",
            "--runtime-component=local",
            "--runtime-instance-id=00000000-0000-0000-0000-000000000001",
            "--data-dir",
            str(tmp_path),
            "--local-port",
            "8125",
            "--runtime-log-file",
            str(tmp_path / "local.log"),
        ]
    )
    assert result == 2
    output = capsys.readouterr().err
    assert secret not in output


def test_real_local_runtime_start_status_stop(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "profile.json"
    data_dir = tmp_path / "data"
    port = _free_port()
    configured = cli.main(
        [
            "runtime",
            "configure",
            "--profile",
            str(profile_path),
            "--data-dir",
            str(data_dir),
            "--local-port",
            str(port),
        ]
    )
    assert configured == 0
    _ = capsys.readouterr()
    FileModelConfigurationRepository(data_dir / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://127.0.0.1:1/v1", model="offline")
    )
    try:
        assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 0
        started = json.loads(capsys.readouterr().out)
        assert started["runtime"]["state"] == "running"
        assert started["runtime"]["components"][0]["process_present"] is True
        assert started["model"]["status"] == "unavailable"

        assert cli.main(["runtime", "status", "--profile", str(profile_path)]) == 0
        assert json.loads(capsys.readouterr().out)["runtime"]["state"] == "running"

        assert cli.main(["runtime", "stop", "--profile", str(profile_path)]) == 0
        assert json.loads(capsys.readouterr().out)["runtime"]["state"] == "stopped"
    finally:
        paths = RuntimePaths(
            profile_file=profile_path,
            data_dir=data_dir,
            log_dir=data_dir / "runtime" / "logs",
            state_dir=data_dir / "runtime" / "state",
        )
        record = ProcessRecordRepository(paths.state_dir).load(RuntimeComponent.LOCAL)
        if record is not None:
            snapshot = DetachedProcessAdapter().inspect(record.pid)
            if snapshot is not None:
                DetachedProcessAdapter().terminate(record.pid)
                DetachedProcessAdapter().wait(record.pid, 5)


def test_real_local_port_conflict_fails_then_recovers_independently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "profile.json"
    data_dir = tmp_path / "data"
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = int(occupied.getsockname()[1])
        assert (
            cli.main(
                [
                    "runtime",
                    "configure",
                    "--profile",
                    str(profile_path),
                    "--data-dir",
                    str(data_dir),
                    "--local-port",
                    str(port),
                ]
            )
            == 0
        )
        _ = capsys.readouterr()
        assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 1
        failed = json.loads(capsys.readouterr().out)
        assert failed["runtime"]["components"][0]["error_code"] == "startup_unstable"

    try:
        assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 0
        recovered = json.loads(capsys.readouterr().out)
        assert recovered["runtime"]["state"] == "running"
        assert cli.main(["runtime", "stop", "--profile", str(profile_path)]) == 0
        assert json.loads(capsys.readouterr().out)["runtime"]["state"] == "stopped"
    finally:
        repository = ProcessRecordRepository(data_dir / "runtime" / "state")
        record = repository.load(RuntimeComponent.LOCAL)
        adapter = DetachedProcessAdapter()
        if record is not None and adapter.inspect(record.pid) is not None:
            adapter.terminate(record.pid)
            adapter.wait(record.pid, 5)


def test_real_gateway_failure_isolated_then_recovers_without_token_probe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "profile.json"
    data_dir = tmp_path / "data"
    local_port = _free_port()
    gateway_host, gateway_port = _private_host_and_port()
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile_path),
                "--data-dir",
                str(data_dir),
                "--local-port",
                str(local_port),
                "--enable-gateway",
            ]
        )
        == 0
    )
    _ = capsys.readouterr()
    try:
        assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 1
        degraded = json.loads(capsys.readouterr().out)
        by_component = {item["component"]: item for item in degraded["runtime"]["components"]}
        assert degraded["runtime"]["state"] == "degraded"
        assert by_component["gateway"]["error_code"] == "gateway_unconfigured"
        assert by_component["local"]["state"] == "running"

        service = GatewayConfigurationService(
            FileGatewayConfigurationRepository(data_dir / "gateway.json"),
            configure_gateway_secret_store(data_dir, GatewaySecretStoreKind.RESTRICTED_FILE),
        )
        service.configure_local(GatewayBindConfig(host=gateway_host, port=gateway_port))
        token = "tmn_" + "g" * 40
        service.provision_peer(
            GatewayPeerInput(
                peer=GatewayPeerConfig(
                    node_id=NodeId.new(),
                    host=gateway_host,
                    port=gateway_port,
                    allowed_tools=frozenset({"get_node_summary"}),
                ),
                token=token,
            )
        )
        assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 0
        recovered_output = capsys.readouterr().out
        recovered = json.loads(recovered_output)
        assert recovered["runtime"]["state"] == "running"
        assert all(item["state"] == "running" for item in recovered["runtime"]["components"])
        assert token not in recovered_output

        assert cli.main(["runtime", "stop", "--profile", str(profile_path)]) == 0
        stopped = json.loads(capsys.readouterr().out)
        assert stopped["runtime"]["state"] == "stopped"
        logs = "".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in (data_dir / "runtime" / "logs").glob("*.log*")
        )
        assert token not in logs
    finally:
        repository = ProcessRecordRepository(data_dir / "runtime" / "state")
        adapter = DetachedProcessAdapter()
        for component in (RuntimeComponent.LOCAL, RuntimeComponent.GATEWAY):
            record = repository.load(component)
            if record is not None and adapter.inspect(record.pid) is not None:
                adapter.terminate(record.pid)
                adapter.wait(record.pid, 5)
