"""Windows 只读工具适配器测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from threading import get_ident
from typing import Any, TypeVar, cast

import pytest
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.platforms.windows.adapters import (
    DockerServicesAdapter,
    NetworkListenersAdapter,
    NodeSummaryAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
    WireGuardStatusAdapter,
)
from tunnelminion.platforms.windows.models import (
    Availability,
    DockerService,
    InterfaceSnapshot,
    NetworkListener,
    ProcessInfo,
)
from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """执行一个异步适配器动作。"""
    return asyncio.run(coroutine)


class FakeReader:
    """按配置返回 Windows 系统状态。"""

    def __init__(self) -> None:
        self.interface_value: InterfaceSnapshot | None = InterfaceSnapshot(
            name="HomeMac", is_up=True, addresses=("10.77.0.2",)
        )
        self.listener_error = False
        self.process_error = False
        self.process_thread_id: int | None = None

    def interface(self, name: str) -> InterfaceSnapshot | None:
        assert name == "HomeMac"
        return self.interface_value

    def listeners(self) -> tuple[NetworkListener, ...]:
        if self.listener_error:
            raise PermissionError
        return (
            NetworkListener(
                protocol="tcp",
                address="127.0.0.1",
                port=8080,
                pid=10,
                process_name="server",
            ),
        )

    def processes(self, limit: int) -> tuple[ProcessInfo, ...]:
        self.process_thread_id = get_ident()
        if self.process_error:
            raise PermissionError
        return (
            ProcessInfo(
                pid=10,
                name="server",
                status="running",
                memory_bytes=1024,
                thread_count=2,
            ),
        )[:limit]


class FakeRunner:
    """根据命令参数最后一项返回固定结果。"""

    def __init__(self, results: dict[str, CommandResult]) -> None:
        self.results = results
        self.commands: list[tuple[str, ...]] = []

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.commands.append(command)
        return self.results[command[-1]]


def command_result(stdout: str = "", stderr: str = "", returncode: int = 0) -> CommandResult:
    """构造固定命令结果。"""
    return CommandResult(returncode=returncode, stdout=stdout, stderr=stderr)


def token(cancelled: bool = False) -> ToolCancellationToken:
    """构造可选预取消信号。"""
    value = ToolCancellationToken()
    if cancelled:
        value.cancel()
    return value


def test_wireguard_reports_missing_interface_and_permission_degradation() -> None:
    reader = FakeReader()
    reader.interface_value = None
    runner = FakeRunner({})
    adapter = WireGuardStatusAdapter(reader, runner, "wg.exe")
    missing = cast(dict[str, JsonValue], run(adapter.execute({}, token())))
    assert missing["availability"] == Availability.UNAVAILABLE
    assert runner.commands == []

    reader.interface_value = InterfaceSnapshot(name="HomeMac", is_up=True, addresses=("10.77.0.2",))
    runner.results["peers"] = command_result(
        stderr="Unable to access interface: Permission denied", returncode=1
    )
    degraded = cast(dict[str, JsonValue], run(adapter.execute({}, token())))
    assert degraded["availability"] == Availability.DEGRADED
    assert degraded["error_code"] == "permission_denied"
    assert "private" not in str(degraded).lower()

    runner.results["peers"] = command_result(stderr="not installed", returncode=1)
    unavailable_cli = cast(dict[str, JsonValue], run(adapter.execute({}, token())))
    assert unavailable_cli["error_code"] == "dependency_unavailable"


def test_wireguard_parses_peer_status_without_requesting_private_key() -> None:
    long_key = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG="
    short_key = "short"
    missing_key = "missing-key-long-enough"
    runner = FakeRunner(
        {
            "peers": command_result(f"{long_key}\n{short_key}\n{missing_key}\n"),
            "allowed-ips": command_result(f"{long_key}\t10.77.0.1/32,fd00::1/128\nmalformed\n"),
            "endpoints": command_result(returncode=1),
            "latest-handshakes": command_result(f"{long_key}\t123\n{short_key}\tbad\n"),
            "transfer": command_result(f"{long_key}\t100\t200\n{short_key}\t-1\tbad\n"),
        }
    )
    adapter = WireGuardStatusAdapter(FakeReader(), runner, "wg.exe")
    value = cast(dict[str, JsonValue], run(adapter.execute({}, token())))
    peers = cast(list[dict[str, JsonValue]], value["peers"])
    assert value["availability"] == Availability.AVAILABLE
    assert peers[0]["public_key_summary"] == f"{long_key[:8]}…{long_key[-4:]}"
    assert peers[0]["latest_handshake_epoch"] == 123
    assert peers[0]["received_bytes"] == 100
    assert peers[1]["public_key_summary"] == "[short-key]"
    assert peers[1]["latest_handshake_epoch"] is None
    assert peers[1]["received_bytes"] is None
    assert peers[1]["sent_bytes"] is None
    assert peers[2]["latest_handshake_epoch"] is None
    assert all(
        "private-key" not in command and "dump" not in command for command in runner.commands
    )


def test_windows_collection_adapters_succeed_and_degrade() -> None:
    reader = FakeReader()
    listeners = NetworkListenersAdapter(reader)
    listener_result = cast(dict[str, JsonValue], run(listeners.execute({}, token())))
    assert listener_result["availability"] == Availability.AVAILABLE
    assert cast(list[object], listener_result["items"])[0]

    reader.listener_error = True
    listener_error = cast(dict[str, JsonValue], run(listeners.execute({}, token())))
    assert listener_error["error_code"] == "permission_denied"

    processes = ProcessSummaryAdapter(reader)
    process_result = cast(dict[str, JsonValue], run(processes.execute({"limit": 1}, token())))
    assert process_result["availability"] == Availability.AVAILABLE
    assert reader.process_thread_id != get_ident()
    default_limit = cast(dict[str, JsonValue], run(processes.execute({}, token())))
    assert default_limit["availability"] == Availability.AVAILABLE
    reader.process_error = True
    process_error = cast(dict[str, JsonValue], run(processes.execute({}, token())))
    assert process_error["error_code"] == "permission_denied"

    with pytest.raises(asyncio.CancelledError):
        run(listeners.execute({}, token(True)))
    with pytest.raises(asyncio.CancelledError):
        run(processes.execute({}, token(True)))


def test_docker_adapter_only_returns_allowed_fields_and_handles_offline() -> None:
    docker_line = (
        '{"ID":"abc","Names":"pdf","Image":"pdf:latest",'
        '"Ports":"127.0.0.1:8080->8080/tcp","Status":"Up",'
        '"Environment":"SECRET=value"}'
    )
    runner = FakeRunner({"{{json .}}": command_result(f"\n{docker_line}\n")})
    adapter = DockerServicesAdapter(runner, "docker.exe")
    result = cast(dict[str, JsonValue], run(adapter.execute({}, token())))
    item = cast(list[dict[str, JsonValue]], result["items"])[0]
    assert DockerService.model_validate(item).name == "pdf"
    assert "Environment" not in item
    assert runner.commands[0][1:4] == ("ps", "--no-trunc", "--format")

    runner.results["{{json .}}"] = command_result(stderr="daemon offline", returncode=1)
    offline = cast(dict[str, JsonValue], run(adapter.execute({}, token())))
    assert offline["availability"] == Availability.UNAVAILABLE
    assert offline["error_code"] == "dependency_unavailable"
    with pytest.raises(asyncio.CancelledError):
        run(adapter.execute({}, token(True)))


def test_reachability_accepts_private_targets_and_rejects_public_targets() -> None:
    adapter = ServiceReachabilityAdapter()

    async def probe_local_server() -> dict[str, JsonValue]:
        server = await asyncio.start_server(lambda _r, _w: None, "127.0.0.1", 0)
        sockets = server.sockets
        assert sockets is not None
        port = int(sockets[0].getsockname()[1])
        try:
            return cast(
                dict[str, JsonValue],
                await adapter.execute(
                    {"host": "127.0.0.1", "port": port, "timeout_seconds": 1},
                    token(),
                ),
            )
        finally:
            server.close()
            await server.wait_closed()

    reachable = run(probe_local_server())
    assert reachable["reachable"] is True
    assert reachable["latency_ms"] is not None

    unreachable = cast(
        dict[str, JsonValue],
        run(
            adapter.execute(
                {"host": "127.0.0.1", "port": 1, "timeout_seconds": 0.1},
                token(),
            )
        ),
    )
    assert unreachable["reachable"] is False
    assert unreachable["error_code"] == "unreachable"
    with pytest.raises(ValueError, match="私有"):
        run(adapter.execute({"host": "8.8.8.8", "port": 53}, token()))
    with pytest.raises(asyncio.CancelledError):
        run(adapter.execute({"host": "127.0.0.1", "port": 80}, token(True)))


def test_node_summary_aggregates_model_wireguard_and_registered_tools() -> None:
    runner = FakeRunner(
        {
            "peers": command_result(),
            "allowed-ips": command_result(),
            "endpoints": command_result(),
            "latest-handshakes": command_result(),
            "transfer": command_result(),
        }
    )
    wireguard = WireGuardStatusAdapter(FakeReader(), runner, "wg.exe")
    registry = ToolRegistry()
    from tests.tools.test_registry import definition

    registry.register(definition("read_status"), NetworkListenersAdapter(FakeReader()))
    summary = NodeSummaryAdapter(NodeId.new(), registry, wireguard, lambda: "available")
    result = cast(dict[str, JsonValue], run(summary.execute({}, token())))
    assert result["platform"] == "windows"
    assert result["model_status"] == "available"
    assert result["available_tools"] == ["read_status"]


def test_wireguard_observes_pre_cancel() -> None:
    adapter = WireGuardStatusAdapter(FakeReader(), FakeRunner({}), "wg.exe")
    with pytest.raises(asyncio.CancelledError):
        run(adapter.execute({}, token(True)))
