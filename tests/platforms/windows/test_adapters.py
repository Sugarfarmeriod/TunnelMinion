"""Windows 只读工具适配器测试。"""

from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Coroutine
from threading import get_ident
from typing import Any, TypeVar, cast

import psutil
import pytest
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.web_page import WebPage
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
    CollectionResult,
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


def test_listener_entry_names_are_opt_in_local_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return (
                *(
                    NetworkListener(
                        protocol=protocol, address=host, port=43123, pid=101, process_name="python"
                    )
                    for protocol, host in (("tcp", "0.0.0.0"), ("tcp", "::"), ("udp", "0.0.0.0"))
                ),
                NetworkListener(protocol="tcp", address="127.0.0.1", port=43124),
            )

    class Process:
        def __init__(self, pid: int) -> None:
            assert pid == 101

        def name(self) -> str:
            return "python"

        def cmdline(self) -> list[str]:
            calls.append(101)
            return ["python", "/private/相册.py", "--token", "fixture-secret"]

    monkeypatch.setattr(psutil, "Process", Process)
    adapter = NetworkListenersAdapter(Reader())
    default = CollectionResult.model_validate(run(adapter.execute({}, token())))
    assert calls == []
    assert all("python_entrypoint" not in item for item in default.items)
    named = CollectionResult.model_validate(
        run(adapter.execute({"include_python_entrypoint": True}, token()))
    )
    assert calls == [101]
    assert [item.get("python_entrypoint") for item in named.items] == [
        "相册.py",
        "相册.py",
        None,
        None,
    ]
    assert "fixture-secret" not in named.model_dump_json()
    assert "private" not in named.model_dump_json()
    assert "cmdline" not in named.model_dump_json()


def test_program_names_are_opt_in_cached_and_do_not_export_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return (
                *tuple(
                    NetworkListener(
                        protocol=protocol,
                        address="0.0.0.0",
                        port=9527,
                        pid=101,
                        process_name="supernode",
                    )
                    for protocol in ("tcp", "udp")
                ),
                NetworkListener(protocol="tcp", address="127.0.0.1", port=805),
            )

    class Process:
        def __init__(self, pid: int) -> None:
            calls.append(pid)

        def name(self) -> str:
            return "supernode"

        def exe(self) -> str:
            return "/opt/private-installation/bin/supernode"

    monkeypatch.setattr(psutil, "Process", Process)
    adapter = NetworkListenersAdapter(Reader())
    unnamed = CollectionResult.model_validate(run(adapter.execute({}, token())))
    assert calls == [] and all("program_name" not in item for item in unnamed.items)
    named = CollectionResult.model_validate(
        run(adapter.execute({"include_program_names": True}, token()))
    )
    assert calls == [101]
    assert [item.get("program_name") for item in named.items] == ["supernode", "supernode", None]
    assert "private-installation" not in named.model_dump_json()


def test_python_project_name_is_separate_opt_in_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return tuple(
                NetworkListener(
                    protocol="tcp", address="127.0.0.1", port=port, pid=101, process_name="python"
                )
                for port in (8787, 8788)
            )

    def project_name(listener: NetworkListener, entrypoint: str | None) -> str | None:
        assert entrypoint == "app.py" and listener.pid == 101
        calls.append(101)
        return "Wireguard Panel"

    def entrypoint(listener: NetworkListener) -> str:
        return "app.py"

    def unknown_project(listener: NetworkListener, entrypoint: str | None) -> None:
        return None

    monkeypatch.setattr(
        "tunnelminion.platforms.windows.adapters.read_python_entrypoint", entrypoint
    )
    monkeypatch.setattr(
        "tunnelminion.platforms.windows.adapters.read_python_project_name", project_name
    )
    adapter = NetworkListenersAdapter(Reader())
    plain = CollectionResult.model_validate(
        run(adapter.execute({"include_python_entrypoint": True}, token()))
    )
    assert calls == [] and all("python_project_name" not in item for item in plain.items)
    named = CollectionResult.model_validate(
        run(adapter.execute({"include_python_project_name": True}, token()))
    )
    assert calls == [101] and [item["python_project_name"] for item in named.items] == [
        "Wireguard Panel",
        "Wireguard Panel",
    ]
    assert all("python_entrypoint" not in item for item in named.items)
    monkeypatch.setattr(
        "tunnelminion.platforms.windows.adapters.read_python_project_name",
        unknown_project,
    )
    unknown = CollectionResult.model_validate(
        run(
            adapter.execute(
                {"include_python_project_name": True, "include_python_entrypoint": True}, token()
            )
        )
    )
    assert all(
        item["python_entrypoint"] == "app.py" and "python_project_name" not in item
        for item in unknown.items
    )


def test_process_origin_is_opt_in_cached_and_exports_only_the_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, str | None]] = []

    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return (
                *tuple(
                    NetworkListener(
                        protocol=protocol,
                        address="0.0.0.0",
                        port=9527,
                        pid=101,
                        process_name="supernode",
                    )
                    for protocol in ("tcp", "udp")
                ),
                NetworkListener(protocol="tcp", address="127.0.0.1", port=7000, pid=102),
                NetworkListener(protocol="tcp", address="127.0.0.1", port=805),
            )

    def origin(pid: int, expected_name: str | None) -> ProcessOrigin | None:
        calls.append((pid, expected_name))
        return ProcessOrigin.TERMINAL if pid == 101 else None

    monkeypatch.setattr("tunnelminion.platforms.windows.adapters.read_process_origin", origin)
    adapter = NetworkListenersAdapter(Reader())
    plain = CollectionResult.model_validate(run(adapter.execute({}, token())))
    assert calls == [] and all("origin" not in item for item in plain.items)
    marked = CollectionResult.model_validate(
        run(adapter.execute({"include_process_origin": True}, token()))
    )
    assert calls == [(101, "supernode"), (102, None)]
    assert [item.get("origin") for item in marked.items] == ["terminal", "terminal", None, None]


def test_web_pages_are_opt_in_and_skip_system_desktop_udp_own_and_public_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probed: list[tuple[str, int]] = []

    def listener(protocol: str, address: str, port: int, pid: int, name: str) -> NetworkListener:
        return NetworkListener(
            protocol=protocol, address=address, port=port, pid=pid, process_name=name
        )

    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return (
                listener("tcp", "0.0.0.0", 8787, 101, "python"),
                listener("tcp", "::", 8787, 101, "python"),
                listener("tcp", "0.0.0.0", 8787, 101, "python"),
                listener("tcp", "0.0.0.0", 9000, 102, "agent"),
                listener("tcp", "0.0.0.0", 445, 4, "System"),
                listener("tcp", "0.0.0.0", 27036, 5, "steam"),
                listener("udp", "0.0.0.0", 5353, 101, "python"),
                listener("tcp", "127.0.0.1", 7000, os.getpid(), "me"),
                listener("tcp", "8.8.8.8", 80, 103, "odd"),
            )

    origins = {
        101: ProcessOrigin.TERMINAL,
        4: ProcessOrigin.SYSTEM,
        5: ProcessOrigin.DESKTOP_APP,
        103: ProcessOrigin.UNKNOWN,
    }

    def origin(pid: int, expected_name: str | None) -> ProcessOrigin | None:
        return origins.get(pid)

    def probe(address: str, port: int) -> WebPage | None:
        probed.append((address, port))
        if port != 8787:
            return None
        return WebPage(title="WireGuard Panel" if address == "0.0.0.0" else None)

    monkeypatch.setattr("tunnelminion.platforms.windows.adapters.read_process_origin", origin)
    monkeypatch.setattr("tunnelminion.platforms.windows.adapters.probe_web_page", probe)
    adapter = NetworkListenersAdapter(Reader())
    plain = CollectionResult.model_validate(
        run(adapter.execute({"include_process_origin": True}, token()))
    )
    assert probed == [] and all("has_web_page" not in item for item in plain.items)
    marked = CollectionResult.model_validate(
        run(adapter.execute({"include_process_origin": True, "include_web_title": True}, token()))
    )
    assert sorted(probed) == [("0.0.0.0", 8787), ("0.0.0.0", 9000), ("::", 8787)]
    summary = [
        (item["address"], item["port"], item.get("has_web_page"), item.get("web_title"))
        for item in marked.items
    ]
    assert summary[:4] == [
        ("0.0.0.0", 8787, True, "WireGuard Panel"),
        ("::", 8787, True, None),
        ("0.0.0.0", 8787, True, "WireGuard Panel"),
        ("0.0.0.0", 9000, False, None),
    ]
    assert all(item.get("has_web_page") is None for item in marked.items[4:])


def test_web_probing_respects_count_and_time_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return tuple(
                NetworkListener(protocol="tcp", address="127.0.0.1", port=port, pid=port)
                for port in range(2000, 2040)
            )

    release = threading.Event()

    def probe(address: str, port: int) -> WebPage | None:
        if port == 2000:
            release.wait(2)
        return WebPage(title=None)

    monkeypatch.setattr("tunnelminion.platforms.windows.adapters.probe_web_page", probe)
    monkeypatch.setattr("tunnelminion.platforms.windows.adapters._WEB_PROBE_DEADLINE_SECONDS", 0.5)
    result = CollectionResult.model_validate(
        run(NetworkListenersAdapter(Reader()).execute({"include_web_title": True}, token()))
    )
    release.set()
    probed = {item["port"] for item in result.items if "has_web_page" in item}
    # 只探前 32 个；卡住的那个超过总时限，不给出结论。
    assert 2000 not in probed and probed == set(range(2001, 2032))


def test_web_probing_with_no_candidates_does_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def probe(address: str, port: int) -> WebPage | None:
        raise AssertionError("不应探测")

    class Reader(FakeReader):
        def listeners(self) -> tuple[NetworkListener, ...]:
            return (NetworkListener(protocol="udp", address="0.0.0.0", port=53, pid=9),)

    monkeypatch.setattr("tunnelminion.platforms.windows.adapters.probe_web_page", probe)
    result = CollectionResult.model_validate(
        run(NetworkListenersAdapter(Reader()).execute({"include_web_title": True}, token()))
    )
    assert "has_web_page" not in result.items[0]


def test_docker_adapter_reads_compose_project_from_labels() -> None:
    lines = "\n".join(
        (
            '{"ID":"a","Names":"penpot-web-1","Image":"web","Ports":"","Status":"Up",'
            '"Labels":"com.docker.compose.service=web, com.docker.compose.project=penpot"}',
            '{"ID":"b","Names":"solo","Image":"solo","Ports":"","Status":"Exited (0)"}',
            '{"ID":"c","Names":"long","Image":"x","Ports":"","Status":"Up",'
            f'"Labels":"com.docker.compose.project={"x" * 81}"}}',
        )
    )
    adapter = DockerServicesAdapter(FakeRunner({"{{json .}}": command_result(lines)}), "docker")
    result = CollectionResult.model_validate(run(adapter.execute({}, token())))
    services = [DockerService.model_validate(item) for item in result.items]
    assert [item.compose_project for item in services] == ["penpot", None, None]
    assert [item.running for item in services] == [True, False, True]


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
    assert runner.commands[0][1:5] == ("ps", "-a", "--no-trunc", "--format")

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
