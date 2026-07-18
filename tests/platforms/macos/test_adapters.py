"""macOS WireGuard 发现与节点摘要测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar, cast

import pytest
from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.platforms.macos.adapters import (
    MacOSNodeSummaryAdapter,
    MacOSWireGuardStatusAdapter,
    NetworkListenersAdapter,
)
from tunnelminion.platforms.windows.models import InterfaceSnapshot, NetworkListener, ProcessInfo
from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry

T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """执行异步适配器动作。"""
    return asyncio.run(coroutine)


class FakeMacReader:
    """返回固定 macOS 系统元数据。"""

    def __init__(self) -> None:
        self.requested_interfaces: list[str] = []

    def interface(self, name: str) -> InterfaceSnapshot | None:
        self.requested_interfaces.append(name)
        return InterfaceSnapshot(name=name, is_up=True, addresses=("10.77.0.1",))

    def listeners(self) -> tuple[NetworkListener, ...]:
        return ()

    def processes(self, limit: int) -> tuple[ProcessInfo, ...]:
        del limit
        return ()


class FakeRunner:
    """按固定 `wg show` 字段返回结果并记录命令。"""

    def __init__(self, results: dict[str, CommandResult]) -> None:
        self.results = results
        self.commands: list[tuple[str, ...]] = []

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.commands.append(command)
        return self.results[command[-1]]


def result(stdout: str = "", stderr: str = "", returncode: int = 0) -> CommandResult:
    """构造固定命令结果。"""
    return CommandResult(returncode=returncode, stdout=stdout, stderr=stderr)


def token(cancelled: bool = False) -> ToolCancellationToken:
    """构造可选的预取消信号。"""
    value = ToolCancellationToken()
    if cancelled:
        value.cancel()
    return value


def successful_runner() -> FakeRunner:
    """构造可完整读取一个 utun 接口的命令结果。"""
    key = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG="
    return FakeRunner(
        {
            "interfaces": result("utun7\n"),
            "peers": result(f"{key}\n"),
            "allowed-ips": result(f"{key}\t10.77.0.2/32\n"),
            "endpoints": result(f"{key}\t10.0.0.2:51820\n"),
            "latest-handshakes": result(f"{key}\t123\n"),
            "transfer": result(f"{key}\t100\t200\n"),
        }
    )


def test_macos_wireguard_discovers_interface_without_secret_queries() -> None:
    """macOS 先发现接口，再使用不含 private-key/dump 的字段查询。"""
    reader = FakeMacReader()
    runner = successful_runner()
    adapter = MacOSWireGuardStatusAdapter(reader, runner, "/opt/homebrew/bin/wg")

    value = cast(dict[str, JsonValue], run(adapter.execute({}, token())))

    assert value["availability"] == "available"
    assert value["interface"] == "utun7"
    assert reader.requested_interfaces == ["utun7"]
    assert all(
        "private-key" not in command and "dump" not in command for command in runner.commands
    )
    assert "PRIVATE" not in str(value)


@pytest.mark.parametrize(
    ("stderr", "expected_availability", "expected_code"),
    [
        ("Permission denied", "degraded", "permission_denied"),
        ("wg missing", "unavailable", "dependency_unavailable"),
    ],
)
def test_macos_wireguard_discovery_degrades_structurally(
    stderr: str, expected_availability: str, expected_code: str
) -> None:
    """发现权限不足和 CLI 缺失不会使 Runtime 崩溃。"""
    runner = FakeRunner({"interfaces": result(stderr=stderr, returncode=1)})
    adapter = MacOSWireGuardStatusAdapter(FakeMacReader(), runner, "wg")

    value = cast(dict[str, JsonValue], run(adapter.execute({}, token())))

    assert value["availability"] == expected_availability
    assert value["error_code"] == expected_code


def test_macos_wireguard_handles_empty_and_explicit_interface_selection() -> None:
    """空接口或缺失的显式接口都稳定降级，显式存在时按配置读取。"""
    empty = FakeRunner({"interfaces": result()})
    value = cast(
        dict[str, JsonValue],
        run(MacOSWireGuardStatusAdapter(FakeMacReader(), empty, "wg").execute({}, token())),
    )
    assert value["error_code"] == "dependency_unavailable"

    missing = FakeRunner({"interfaces": result("utun7")})
    configured = MacOSWireGuardStatusAdapter(FakeMacReader(), missing, "wg", interface_name="utun9")
    missing_value = cast(dict[str, JsonValue], run(configured.execute({}, token())))
    assert missing_value["interface"] == "utun9"

    runner = successful_runner()
    explicit = MacOSWireGuardStatusAdapter(FakeMacReader(), runner, "wg", interface_name="utun7")
    assert cast(dict[str, JsonValue], run(explicit.execute({}, token())))["interface"] == "utun7"

    with pytest.raises(asyncio.CancelledError):
        run(explicit.execute({}, token(True)))


def test_macos_node_summary_reports_platform_and_registered_capabilities() -> None:
    """节点摘要不依赖本地模型即可报告 macOS 工具能力。"""
    reader = FakeMacReader()
    wireguard = MacOSWireGuardStatusAdapter(reader, successful_runner(), "wg")
    registry = ToolRegistry()
    from tests.tools.test_registry import definition

    definition_value = definition("read_status").model_copy(update={"platforms": {"macos"}})
    registry.register(definition_value, NetworkListenersAdapter(reader))
    adapter = MacOSNodeSummaryAdapter(NodeId.new(), registry, wireguard, lambda: "unconfigured")

    value = cast(dict[str, JsonValue], run(adapter.execute({}, token())))

    assert value["platform"] == "macos"
    assert value["model_status"] == "unconfigured"
    assert value["available_tools"] == ["read_status"]
