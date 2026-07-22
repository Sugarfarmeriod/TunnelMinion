"""macOS 六个确定性只读工具适配器。"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import cast

from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.platforms.macos.system import CommandRunner, SystemReader
from tunnelminion.platforms.windows.adapters import (
    DockerServicesAdapter,
    NetworkListenersAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
    WireGuardStatusAdapter,
)
from tunnelminion.platforms.windows.models import (
    Availability,
    NodeSummary,
    WireGuardStatus,
)
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry

__all__ = [
    "DockerServicesAdapter",
    "MacOSNodeSummaryAdapter",
    "MacOSWireGuardStatusAdapter",
    "NetworkListenersAdapter",
    "ProcessSummaryAdapter",
    "ServiceReachabilityAdapter",
]


def _json_value(value: object) -> JsonValue:
    return cast(JsonValue, value)


class MacOSWireGuardStatusAdapter:
    """先只读发现 utun/WireGuard 接口，再复用脱敏 peer 查询。"""

    def __init__(
        self,
        reader: SystemReader,
        runner: CommandRunner,
        wg_path: str,
        *,
        interface_name: str | None = None,
    ) -> None:
        self._reader = reader
        self._runner = runner
        self._wg_path = wg_path
        self._interface_name = interface_name

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        if cancellation.cancelled:
            raise asyncio.CancelledError
        discovered = await self._runner.run((self._wg_path, "show", "interfaces"), 5)
        if discovered.returncode != 0:
            denied = "permission denied" in discovered.stderr.lower()
            return _json_value(
                WireGuardStatus(
                    availability=(Availability.DEGRADED if denied else Availability.UNAVAILABLE),
                    interface=self._interface_name or "unknown",
                    interface_up=False,
                    error_code=("permission_denied" if denied else "dependency_unavailable"),
                    error_message=(
                        "当前账户无权发现 WireGuard 接口" if denied else "WireGuard CLI 不可用"
                    ),
                ).model_dump(mode="json")
            )
        interfaces = tuple(discovered.stdout.split())
        selected = self._select_interface(interfaces)
        if selected is None:
            return _json_value(
                WireGuardStatus(
                    availability=Availability.UNAVAILABLE,
                    interface=self._interface_name or "unknown",
                    interface_up=False,
                    error_code="dependency_unavailable",
                    error_message="未发现运行中的 WireGuard 接口",
                ).model_dump(mode="json")
            )
        delegate = WireGuardStatusAdapter(
            self._reader,
            self._runner,
            self._wg_path,
            interface_name=selected,
        )
        return await delegate.execute(arguments, cancellation)

    def _select_interface(self, interfaces: tuple[str, ...]) -> str | None:
        if self._interface_name is not None:
            return self._interface_name if self._interface_name in interfaces else None
        return interfaces[0] if interfaces else None


class MacOSNodeSummaryAdapter:
    """聚合 macOS 平台、模型、WireGuard 和只读工具能力。"""

    def __init__(
        self,
        node_id: NodeId,
        registry: ToolRegistry,
        wireguard: MacOSWireGuardStatusAdapter,
        model_status: Callable[[], str],
    ) -> None:
        self._node_id = node_id
        self._registry = registry
        self._wireguard = wireguard
        self._model_status = model_status

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        wireguard_value = await self._wireguard.execute(arguments, cancellation)
        summary = NodeSummary(
            node_id=str(self._node_id),
            platform=Platform.MACOS,
            agent_status="ready",
            model_status=self._model_status(),
            wireguard=WireGuardStatus.model_validate(wireguard_value),
            available_tools=tuple(item.name for item in self._registry.model_tools(Platform.MACOS)),
        )
        return _json_value(summary.model_dump(mode="json"))
