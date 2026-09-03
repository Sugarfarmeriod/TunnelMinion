"""Windows 真实只读工具适配器。"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from collections.abc import Callable
from time import perf_counter
from typing import cast

from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.platforms.windows.models import (
    Availability,
    CollectionResult,
    DockerService,
    NodeSummary,
    ReachabilityResult,
    WireGuardPeerSummary,
    WireGuardStatus,
)
from tunnelminion.platforms.windows.system import CommandRunner, SystemReader
from tunnelminion.tools.contracts import ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry


def _json_value(value: object) -> JsonValue:
    return cast(JsonValue, value)


class WireGuardStatusAdapter:
    """读取 `HomeMac` 接口和 peer 统计，不请求或返回私钥。"""

    def __init__(
        self,
        reader: SystemReader,
        runner: CommandRunner,
        wg_path: str,
        *,
        interface_name: str = "HomeMac",
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
        del arguments
        if cancellation.cancelled:
            raise asyncio.CancelledError
        interface = self._reader.interface(self._interface_name)
        if interface is None:
            return _json_value(
                WireGuardStatus(
                    availability=Availability.UNAVAILABLE,
                    interface=self._interface_name,
                    interface_up=False,
                    error_code="dependency_unavailable",
                    error_message="未找到 WireGuard 接口",
                ).model_dump(mode="json")
            )

        peers_result = await self._runner.run(
            (self._wg_path, "show", self._interface_name, "peers"), 5
        )
        if peers_result.returncode != 0:
            permission_denied = "permission denied" in peers_result.stderr.lower()
            return _json_value(
                WireGuardStatus(
                    availability=Availability.DEGRADED,
                    interface=self._interface_name,
                    interface_up=interface.is_up,
                    addresses=interface.addresses,
                    error_code="permission_denied"
                    if permission_denied
                    else "dependency_unavailable",
                    error_message="当前账户无权读取 peer 统计"
                    if permission_denied
                    else "WireGuard CLI 查询失败",
                ).model_dump(mode="json")
            )

        peer_keys = tuple(line.strip() for line in peers_result.stdout.splitlines() if line.strip())
        allowed = await self._query_peer_map("allowed-ips")
        endpoints = await self._query_peer_map("endpoints")
        handshakes = await self._query_peer_map("latest-handshakes")
        transfer = await self._query_peer_map("transfer")
        peers = tuple(
            WireGuardPeerSummary(
                public_key_summary=self._summarize_key(key),
                endpoint=self._first(endpoints.get(key)),
                allowed_addresses=tuple((self._first(allowed.get(key)) or "").split(","))
                if self._first(allowed.get(key))
                else (),
                latest_handshake_epoch=self._integer(self._first(handshakes.get(key))),
                received_bytes=self._integer(self._item(transfer.get(key), 0)),
                sent_bytes=self._integer(self._item(transfer.get(key), 1)),
            )
            for key in peer_keys
        )
        return _json_value(
            WireGuardStatus(
                availability=Availability.AVAILABLE,
                interface=self._interface_name,
                interface_up=interface.is_up,
                addresses=interface.addresses,
                peers=peers,
            ).model_dump(mode="json")
        )

    async def _query_peer_map(self, field: str) -> dict[str, tuple[str, ...]]:
        result = await self._runner.run((self._wg_path, "show", self._interface_name, field), 5)
        if result.returncode != 0:
            return {}
        values: dict[str, tuple[str, ...]] = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                values[parts[0]] = tuple(parts[1:])
        return values

    @staticmethod
    def _summarize_key(value: str) -> str:
        return f"{value[:8]}…{value[-4:]}" if len(value) > 12 else "[short-key]"

    @staticmethod
    def _first(value: tuple[str, ...] | None) -> str | None:
        return value[0] if value else None

    @staticmethod
    def _item(value: tuple[str, ...] | None, index: int) -> str | None:
        return value[index] if value is not None and len(value) > index else None

    @staticmethod
    def _integer(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None


class NetworkListenersAdapter:
    """读取 TCP/UDP 监听端点并支持权限不足降级。"""

    def __init__(self, reader: SystemReader) -> None:
        self._reader = reader

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        del arguments
        if cancellation.cancelled:
            raise asyncio.CancelledError
        try:
            items = tuple(item.model_dump(mode="json") for item in self._reader.listeners())
            result = CollectionResult(availability=Availability.AVAILABLE, items=items)
        except PermissionError:
            result = CollectionResult(
                availability=Availability.DEGRADED,
                error_code="permission_denied",
                error_message="当前账户无法读取全部监听端点",
            )
        return _json_value(result.model_dump(mode="json"))


class ProcessSummaryAdapter:
    """读取有限数量的进程元数据。"""

    def __init__(self, reader: SystemReader) -> None:
        self._reader = reader

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        if cancellation.cancelled:
            raise asyncio.CancelledError
        limit = int(cast(int, arguments.get("limit", 50)))
        try:
            values = await asyncio.to_thread(self._reader.processes, limit)
            items = tuple(item.model_dump(mode="json") for item in values)
            result = CollectionResult(availability=Availability.AVAILABLE, items=items)
        except PermissionError:
            result = CollectionResult(
                availability=Availability.DEGRADED,
                error_code="permission_denied",
                error_message="当前账户无法读取进程摘要",
            )
        return _json_value(result.model_dump(mode="json"))


class DockerServicesAdapter:
    """只调用 `docker ps`，不读取环境变量或执行控制操作。"""

    def __init__(self, runner: CommandRunner, docker_path: str) -> None:
        self._runner = runner
        self._docker_path = docker_path

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        del arguments
        if cancellation.cancelled:
            raise asyncio.CancelledError
        result = await self._runner.run(
            (self._docker_path, "ps", "--no-trunc", "--format", "{{json .}}"), 10
        )
        if result.returncode != 0:
            return _json_value(
                CollectionResult(
                    availability=Availability.UNAVAILABLE,
                    error_code="dependency_unavailable",
                    error_message="Docker daemon 不可用",
                ).model_dump(mode="json")
            )
        services: list[dict[str, object]] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            services.append(
                DockerService(
                    container_id=str(item.get("ID", "")),
                    name=str(item.get("Names", "")),
                    image=str(item.get("Image", "")),
                    ports=str(item.get("Ports", "")),
                    status=str(item.get("Status", "")),
                ).model_dump(mode="json")
            )
        return _json_value(
            CollectionResult(
                availability=Availability.AVAILABLE,
                items=tuple(services),
            ).model_dump(mode="json")
        )


class ServiceReachabilityAdapter:
    """只建立受预算限制的 TCP 连接，不发送或读取应用正文。"""

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        if cancellation.cancelled:
            raise asyncio.CancelledError
        host = str(arguments["host"])
        port = int(cast(int, arguments["port"]))
        timeout_seconds = float(cast(float | int, arguments.get("timeout_seconds", 2)))
        address = ipaddress.ip_address(host)
        if not (address.is_private or address.is_loopback):
            raise ValueError("只允许探测私有或环回地址")
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(timeout_seconds):
                _, writer = await asyncio.open_connection(host, port)
            latency = (perf_counter() - started) * 1000
            result = ReachabilityResult(
                host=host, port=port, reachable=True, latency_ms=round(latency, 2)
            )
        except (TimeoutError, OSError):
            result = ReachabilityResult(
                host=host,
                port=port,
                reachable=False,
                error_code="unreachable",
            )
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
        return _json_value(result.model_dump(mode="json"))


class NodeSummaryAdapter:
    """聚合平台、模型、WireGuard 和工具能力状态。"""

    def __init__(
        self,
        node_id: NodeId,
        registry: ToolRegistry,
        wireguard: WireGuardStatusAdapter,
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
        wireguard = WireGuardStatus.model_validate(wireguard_value)
        summary = NodeSummary(
            node_id=str(self._node_id),
            platform=Platform.WINDOWS,
            agent_status="ready",
            model_status=self._model_status(),
            wireguard=wireguard,
            available_tools=tuple(
                item.name for item in self._registry.model_tools(Platform.WINDOWS)
            ),
        )
        return _json_value(summary.model_dump(mode="json"))
