"""Windows 真实只读工具适配器。"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from time import perf_counter
from typing import cast

from pydantic import JsonValue

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.platforms.process_origin import ProcessOrigin, read_process_origin
from tunnelminion.platforms.program_name import read_program_name
from tunnelminion.platforms.python_entrypoint import (
    read_python_entrypoint,
    read_python_project_name,
)
from tunnelminion.platforms.web_page import WebPage, probe_host, probe_web_page
from tunnelminion.platforms.windows.models import (
    Availability,
    CollectionResult,
    DockerService,
    NetworkListener,
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
    """读取监听端点，按需在本机缩减 Python 入口与自装程序名称。"""

    def __init__(self, reader: SystemReader) -> None:
        self._reader = reader

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        if cancellation.cancelled:
            raise asyncio.CancelledError
        try:
            items = await asyncio.to_thread(
                self._items,
                arguments.get("include_python_entrypoint") is True,
                arguments.get("include_program_names") is True,
                arguments.get("include_python_project_name") is True,
                arguments.get("include_process_origin") is True,
                arguments.get("include_web_title") is True,
            )
            result = CollectionResult(availability=Availability.AVAILABLE, items=items)
        except PermissionError:
            result = CollectionResult(
                availability=Availability.DEGRADED,
                error_code="permission_denied",
                error_message="当前账户无法读取全部监听端点",
            )
        return _json_value(result.model_dump(mode="json"))

    def _items(
        self,
        include_python_entrypoint: bool,
        include_program_names: bool,
        include_python_project_name: bool,
        include_process_origin: bool = False,
        include_web_title: bool = False,
    ) -> tuple[dict[str, object], ...]:
        items: list[dict[str, object]] = []
        listeners = self._reader.listeners()
        entrypoints: dict[tuple[int | None, str | None], str | None] = {}
        programs: dict[tuple[int | None, str | None], str | None] = {}
        projects: dict[tuple[int | None, str | None], str | None] = {}
        origins: dict[tuple[int | None, str | None], ProcessOrigin | None] = {}
        if include_process_origin:
            for listener in listeners:
                key = (listener.pid, listener.process_name)
                if listener.pid is not None and key not in origins:
                    # 路径和父进程只在本机用于判断，输出里只有来历类别。
                    origins[key] = read_process_origin(listener.pid, listener.process_name)
        pages = (
            _probe_web_pages(
                tuple(
                    listener
                    for listener in listeners
                    # 系统程序和桌面应用不会是用户的服务，不去访问它们的端口。
                    if origins.get((listener.pid, listener.process_name)) not in _NOT_SERVICES
                )
            )
            if include_web_title
            else {}
        )
        for listener in listeners:
            item = listener.model_dump(
                mode="json",
                exclude={
                    "python_entrypoint",
                    "program_name",
                    "python_project_name",
                    "origin",
                    "has_web_page",
                    "web_title",
                },
            )
            key = (listener.pid, listener.process_name)
            page_key = (listener.address, listener.port)
            if listener.protocol == "tcp" and page_key in pages:
                page = pages[page_key]
                item["has_web_page"] = page is not None
                if page is not None and page.title is not None:
                    item["web_title"] = page.title
            if origins.get(key) is not None:
                item["origin"] = origins[key]
            if include_program_names:
                if key not in programs:
                    programs[key] = read_program_name(listener)
                if programs[key] is not None:
                    item["program_name"] = programs[key]
            if (
                include_python_entrypoint or include_python_project_name
            ) and listener.protocol == "tcp":
                if key not in entrypoints:
                    entrypoints[key] = read_python_entrypoint(listener)
                if include_python_entrypoint and entrypoints[key] is not None:
                    item["python_entrypoint"] = entrypoints[key]
                if include_python_project_name:
                    if key not in projects:
                        projects[key] = read_python_project_name(listener, entrypoints[key])
                    if projects[key] is not None:
                        item["python_project_name"] = projects[key]
            items.append(item)
        return tuple(items)


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


_NOT_SERVICES = frozenset({ProcessOrigin.SYSTEM, ProcessOrigin.DESKTOP_APP})
_WEB_PROBE_LIMIT = 32
_WEB_PROBE_WORKERS = 8
_WEB_PROBE_DEADLINE_SECONDS = 4.0


def _probe_web_pages(
    listeners: tuple[NetworkListener, ...],
) -> dict[tuple[str, int], WebPage | None]:
    """并发访问候选端口的首页；超出数量或总时限的端口不探测，结果里也不出现。"""
    candidates: list[tuple[str, int]] = []
    for listener in listeners:
        key = (listener.address, listener.port)
        if (
            listener.protocol != "tcp"
            or listener.pid == os.getpid()
            or key in candidates
            or probe_host(listener.address) is None
        ):
            continue
        candidates.append(key)
    candidates = candidates[:_WEB_PROBE_LIMIT]
    if not candidates:
        return {}
    results: dict[tuple[str, int], WebPage | None] = {}
    executor = ThreadPoolExecutor(max_workers=_WEB_PROBE_WORKERS)
    try:
        futures = {executor.submit(probe_web_page, *key): key for key in candidates}
        done, _ = wait(futures, timeout=_WEB_PROBE_DEADLINE_SECONDS)
        for future in done:
            results[futures[future]] = future.result()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return results


def _compose_project(labels: str) -> str | None:
    """从 `docker ps` 的标签串里取 compose 项目名，同一项目的容器在首页合并成一项。"""
    for pair in labels.split(","):
        key, _, value = pair.partition("=")
        if key.strip() == "com.docker.compose.project" and 0 < len(value.strip()) <= 80:
            return value.strip()
    return None


class DockerServicesAdapter:
    """只调用 `docker ps -a`，不读取环境变量或执行控制操作。"""

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
            (self._docker_path, "ps", "-a", "--no-trunc", "--format", "{{json .}}"), 10
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
                    compose_project=_compose_project(str(item.get("Labels", ""))),
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
