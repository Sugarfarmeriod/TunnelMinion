"""目标节点执行前对已提交 HTTP 服务计划进行实时保守复核。"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime
from typing import Protocol

import httpx

from tunnelminion.operation.contracts import (
    OperationStore,
    ServiceEvidence,
    compute_service_fingerprint,
)
from tunnelminion.platforms.windows.models import NetworkListener


class ServiceIdentityReader(Protocol):
    """执行前只读重取监听身份所需的最小平台边界。"""

    def listeners(self) -> tuple[NetworkListener, ...]: ...


class HTTPServiceProbeEvidenceProvider:
    """只复核已提交计划中的环回 HTTP 端点，不发现或修改其他服务。"""

    def __init__(
        self,
        operations: OperationStore,
        *,
        timeout_seconds: float = 3,
        transport: httpx.AsyncBaseTransport | None = None,
        identity_reader: ServiceIdentityReader | None = None,
    ) -> None:
        if not 0 < timeout_seconds <= 30:
            raise ValueError("服务复核超时必须在 0 到 30 秒之间")
        self._operations = operations
        self._timeout = timeout_seconds
        self._transport = transport
        self._identity_reader = identity_reader

    async def read(self, service_id: str) -> ServiceEvidence | None:
        """对匹配计划的环回端点发起有界请求，失败时保守拒绝执行。"""
        matches = tuple(
            record
            for record in self._operations.list_all()
            if record.plan.service.service_id == service_id
        )
        if not matches:
            return None
        record = max(matches, key=lambda item: item.plan.service.observed_at)
        expected = record.plan.service
        try:
            address = ipaddress.ip_address(expected.host)
        except ValueError:
            return None
        if expected.scheme != "http" or not address.is_loopback or not 1 <= expected.port <= 65535:
            return None
        if self._identity_reader is not None:
            try:
                listeners = await asyncio.to_thread(self._identity_reader.listeners)
            except PermissionError:
                return None
            current = tuple(
                item
                for item in listeners
                if item.protocol == "tcp"
                and item.address == expected.host
                and item.port == expected.port
            )
            if len(current) != 1:
                return None
            listener = current[0]
            fingerprint = compute_service_fingerprint(
                node_id=record.plan.target_node_id,
                protocol=listener.protocol,
                address=listener.address,
                port=listener.port,
                process_pid=listener.pid,
                process_name=listener.process_name,
            )
            if fingerprint != expected.fingerprint:
                return None
        try:
            async with (
                httpx.AsyncClient(
                    timeout=self._timeout,
                    trust_env=False,
                    transport=self._transport,
                ) as client,
                client.stream(
                    "GET",
                    f"http://{expected.host}:{expected.port}/",
                    headers={"Range": "bytes=0-0"},
                ) as response,
            ):
                if response.status_code >= 500:
                    return None
        except httpx.HTTPError:
            return None
        return expected.model_copy(update={"observed_at": datetime.now(UTC)})
