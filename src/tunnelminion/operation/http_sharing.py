"""只绑定显式 WireGuard 地址的有界临时 HTTP 共享适配器。"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import secrets
import socket
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

import httpx
import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.domain.identifiers import OperationId, ResourceId
from tunnelminion.operation.contracts import (
    CleanupRecord,
    CleanupResult,
    LeaseRecord,
    OperationError,
    OperationErrorCode,
    OperationPlan,
    ResourceOwnership,
)
from tunnelminion.operation.workflow import AdapterExecutionResult

SHARE_TOKEN_HEADER = "X-TunnelMinion-Share-Token"
_REQUEST_HOP_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        SHARE_TOKEN_HEADER.lower(),
    }
)
_RESPONSE_HOP_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


class HTTPProxyLimits(BaseModel):
    """每个临时入口的确定性资源预算。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_concurrent_requests: int = Field(default=16, ge=1, le=256)
    max_request_bytes: int = Field(default=1_048_576, ge=1, le=16_777_216)
    max_response_bytes: int = Field(default=4_194_304, ge=1, le=67_108_864)
    request_timeout_seconds: float = Field(default=15, gt=0, le=120)
    graceful_shutdown_seconds: float = Field(default=5, gt=0, le=30)


class HTTPSharingConfig(BaseModel):
    """由目标节点本地配置的 WireGuard 地址、端口和 peer 地址映射。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wireguard_addresses: frozenset[str] = Field(min_length=1)
    allowed_peer_addresses: dict[str, frozenset[str]]
    minimum_port: int = Field(default=18_880, ge=1024, le=65535)
    maximum_port: int = Field(default=18_899, ge=1024, le=65535)
    maximum_duration_seconds: int = Field(default=3600, ge=1, le=86_400)
    limits: HTTPProxyLimits = Field(default_factory=HTTPProxyLimits)


class StopResult(StrEnum):
    """代理运行时的所有权检查与停止结果。"""

    STOPPED = "stopped"
    ALREADY_MISSING = "already_missing"
    OWNERSHIP_MISMATCH = "ownership_mismatch"
    FAILED = "failed"


class ProxyRuntime(Protocol):
    """可由真实 Uvicorn 或测试假实现提供的进程所有权边界。"""

    def start(
        self,
        app: FastAPI,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
        expires_at: datetime,
        graceful_shutdown_seconds: float,
    ) -> int: ...

    def stop(
        self,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
    ) -> StopResult: ...


class _UvicornHandle:
    """仅保存在本进程内的 Uvicorn 所有权句柄。"""

    def __init__(
        self,
        server: uvicorn.Server,
        thread: threading.Thread,
        timer: threading.Timer,
        fingerprint: str,
    ) -> None:
        self.server = server
        self.thread = thread
        self.timer = timer
        self.fingerprint = fingerprint


class UvicornProxyRuntime(ProxyRuntime):
    """以显式句柄启动、排空并停止内嵌 Uvicorn 代理。"""

    def __init__(self) -> None:
        self._handles: dict[tuple[str, int], _UvicornHandle] = {}
        self._lock = threading.Lock()

    def start(
        self,
        app: FastAPI,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
        expires_at: datetime,
        graceful_shutdown_seconds: float,
    ) -> int:
        endpoint = (host, port)
        with self._lock:
            if endpoint in self._handles or _port_is_occupied(host, port):
                raise OSError("入口端口已被占用")
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=host,
                    port=port,
                    log_level="error",
                    access_log=False,
                    timeout_graceful_shutdown=int(graceful_shutdown_seconds),
                )
            )
            thread = threading.Thread(target=server.run, daemon=True)
            delay = max(0.0, (expires_at - datetime.now(UTC)).total_seconds())
            timer = threading.Timer(
                delay,
                self._expire,
                kwargs={
                    "host": host,
                    "port": port,
                    "owner_fingerprint": owner_fingerprint,
                },
            )
            handle = _UvicornHandle(server, thread, timer, owner_fingerprint)
            self._handles[endpoint] = handle
            thread.start()
            timer.daemon = True
            timer.start()
        if not _wait_for_listener(host, port, thread):
            self.stop(host=host, port=port, owner_fingerprint=owner_fingerprint)
            raise RuntimeError("临时 HTTP 入口未能启动")
        return os.getpid()

    def stop(
        self,
        *,
        host: str,
        port: int,
        owner_fingerprint: str,
    ) -> StopResult:
        endpoint = (host, port)
        with self._lock:
            handle = self._handles.get(endpoint)
            if handle is None:
                return (
                    StopResult.OWNERSHIP_MISMATCH
                    if _port_is_occupied(host, port)
                    else StopResult.ALREADY_MISSING
                )
            if not secrets.compare_digest(handle.fingerprint, owner_fingerprint):
                return StopResult.OWNERSHIP_MISMATCH
            self._handles.pop(endpoint)
        handle.timer.cancel()
        handle.server.should_exit = True
        handle.thread.join(timeout=float(handle.server.config.timeout_graceful_shutdown or 5) + 1)
        return StopResult.FAILED if handle.thread.is_alive() else StopResult.STOPPED

    def _expire(self, *, host: str, port: int, owner_fingerprint: str) -> None:
        self.stop(host=host, port=port, owner_fingerprint=owner_fingerprint)


def _port_is_occupied(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        try:
            candidate.bind((host, port))
        except OSError:
            return True
    return False


def _wait_for_listener(host: str, port: int, thread: threading.Thread) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and thread.is_alive():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.1)
            if client.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.02)
    return False


def validate_http_sharing_plan(plan: OperationPlan, config: HTTPSharingConfig) -> None:
    """在创建监听前验证地址、上游、peer、端口和时长边界。"""
    bind = ipaddress.ip_address(plan.access_scope.bind_host)
    if bind.is_unspecified or bind.is_loopback or not bind.is_private:
        raise ValueError("共享入口必须绑定显式 WireGuard 私网地址")
    if plan.access_scope.bind_host not in config.wireguard_addresses:
        raise ValueError("共享入口地址不在本地允许的 WireGuard 地址集合")
    if config.maximum_port < config.minimum_port:
        raise ValueError("共享端口范围无效")
    if not config.minimum_port <= plan.access_scope.bind_port <= config.maximum_port:
        raise ValueError("共享入口端口超出本地策略范围")
    if plan.access_scope.duration_seconds > config.maximum_duration_seconds:
        raise ValueError("共享持续时间超出本地策略上限")
    upstream = ipaddress.ip_address(plan.service.host)
    if not upstream.is_loopback:
        raise ValueError("第一版 HTTP 共享上游必须监听环回地址")
    if plan.service.scheme != "http":
        raise ValueError("第一版仅支持明文环回 HTTP 上游")
    peer_addresses = config.allowed_peer_addresses.get(str(plan.request_node_id))
    if not peer_addresses:
        raise ValueError("请求 peer 没有配置可验证的 WireGuard 来源地址")
    for address in peer_addresses:
        parsed = ipaddress.ip_address(address)
        if parsed.is_unspecified or parsed.is_loopback or not parsed.is_private:
            raise ValueError("请求 peer 来源必须是显式 WireGuard 私网地址")


def create_bounded_proxy_app(
    *,
    upstream_url: str,
    access_token: str,
    allowed_client_addresses: frozenset[str],
    expires_at: datetime,
    limits: HTTPProxyLimits,
    transport: httpx.AsyncBaseTransport | None = None,
    now: Callable[[], datetime] | None = None,
) -> FastAPI:
    """创建带来源、凭据、租约和资源预算的 HTTP 代理应用。"""
    app = FastAPI(title="TunnelMinion Temporary HTTP Share", docs_url=None)
    semaphore = asyncio.Semaphore(limits.max_concurrent_requests)
    clock = now or (lambda: datetime.now(UTC))

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def proxy(path: str, request: Request) -> Response:
        client_host = request.client.host if request.client is not None else ""
        if client_host not in allowed_client_addresses:
            return _proxy_error(status.HTTP_403_FORBIDDEN, "peer_not_allowed")
        supplied = request.headers.get(SHARE_TOKEN_HEADER, "")
        if not secrets.compare_digest(supplied, access_token):
            return _proxy_error(status.HTTP_401_UNAUTHORIZED, "invalid_share_token")
        if clock() >= expires_at:
            return _proxy_error(status.HTTP_410_GONE, "share_expired")
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                return _proxy_error(status.HTTP_400_BAD_REQUEST, "invalid_content_length")
            if declared_length > limits.max_request_bytes:
                return _proxy_error(status.HTTP_413_CONTENT_TOO_LARGE, "request_too_large")
        body = await request.body()
        if len(body) > limits.max_request_bytes:
            return _proxy_error(status.HTTP_413_CONTENT_TOO_LARGE, "request_too_large")
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in _REQUEST_HOP_HEADERS
        }
        try:
            async with (
                semaphore,
                httpx.AsyncClient(
                    transport=transport,
                    timeout=limits.request_timeout_seconds,
                    trust_env=False,
                ) as client,
            ):
                upstream = await client.request(
                    request.method,
                    f"{upstream_url.rstrip('/')}/{path}",
                    content=body,
                    headers=headers,
                )
        except httpx.TimeoutException:
            return _proxy_error(status.HTTP_504_GATEWAY_TIMEOUT, "upstream_timeout")
        except httpx.HTTPError:
            return _proxy_error(status.HTTP_502_BAD_GATEWAY, "upstream_unavailable")
        if len(upstream.content) > limits.max_response_bytes:
            return _proxy_error(status.HTTP_502_BAD_GATEWAY, "upstream_response_too_large")
        response_headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower() not in _RESPONSE_HOP_HEADERS
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
        )

    _ = proxy
    return app


def _proxy_error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code}})


class HTTPSharingAdapter:
    """把已验证环回 HTTP 服务映射到受控 WireGuard 入口。"""

    def __init__(
        self,
        config: HTTPSharingConfig,
        runtime: ProxyRuntime | None = None,
    ) -> None:
        self._config = config
        self._runtime = runtime or UvicornProxyRuntime()

    async def create(
        self,
        plan: OperationPlan,
        lease: LeaseRecord,
        access_token: str,
    ) -> AdapterExecutionResult:
        """验证全部策略后启动唯一自有代理资源。"""
        try:
            validate_http_sharing_plan(plan, self._config)
            if len(access_token) < 43:
                raise ValueError("临时访问令牌熵不足")
            if lease.operation_id != plan.operation_id:
                raise ValueError("租约与操作不匹配")
            resource_id = ResourceId.new()
            fingerprint = _resource_fingerprint(plan, resource_id)
            app = create_bounded_proxy_app(
                upstream_url=(f"{plan.service.scheme}://{plan.service.host}:{plan.service.port}"),
                access_token=access_token,
                allowed_client_addresses=self._config.allowed_peer_addresses[
                    str(plan.request_node_id)
                ],
                expires_at=lease.expires_at,
                limits=self._config.limits,
            )
            process_id = self._runtime.start(
                app,
                host=plan.access_scope.bind_host,
                port=plan.access_scope.bind_port,
                owner_fingerprint=fingerprint,
                expires_at=lease.expires_at,
                graceful_shutdown_seconds=self._config.limits.graceful_shutdown_seconds,
            )
        except (ValueError, OSError, RuntimeError):
            return AdapterExecutionResult(
                error=OperationError(
                    code=OperationErrorCode.EXECUTION_FAILED,
                    message="无法创建受控临时 HTTP 入口",
                    correlation_id=str(plan.operation_id),
                )
            )
        resource = ResourceOwnership(
            resource_id=resource_id,
            operation_id=plan.operation_id,
            kind="embedded_http_proxy",
            bind_host=plan.access_scope.bind_host,
            bind_port=plan.access_scope.bind_port,
            owner_fingerprint=fingerprint,
            process_id=process_id,
            created_at=lease.starts_at,
        )
        return AdapterExecutionResult(resources=(resource,))

    async def cleanup(
        self,
        operation_id: OperationId,
        resources: tuple[ResourceOwnership, ...],
        *,
        at: datetime,
    ) -> CleanupRecord:
        """只停止与持久化指纹匹配的 TunnelMinion 自有代理。"""
        if not resources:
            return CleanupRecord(
                operation_id=operation_id,
                result=CleanupResult.SUCCEEDED,
                reason="没有需要清理的共享资源",
                completed_at=at,
            )
        if any(item.operation_id != operation_id for item in resources):
            return _ownership_mismatch(operation_id, at, "资源不属于当前操作")
        results = tuple(
            self._runtime.stop(
                host=item.bind_host,
                port=item.bind_port,
                owner_fingerprint=item.owner_fingerprint,
            )
            for item in resources
        )
        if StopResult.OWNERSHIP_MISMATCH in results:
            return _ownership_mismatch(operation_id, at, "资源指纹或端口占用者不匹配")
        if StopResult.FAILED in results:
            return CleanupRecord(
                operation_id=operation_id,
                result=CleanupResult.FAILED,
                reason="自有代理未能在排空期限内停止",
                manual_action="在目标节点检查对应 operation_id 的代理进程",
                completed_at=at,
            )
        return CleanupRecord(
            operation_id=operation_id,
            result=CleanupResult.SUCCEEDED,
            reason=(
                "normal_expiry：租约到期并完成连接排空"
                if all(item is StopResult.ALREADY_MISSING for item in results)
                else "forced_or_scheduled_cleanup：自有代理已停止并完成连接排空"
            ),
            completed_at=at,
        )


def _resource_fingerprint(plan: OperationPlan, resource_id: ResourceId) -> str:
    value = "|".join(
        (
            str(plan.operation_id),
            str(resource_id),
            plan.access_scope.bind_host,
            str(plan.access_scope.bind_port),
            plan.service.fingerprint,
        )
    )
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _ownership_mismatch(operation_id: OperationId, at: datetime, reason: str) -> CleanupRecord:
    return CleanupRecord(
        operation_id=operation_id,
        result=CleanupResult.OWNERSHIP_MISMATCH,
        reason=reason,
        manual_action="不要停止未知进程；请在目标节点核对端口与操作记录",
        completed_at=at,
    )
