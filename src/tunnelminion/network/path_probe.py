"""跨平台生产只读 PathProbe 的共享契约与有界执行器。"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    CandidateSource,
    EndpointCandidate,
    ProviderKind,
    canonical_sha256,
)
from tunnelminion.network.path_controller import (
    CandidateProbePolicy,
    DirectPathErrorCode,
    DirectPathEvidence,
)


class PathProbePolicy(CandidateProbePolicy):
    """生产探测的固定预算；测试可通过较小的候选上限验证边界。"""

    approved_ports: tuple[int, ...] = Field(default=(51820,), min_length=1, max_length=32)
    max_candidates: int = Field(default=4, ge=1, le=4)
    per_candidate_timeout_seconds: float = Field(default=1.0, gt=0, le=1.0)
    target_timeout_seconds: float = Field(default=2.0, gt=0, le=2.0)
    min_refresh_interval_seconds: float = Field(default=30.0, ge=30.0, le=30.0)


class ObservedEndpoint(BaseModel):
    """平台只读观察到的 endpoint；只在内存中参与候选匹配。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)

    @model_validator(mode="after")
    def validate_address(self) -> Self:
        ipaddress.ip_address(self.host)
        return self


class PathProbeFacts(BaseModel):
    """一次平台只读快照；endpoint 与 route 不得进入脱敏 evidence。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(min_length=1, max_length=128)
    observed_endpoints: tuple[ObservedEndpoint, ...] = Field(default=(), max_length=32)
    last_handshake_at: datetime | None = None
    handshake_probe_at: datetime
    host_routes: tuple[str, ...] = Field(default=(), max_length=64)
    host_route_probe_at: datetime
    observed_at: datetime
    error_code: DirectPathErrorCode | None = None

    @model_validator(mode="after")
    def validate_reading(self) -> Self:
        timestamps = (
            self.handshake_probe_at,
            self.host_route_probe_at,
            self.observed_at,
        )
        if any(value.tzinfo is None for value in timestamps):
            raise ValueError("PathProbe 观察时间必须包含时区")
        if self.last_handshake_at is not None and self.last_handshake_at.tzinfo is None:
            raise ValueError("handshake 时间必须包含时区")
        for route in self.host_routes:
            network = ipaddress.ip_network(route, strict=True)
            if network.prefixlen != network.max_prefixlen:
                raise ValueError("PathProbe 只允许精确 host route")
            if str(network) != route:
                raise ValueError("host route 必须使用规范形式")
        return self


class PathFactsReader(Protocol):
    """平台适配器的结构化只读事实入口。"""

    async def __call__(self) -> PathProbeFacts: ...  # pragma: no cover - Protocol


class TargetProbe(Protocol):
    """只建立固定目标的短连接，不发送或读取应用正文。"""

    async def __call__(self, host: str, port: int, timeout_seconds: float) -> bool: ...


async def tcp_target_probe(host: str, port: int, timeout_seconds: float) -> bool:
    """对结构化私有目标执行有界 TCP connect，并立即关闭连接。"""
    _validate_target(host, port)
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout_seconds):
            _, writer = await asyncio.open_connection(host, port)
        return True
    except (TimeoutError, OSError):
        return False
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()


class PlatformPathProbe:
    """把平台快照和固定目标探测合并成共享四维 evidence。"""

    def __init__(
        self,
        *,
        provider: ProviderKind,
        policy: PathProbePolicy,
        facts_reader: PathFactsReader,
        target_probe: TargetProbe = tcp_target_probe,
        facts_reader_for_route: Callable[[str], Awaitable[PathProbeFacts]] | None = None,
    ) -> None:
        self._provider = provider
        self._policy = policy
        self._facts_reader = facts_reader
        self._facts_reader_for_route = facts_reader_for_route
        self._target_probe = target_probe
        self._lock = asyncio.Lock()
        self._last_results: dict[str, DirectPathEvidence] = {}

    async def probe(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        plan_hash: str,
        authorization_revision: int,
        revision: int,
        candidates: tuple[EndpointCandidate, ...],
        expected_host_route: str,
        target_host: str,
        target_port: int,
        now: datetime,
        cancel_event: asyncio.Event | None = None,
    ) -> DirectPathEvidence:
        """执行一次单并发、可取消、最小刷新间隔受限的只读探测。"""
        current = self._aware(now)
        _validate_host_route(expected_host_route)
        self._validate_route_policy(expected_host_route)
        _validate_target(target_host, target_port)
        self._validate_target_policy(target_host, target_port)
        key = self._request_key(
            network_id=network_id,
            node_id=node_id,
            plan_hash=plan_hash,
            authorization_revision=authorization_revision,
            revision=revision,
            candidates=candidates,
            expected_host_route=expected_host_route,
            target_host=target_host,
            target_port=target_port,
        )
        async with self._lock:
            self._raise_if_cancelled(cancel_event)
            cached = self._last_results.get(key)
            if (
                cached is not None
                and (current - cached.observed_at).total_seconds()
                < self._policy.min_refresh_interval_seconds
            ):
                return cached

            ranked = self._rank_candidates(candidates, current)
            try:
                facts = await self._load_facts(
                    cancel_event,
                    timeout_seconds=self._policy.per_candidate_timeout_seconds
                    * max(1, len(ranked)),
                    expected_host_route=expected_host_route,
                )
            except PermissionError:
                facts = self._fallback_facts(current, DirectPathErrorCode.PERMISSION_DENIED)
            except TimeoutError:
                facts = self._fallback_facts(current, DirectPathErrorCode.TIMEOUT)
            except NotImplementedError:
                facts = self._fallback_facts(current, DirectPathErrorCode.UNSUPPORTED)
            except ConnectionError:
                facts = self._fallback_facts(
                    current,
                    DirectPathErrorCode.PROVIDER_UNAVAILABLE,
                )
            except OSError:
                facts = self._fallback_facts(current, DirectPathErrorCode.PATH_UNAVAILABLE)
            self._raise_if_cancelled(cancel_event)
            if facts.error_code is not None:
                evidence = self._failed_evidence(
                    network_id=network_id,
                    node_id=node_id,
                    plan_hash=plan_hash,
                    authorization_revision=authorization_revision,
                    revision=revision,
                    candidate_count=len(ranked),
                    current=current,
                    facts=facts,
                    error_code=facts.error_code,
                    target_host=target_host,
                    target_port=target_port,
                    expected_host_route=expected_host_route,
                )
                self._last_results[key] = evidence
                return evidence

            selected: EndpointCandidate | None = None
            endpoint_probe_at: datetime | None = None
            for candidate in ranked:
                self._raise_if_cancelled(cancel_event)
                endpoint_probe_at = current
                if any(
                    observed.host == candidate.host and observed.port == candidate.port
                    for observed in facts.observed_endpoints
                ):
                    selected = candidate
                    break

            handshake_fresh = self._handshake_fresh(facts.last_handshake_at, current)
            expected_route = str(ipaddress.ip_network(expected_host_route, strict=True))
            route_present = expected_route in facts.host_routes
            target_probe_at = current if selected is not None else None
            target_succeeded = False
            if selected is not None:
                self._raise_if_cancelled(cancel_event)
                target_succeeded = await self._run_target_probe(
                    target_host,
                    target_port,
                    cancel_event,
                )
                self._raise_if_cancelled(cancel_event)
            verified = (
                selected is not None and handshake_fresh and route_present and target_succeeded
            )
            evidence = DirectPathEvidence(
                network_id=network_id,
                node_id=node_id,
                plan_hash=plan_hash,
                authorization_revision=authorization_revision,
                provider=self._provider,
                revision=revision,
                target_host_hash=canonical_sha256({"host": target_host}),
                target_port=target_port,
                route_identity_hash=canonical_sha256({"host_route": expected_host_route}),
                candidate_count=len(ranked),
                selected_candidate_hash=(
                    canonical_sha256(selected.model_dump(mode="json"))
                    if selected is not None
                    else None
                ),
                selected_candidate_source=selected.source if selected is not None else None,
                endpoint_probe_at=endpoint_probe_at,
                endpoint_probe_succeeded=selected is not None,
                last_handshake_at=facts.last_handshake_at,
                handshake_probe_at=facts.handshake_probe_at,
                handshake_fresh=handshake_fresh,
                host_route_probe_at=facts.host_route_probe_at,
                host_route_present=route_present,
                target_probe_at=target_probe_at,
                target_probe_succeeded=target_succeeded,
                verified=verified,
                stable_error_code=self._error_code(
                    ranked=ranked,
                    selected=selected,
                    handshake_fresh=handshake_fresh,
                    route_present=route_present,
                    target_succeeded=target_succeeded,
                ),
                source=facts.source,
                observed_at=current,
                freshness_ttl_seconds=self._policy.max_handshake_age_seconds,
                expires_at=current + timedelta(seconds=self._policy.max_handshake_age_seconds),
            )
            self._last_results[key] = evidence
            return evidence

    async def endpoint(
        self,
        candidate: EndpointCandidate,
        timeout_seconds: float,
    ) -> bool:
        """兼容基础 PathProbe 契约的只读 endpoint 匹配。"""
        facts = await asyncio.wait_for(self._facts_reader(), timeout=timeout_seconds)
        return facts.error_code is None and any(
            item.host == candidate.host and item.port == candidate.port
            for item in facts.observed_endpoints
        )

    async def target(self, host: str, port: int, timeout_seconds: float) -> bool:
        """兼容基础 PathProbe 契约的固定目标探测。"""
        _validate_target(host, port)
        self._validate_target_policy(host, port)
        return await asyncio.wait_for(
            self._target_probe(host, port, timeout_seconds), timeout=timeout_seconds
        )

    async def _load_facts(
        self,
        cancel_event: asyncio.Event | None,
        *,
        timeout_seconds: float,
        expected_host_route: str,
    ) -> PathProbeFacts:
        reader: Awaitable[PathProbeFacts]
        if self._facts_reader_for_route is not None:
            reader = self._facts_reader_for_route(expected_host_route)
        else:
            reader = self._facts_reader()
        return cast(
            PathProbeFacts,
            await self._await_cancellable(
                reader,
                cancel_event,
                timeout_seconds=timeout_seconds,
            ),
        )

    async def _run_target_probe(
        self,
        host: str,
        port: int,
        cancel_event: asyncio.Event | None,
    ) -> bool:
        try:
            return cast(
                bool,
                await self._await_cancellable(
                    self._target_probe(host, port, self._policy.target_timeout_seconds),
                    cancel_event,
                    timeout_seconds=self._policy.target_timeout_seconds,
                ),
            )
        except (TimeoutError, OSError):
            return False

    async def _await_cancellable(
        self,
        awaitable: Awaitable[PathProbeFacts] | Awaitable[bool],
        cancel_event: asyncio.Event | None,
        *,
        timeout_seconds: float,
    ) -> PathProbeFacts | bool:
        task: asyncio.Future[PathProbeFacts | bool] = asyncio.ensure_future(awaitable)
        if cancel_event is None:
            return await asyncio.wait_for(task, timeout=timeout_seconds)
        cancel_task = asyncio.create_task(cancel_event.wait())
        timeout_task = asyncio.create_task(asyncio.sleep(timeout_seconds))
        try:
            done, _ = await asyncio.wait(
                (task, cancel_task, timeout_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_task in done:
                raise asyncio.CancelledError
            if timeout_task in done:
                raise TimeoutError
            return task.result()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            cancel_task.cancel()
            timeout_task.cancel()
            await asyncio.gather(cancel_task, timeout_task, return_exceptions=True)

    def _rank_candidates(
        self,
        candidates: tuple[EndpointCandidate, ...],
        now: datetime,
    ) -> tuple[EndpointCandidate, ...]:
        approved_networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in self._policy.approved_networks
        )
        priority = {
            CandidateSource.ADMIN_EXPLICIT: 0,
            CandidateSource.STUN_SAME_SOCKET: 1,
            CandidateSource.NODE_OBSERVED: 2,
        }
        accepted = (
            item
            for item in candidates
            if item.source in self._policy.allowed_sources
            and item.expires_at.astimezone(UTC) > now
            and (not self._policy.approved_ports or item.port in self._policy.approved_ports)
            and any(ipaddress.ip_address(item.host) in network for network in approved_networks)
        )
        ranked = sorted(
            accepted,
            key=lambda item: (
                priority[item.source],
                -item.observed_at.timestamp(),
                item.host,
                item.port,
            ),
        )
        return tuple(ranked[: self._policy.max_candidates])

    def _failed_evidence(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        plan_hash: str,
        authorization_revision: int,
        revision: int,
        candidate_count: int,
        current: datetime,
        facts: PathProbeFacts,
        error_code: DirectPathErrorCode,
        target_host: str,
        target_port: int,
        expected_host_route: str,
    ) -> DirectPathEvidence:
        return DirectPathEvidence(
            network_id=network_id,
            node_id=node_id,
            plan_hash=plan_hash,
            authorization_revision=authorization_revision,
            provider=self._provider,
            revision=revision,
            target_host_hash=canonical_sha256({"host": target_host}),
            target_port=target_port,
            route_identity_hash=canonical_sha256({"host_route": expected_host_route}),
            candidate_count=candidate_count,
            last_handshake_at=facts.last_handshake_at,
            handshake_probe_at=facts.handshake_probe_at,
            host_route_probe_at=facts.host_route_probe_at,
            verified=False,
            stable_error_code=error_code,
            source=facts.source,
            observed_at=current,
            freshness_ttl_seconds=self._policy.max_handshake_age_seconds,
            expires_at=current + timedelta(seconds=self._policy.max_handshake_age_seconds),
        )

    def _validate_target_policy(self, host: str, port: int) -> None:
        address = ipaddress.ip_address(host)
        approved_networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in self._policy.approved_networks
        )
        if port not in self._policy.approved_ports or not any(
            address in network for network in approved_networks
        ):
            raise ValueError("PathProbe target 不在批准的 network/port 范围")

    def _validate_route_policy(self, route: str) -> None:
        network = ipaddress.ip_network(route, strict=True)
        approved_networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in self._policy.approved_networks
        )
        if not any(
            network.version == approved.version
            and int(network.network_address) >= int(approved.network_address)
            and int(network.broadcast_address) <= int(approved.broadcast_address)
            for approved in approved_networks
        ):
            raise ValueError("PathProbe host route 不在批准的 network 范围")

    @staticmethod
    def _fallback_facts(
        observed_at: datetime,
        error_code: DirectPathErrorCode,
    ) -> PathProbeFacts:
        return PathProbeFacts(
            source="platform:readonly",
            handshake_probe_at=observed_at,
            host_route_probe_at=observed_at,
            observed_at=observed_at,
            error_code=error_code,
        )

    @staticmethod
    def _error_code(
        *,
        ranked: tuple[EndpointCandidate, ...],
        selected: EndpointCandidate | None,
        handshake_fresh: bool,
        route_present: bool,
        target_succeeded: bool,
    ) -> DirectPathErrorCode | None:
        if not ranked:
            return DirectPathErrorCode.NO_APPROVED_CANDIDATE
        if selected is None:
            return DirectPathErrorCode.ENDPOINT_UNREACHABLE
        if not handshake_fresh:
            return DirectPathErrorCode.HANDSHAKE_STALE
        if not route_present:
            return DirectPathErrorCode.HOST_ROUTE_MISSING
        if not target_succeeded:
            return DirectPathErrorCode.TARGET_UNREACHABLE
        return None

    def _handshake_fresh(self, value: datetime | None, now: datetime) -> bool:
        if value is None or value.tzinfo is None:
            return False
        age = now - value.astimezone(UTC)
        return timedelta(0) <= age <= timedelta(seconds=self._policy.max_handshake_age_seconds)

    @staticmethod
    def _request_key(
        *,
        network_id: NetworkId,
        node_id: NodeId,
        plan_hash: str,
        authorization_revision: int,
        revision: int,
        candidates: tuple[EndpointCandidate, ...],
        expected_host_route: str,
        target_host: str,
        target_port: int,
    ) -> str:
        return canonical_sha256(
            {
                "network_id": str(network_id),
                "node_id": str(node_id),
                "plan_hash": plan_hash,
                "authorization_revision": authorization_revision,
                "revision": revision,
                "candidates": [item.model_dump(mode="json") for item in candidates],
                "expected_host_route": expected_host_route,
                "target_host": target_host,
                "target_port": target_port,
            }
        )

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("路径探测时钟必须包含时区")
        return value.astimezone(UTC)

    @staticmethod
    def _raise_if_cancelled(cancel_event: asyncio.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError


def _validate_host_route(value: str) -> None:
    network = ipaddress.ip_network(value, strict=True)
    address = network.network_address
    if network.prefixlen != network.max_prefixlen or any(
        (
            address.is_multicast,
            address.is_unspecified,
            address.is_loopback,
            address.is_reserved,
            address.is_link_local,
        )
    ):
        raise ValueError("PathProbe 目标必须是精确 host route")


def _validate_target(host: str, port: int) -> None:
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("PathProbe 目标不能是通配或组播地址")
    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError("PathProbe 目标必须属于私有、环回或链路本地地址")
    if not 1 <= port <= 65535:
        raise ValueError("PathProbe 目标端口无效")
