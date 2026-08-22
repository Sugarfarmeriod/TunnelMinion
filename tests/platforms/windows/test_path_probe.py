"""Windows 只读 PathProbe 的平台降级与来源测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any, TypedDict, TypeVar, cast

import pytest

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    CandidateSource,
    EndpointCandidate,
    ProviderKind,
    ProviderMode,
)
from tunnelminion.network.path_controller import DirectPathErrorCode
from tunnelminion.network.path_probe import PathProbePolicy
from tunnelminion.platforms.windows.managed_system import (
    WindowsPeerSnapshot,
    WindowsProviderPreflight,
    WindowsTunnelSnapshot,
    WindowsWireGuardObserver,
)
from tunnelminion.platforms.windows.path_probe import WindowsPathProbe

T = TypeVar("T")


class ProbeArgs(TypedDict):
    network_id: NetworkId
    node_id: NodeId
    plan_hash: str
    authorization_revision: int
    revision: int
    candidates: tuple[EndpointCandidate, ...]
    expected_host_route: str
    target_host: str
    target_port: int
    now: datetime


NOW = datetime(2026, 7, 26, 9, 0, tzinfo=UTC)
PEER = "peer-public-key"


def run(awaitable: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(awaitable)


def policy() -> PathProbePolicy:
    return PathProbePolicy(
        approved_networks=("10.0.0.0/24", "fd00::/64"),
        approved_ports=(51820, 8787),
    )


def snapshot(
    *,
    error: str | None = None,
    peer: WindowsPeerSnapshot | None = None,
) -> WindowsTunnelSnapshot:
    return WindowsTunnelSnapshot(
        interface_name="tmn-test-a",
        interface_present=True,
        interface_up=True,
        service_present=True,
        service_running=True,
        peers=(
            peer
            or WindowsPeerSnapshot(
                public_key=PEER,
                endpoint_host="fd00::10",
                endpoint_port=51820,
                allowed_host_routes=("fd00::2/128",),
                latest_handshake_epoch=int(NOW.timestamp()),
            ),
        ),
        host_routes=("fd00::2/128",),
        observed_error_code=error,
    )


class Observer:
    def __init__(self, value: WindowsTunnelSnapshot | BaseException) -> None:
        self.value = value
        self.calls = 0

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        assert interface_name == "tmn-test-a"
        self.calls += 1
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class PathObserver(Observer):
    async def observe_path(
        self,
        interface_name: str,
        *,
        peer_public_key: str,
        expected_host_route: str,
    ) -> WindowsTunnelSnapshot:
        assert interface_name == "tmn-test-a"
        assert peer_public_key == PEER
        assert expected_host_route == "fd00::2/128"
        return await self.observe(interface_name)


def make_probe(
    observer: Observer,
    *,
    preflight: WindowsProviderPreflight | None = None,
    target: bool | None = None,
) -> WindowsPathProbe:
    async def target_probe(host: str, port: int, timeout_seconds: float) -> bool:
        assert (host, port, timeout_seconds) == ("fd00::2", 8787, 2.0)
        return True if target is None else bool(target)

    return WindowsPathProbe(
        cast(WindowsWireGuardObserver, observer),
        interface_name="tmn-test-a",
        peer_public_key=PEER,
        policy=policy(),
        target_probe=target_probe,
        preflight=preflight,
        clock=lambda: datetime(2026, 7, 26, 9, 0, tzinfo=NOW.tzinfo),
    )


def args() -> ProbeArgs:
    return {
        "network_id": NetworkId.new(),
        "node_id": NodeId.new(),
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_revision": 1,
        "revision": 1,
        "candidates": (
            EndpointCandidate(
                host="fd00::10",
                port=51820,
                source=CandidateSource.ADMIN_EXPLICIT,
                observed_at=datetime(2026, 7, 26, 8, 59, tzinfo=NOW.tzinfo),
                expires_at=datetime(2026, 7, 26, 9, 5, tzinfo=NOW.tzinfo),
            ),
        ),
        "expected_host_route": "fd00::2/128",
        "target_host": "fd00::2",
        "target_port": 8787,
        "now": datetime(2026, 7, 26, 9, 0, tzinfo=NOW.tzinfo),
    }


def test_windows_probe_returns_ipv6_evidence_and_platform_source() -> None:
    observer = Observer(snapshot())
    result = run(make_probe(observer).probe(**args()))
    assert result.provider is ProviderKind.WINDOWS
    assert result.verified
    assert result.source == "windows:wg-show-route"
    assert result.selected_candidate_source is not None
    assert result.selected_candidate_source.value == "admin_explicit"
    assert result.handshake_probe_at is not None
    assert result.host_route_probe_at is not None
    assert observer.calls == 1


def test_windows_probe_passes_exact_route_context_to_platform_observer() -> None:
    observer = PathObserver(snapshot())
    result = run(make_probe(cast(Observer, observer)).probe(**args()))
    assert result.verified
    assert observer.calls == 1


@pytest.mark.parametrize(
    ("error_code", "expected"),
    [
        ("permission_denied", DirectPathErrorCode.PERMISSION_DENIED),
        ("platform_unsupported", DirectPathErrorCode.UNSUPPORTED),
        ("dependency_unavailable", DirectPathErrorCode.UNSUPPORTED),
    ],
)
def test_windows_probe_maps_preflight_without_observing(
    error_code: str,
    expected: DirectPathErrorCode,
) -> None:
    preflight = WindowsProviderPreflight(
        mode=ProviderMode.OBSERVE_ONLY,
        platform_supported=error_code != "platform_unsupported",
        wireguard_manager_available=False,
        wg_available=False,
        service_control_available=False,
        route_tool_available=False,
        administrator=False,
        error_code=error_code,
    )
    observer = Observer(snapshot())
    result = run(make_probe(observer, preflight=preflight).probe(**args()))
    assert result.stable_error_code is expected
    assert observer.calls == 0


@pytest.mark.parametrize(
    "error",
    ["permission_denied", "service_query_failed", "wireguard_query_failed", "other"],
)
def test_windows_probe_maps_snapshot_and_reader_failures(error: str) -> None:
    observer = Observer(snapshot(error=error))
    result = run(make_probe(observer).probe(**args()))
    expected = (
        DirectPathErrorCode.PERMISSION_DENIED
        if error in {"permission_denied", "service_query_failed"}
        else DirectPathErrorCode.UNSUPPORTED
    )
    assert result.stable_error_code is expected

    for failure in (PermissionError("denied"), FileNotFoundError("missing"), OSError("failed")):
        result = run(make_probe(Observer(failure)).probe(**args()))
        expected = (
            DirectPathErrorCode.PERMISSION_DENIED
            if isinstance(failure, PermissionError)
            else DirectPathErrorCode.UNSUPPORTED
        )
        assert result.stable_error_code is expected


def test_windows_probe_handles_missing_peer_handshake_and_endpoint() -> None:
    peer = WindowsPeerSnapshot(
        public_key="other-peer",
        latest_handshake_epoch=None,
        allowed_host_routes=(),
    )
    result = run(make_probe(Observer(snapshot(peer=peer))).probe(**args()))
    assert result.stable_error_code is DirectPathErrorCode.ENDPOINT_UNREACHABLE
    assert result.last_handshake_at is None
