"""macOS 只读 PathProbe 的平台降级与来源测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any, TypedDict, TypeVar, cast

import pytest

from tunnelminion.network.contracts import (
    CandidateSource,
    EndpointCandidate,
    ProviderKind,
    ProviderMode,
)
from tunnelminion.network.path_controller import DirectPathErrorCode
from tunnelminion.network.path_probe import PathProbePolicy
from tunnelminion.platforms.macos.managed_system import (
    MacOSPeerSnapshot,
    MacOSProviderPreflight,
    MacOSTunnelSnapshot,
    MacOSWireGuardObserver,
)
from tunnelminion.platforms.macos.path_probe import MacOSPathProbe

T = TypeVar("T")


class ProbeArgs(TypedDict):
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
        approved_ports=(51820,),
    )


def snapshot(
    *,
    error: str | None = None,
    peer: MacOSPeerSnapshot | None = None,
) -> MacOSTunnelSnapshot:
    return MacOSTunnelSnapshot(
        interface_name="utun9",
        interface_present=True,
        interface_up=True,
        service_present=True,
        service_running=True,
        peers=(
            peer
            or MacOSPeerSnapshot(
                public_key=PEER,
                endpoint_host="10.0.0.10",
                endpoint_port=51820,
                allowed_host_routes=("10.0.0.2/32",),
                latest_handshake_epoch=int(NOW.timestamp()),
            ),
        ),
        host_routes=("10.0.0.2/32",),
        observed_error_code=error,
    )


class Observer:
    def __init__(self, value: MacOSTunnelSnapshot | BaseException) -> None:
        self.value = value
        self.calls = 0

    async def observe(self, interface_name: str) -> MacOSTunnelSnapshot:
        assert interface_name == "utun9"
        self.calls += 1
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


def make_probe(
    observer: Observer,
    *,
    preflight: MacOSProviderPreflight | None = None,
) -> MacOSPathProbe:
    async def target_probe(host: str, port: int, timeout_seconds: float) -> bool:
        assert (host, port, timeout_seconds) == ("10.0.0.2", 8787, 2.0)
        return True

    return MacOSPathProbe(
        cast(MacOSWireGuardObserver, observer),
        interface_name="utun9",
        peer_public_key=PEER,
        policy=policy(),
        target_probe=target_probe,
        preflight=preflight,
        clock=lambda: NOW,
    )


def args() -> ProbeArgs:
    return {
        "revision": 1,
        "candidates": (
            EndpointCandidate(
                host="10.0.0.10",
                port=51820,
                source=CandidateSource.ADMIN_EXPLICIT,
                observed_at=NOW,
                expires_at=datetime(2026, 7, 26, 9, 5, tzinfo=UTC),
            ),
        ),
        "expected_host_route": "10.0.0.2/32",
        "target_host": "10.0.0.2",
        "target_port": 8787,
        "now": NOW,
    }


def test_macos_probe_returns_evidence_from_official_readonly_source() -> None:
    observer = Observer(snapshot())
    result = run(make_probe(observer).probe(**args()))
    assert result.provider is ProviderKind.MACOS
    assert result.verified
    assert result.source == "macos:wg-show-netstat"
    assert result.selected_candidate_source is not None
    assert result.selected_candidate_source.value == "admin_explicit"
    assert result.endpoint_probe_at is not None
    assert result.handshake_probe_at is not None
    assert result.host_route_probe_at is not None
    assert result.target_probe_at is not None


@pytest.mark.parametrize(
    ("error_code", "expected"),
    [
        ("permission_denied", DirectPathErrorCode.PERMISSION_DENIED),
        ("platform_unsupported", DirectPathErrorCode.UNSUPPORTED),
        ("dependency_unavailable", DirectPathErrorCode.UNSUPPORTED),
    ],
)
def test_macos_probe_maps_preflight_without_privilege(
    error_code: str,
    expected: DirectPathErrorCode,
) -> None:
    preflight = MacOSProviderPreflight(
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
    ["permission_denied", "wireguard_query_failed", "unsupported"],
)
def test_macos_probe_maps_snapshot_and_reader_failures(error: str) -> None:
    result = run(make_probe(Observer(snapshot(error=error))).probe(**args()))
    expected = (
        DirectPathErrorCode.PERMISSION_DENIED
        if error == "permission_denied"
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


def test_macos_probe_handles_missing_peer_state() -> None:
    peer = MacOSPeerSnapshot(public_key="other-peer")
    result = run(make_probe(Observer(snapshot(peer=peer))).probe(**args()))
    assert result.stable_error_code is DirectPathErrorCode.ENDPOINT_UNREACHABLE
    assert result.last_handshake_at is None
