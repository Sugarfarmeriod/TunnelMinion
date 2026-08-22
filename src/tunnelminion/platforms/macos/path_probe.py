"""macOS 官方只读事实上的 managed PathProbe。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, cast

from tunnelminion.network.contracts import ProviderKind
from tunnelminion.network.path_controller import DirectPathErrorCode
from tunnelminion.network.path_probe import (
    ObservedEndpoint,
    PathProbeFacts,
    PathProbePolicy,
    PlatformPathProbe,
    TargetProbe,
    tcp_target_probe,
)
from tunnelminion.platforms.macos.managed_system import (
    MacOSProviderPreflight,
    MacOSTunnelSnapshot,
    MacOSWireGuardObserver,
)


class _PathObserver(Protocol):
    async def observe_path(
        self,
        interface_name: str,
        *,
        peer_public_key: str,
        expected_host_route: str,
    ) -> MacOSTunnelSnapshot: ...


class MacOSPathProbe(PlatformPathProbe):
    """读取官方 `wg show`、`ifconfig`、`netstat` 和固定目标连接状态。"""

    def __init__(
        self,
        observer: MacOSWireGuardObserver,
        *,
        interface_name: str,
        peer_public_key: str,
        policy: PathProbePolicy,
        target_probe: TargetProbe = tcp_target_probe,
        preflight: MacOSProviderPreflight | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._observer = observer
        self._interface_name = interface_name
        self._peer_public_key = peer_public_key
        self._preflight_error = self._preflight_error_code(preflight)
        self._clock = clock or (lambda: datetime.now(UTC))
        super().__init__(
            provider=ProviderKind.MACOS,
            policy=policy,
            facts_reader=self._read_facts,
            target_probe=target_probe,
            facts_reader_for_route=self._read_facts_for_route,
        )

    async def _read_facts_for_route(self, expected_host_route: str) -> PathProbeFacts:
        return await self._read_facts(expected_host_route)

    async def _read_facts(self, expected_host_route: str | None = None) -> PathProbeFacts:
        observed_at = self._clock().astimezone(UTC)
        if self._preflight_error is not None:
            return self._facts_error(observed_at, self._preflight_error)
        try:
            if expected_host_route is not None and hasattr(self._observer, "observe_path"):
                snapshot = await cast(_PathObserver, self._observer).observe_path(
                    self._interface_name,
                    peer_public_key=self._peer_public_key,
                    expected_host_route=expected_host_route,
                )
            else:
                snapshot = await self._observer.observe(self._interface_name)
        except PermissionError:
            return self._facts_error(observed_at, DirectPathErrorCode.PERMISSION_DENIED)
        except (FileNotFoundError, OSError):
            return self._facts_error(observed_at, DirectPathErrorCode.UNSUPPORTED)

        error = self._snapshot_error(snapshot.observed_error_code)
        peer = next(
            (item for item in snapshot.peers if item.public_key == self._peer_public_key),
            None,
        )
        handshake_at = (
            datetime.fromtimestamp(peer.latest_handshake_epoch, UTC)
            if peer is not None and peer.latest_handshake_epoch is not None
            else None
        )
        endpoints = ()
        if peer is not None and peer.endpoint_host is not None and peer.endpoint_port is not None:
            endpoints = (ObservedEndpoint(host=peer.endpoint_host, port=peer.endpoint_port),)
        return PathProbeFacts(
            source="macos:wg-show-netstat",
            observed_endpoints=endpoints,
            last_handshake_at=handshake_at,
            handshake_probe_at=observed_at,
            host_routes=snapshot.host_routes,
            host_route_probe_at=observed_at,
            observed_at=observed_at,
            error_code=error,
        )

    @staticmethod
    def _preflight_error_code(
        preflight: MacOSProviderPreflight | None,
    ) -> DirectPathErrorCode | None:
        if preflight is None or preflight.error_code is None:
            return None
        if preflight.error_code == "permission_denied":
            return DirectPathErrorCode.PERMISSION_DENIED
        return DirectPathErrorCode.UNSUPPORTED

    @staticmethod
    def _snapshot_error(error_code: str | None) -> DirectPathErrorCode | None:
        if error_code is None:
            return None
        if "permission" in error_code:
            return DirectPathErrorCode.PERMISSION_DENIED
        return DirectPathErrorCode.UNSUPPORTED

    @staticmethod
    def _facts_error(
        observed_at: datetime,
        error_code: DirectPathErrorCode,
    ) -> PathProbeFacts:
        return PathProbeFacts(
            source="macos:wg-show-netstat",
            handshake_probe_at=observed_at,
            host_route_probe_at=observed_at,
            observed_at=observed_at,
            error_code=error_code,
        )


__all__ = ["MacOSPathProbe"]
