"""Windows 官方 WireGuard 工具的固定参数、预检与只读观察边界。"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Callable, Collection
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tunnelminion.network.contracts import ProviderMode, canonical_sha256
from tunnelminion.platforms.windows.system import CommandResult, CommandRunner, SystemReader

_MANAGED_INTERFACE = re.compile(r"^tmn-[a-z0-9-]{1,48}$")
_MANAGED_RUNTIME_INTERFACE = re.compile(r"^tmn-[a-z0-9-]{1,48}\.r[1-9][0-9]*$")
_ANY_INTERFACE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
_SERVICE_PREFIX = "WireGuardTunnel$"
_MAX_PEERS = 32
_MAX_ROUTES = 256
_MAX_SAFE_ALLOWED_NETWORK_ADDRESSES = 1 << 24
MAX_SAFE_ALLOWED_NETWORKS = 32
_ACTIVE_ROUTE_LABELS = frozenset({"active routes:", "活动路由:"})
_PERSISTENT_ROUTE_LABELS = frozenset({"persistent routes:", "永久路由:"})
_IPV4_ROUTE_HEADERS = frozenset(
    {
        ("network", "destination", "netmask", "gateway", "interface", "metric"),
        ("网络目标", "网络掩码", "网关", "接口", "跃点数"),
    }
)
_IPV6_ROUTE_HEADERS = frozenset(
    {
        ("if", "metric", "network", "destination", "gateway"),
        ("接口", "跃点数", "网络目标", "网关"),
    }
)
_ON_LINK_GATEWAYS = frozenset({"on-link", "在链路上"})


class WindowsProviderPreflight(BaseModel):
    """managed 能力的依赖和权限检查；observe-only 可在失败时继续。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: ProviderMode
    platform_supported: bool
    wireguard_manager_available: bool
    wg_available: bool
    service_control_available: bool
    route_tool_available: bool
    administrator: bool
    error_code: str | None = Field(default=None, min_length=1, max_length=128)


class WindowsPeerSnapshot(BaseModel):
    """本机观察到的公开 peer 状态，不含任何私钥。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    public_key: str = Field(min_length=1, max_length=128)
    endpoint_host: str | None = Field(default=None, min_length=1, max_length=255)
    endpoint_port: int | None = Field(default=None, ge=1, le=65535)
    allowed_host_routes: tuple[str, ...] = Field(default=(), max_length=8)
    allowed_networks: tuple[str, ...] = Field(default=(), max_length=MAX_SAFE_ALLOWED_NETWORKS)
    allowed_networks_complete: bool = True
    latest_handshake_epoch: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_routes(self) -> Self:
        if (self.endpoint_host is None) != (self.endpoint_port is None):
            raise ValueError("peer endpoint 必须同时包含地址和端口")
        if self.endpoint_host is not None:
            ipaddress.ip_address(self.endpoint_host)
        for route in self.allowed_host_routes:
            network = ipaddress.ip_network(route, strict=True)
            if (
                network.prefixlen != network.max_prefixlen
                or parse_safe_allowed_network(route) != route
            ):
                raise ValueError("Windows Provider 只接受 host route")
        for route in self.allowed_networks:
            if parse_safe_allowed_network(route) != route:
                raise ValueError("Windows Provider 只接受安全的 IP network")
        if len(set(self.allowed_host_routes)) != len(self.allowed_host_routes):
            raise ValueError("peer host route 不得重复")
        if len(set(self.allowed_networks)) != len(self.allowed_networks):
            raise ValueError("peer IP network 不得重复")
        return self


class WindowsTunnelSnapshot(BaseModel):
    """官方工具、服务和系统接口联合得到的有限状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    interface_name: str = Field(min_length=1, max_length=64)
    interface_present: bool
    interface_up: bool
    addresses: tuple[str, ...] = Field(default=(), max_length=16)
    service_present: bool
    service_running: bool
    peers: tuple[WindowsPeerSnapshot, ...] = Field(default=(), max_length=_MAX_PEERS)
    host_routes: tuple[str, ...] = Field(default=(), max_length=_MAX_ROUTES)
    public_key_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    stable_interface_id: str | None = Field(default=None, min_length=1, max_length=256)
    creation_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    observed_error_code: str | None = Field(default=None, min_length=1, max_length=128)

    @property
    def system_fingerprint(self) -> str:
        return canonical_sha256(
            {
                "interface_name": self.interface_name,
                "interface_present": self.interface_present,
                "addresses": self.addresses,
                "peers": [
                    {
                        "public_key": peer.public_key,
                        "endpoint_host": peer.endpoint_host,
                        "endpoint_port": peer.endpoint_port,
                        "allowed_host_routes": peer.allowed_host_routes,
                    }
                    for peer in self.peers
                ],
                "host_routes": self.host_routes,
                "public_key_hash": self.public_key_hash,
                "stable_interface_id": self.stable_interface_id,
                "creation_nonce": self.creation_nonce,
            }
        )

    @property
    def path_ownership_fingerprint(self) -> str:
        """为验收前后不变性单独记录已脱敏的 path ownership 事实。"""
        return canonical_sha256(
            {
                "interface_name": self.interface_name,
                "peers": [
                    {
                        "public_key": peer.public_key,
                        "allowed_host_routes": peer.allowed_host_routes,
                        "allowed_networks": peer.allowed_networks,
                        "allowed_networks_complete": peer.allowed_networks_complete,
                    }
                    for peer in self.peers
                ],
            }
        )


class WindowsProviderPaths(BaseModel):
    """只允许管理员预先配置的绝对官方工具和受管配置根目录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wireguard_exe: Path
    wg_exe: Path
    sc_exe: Path
    route_exe: Path
    config_root: Path

    @model_validator(mode="after")
    def validate_absolute_paths(self) -> Self:
        values = (
            self.wireguard_exe,
            self.wg_exe,
            self.sc_exe,
            self.route_exe,
            self.config_root,
        )
        if not all(path.is_absolute() for path in values):
            raise ValueError("Windows Provider 路径必须全部为绝对路径")
        return self


class FixedWindowsWireGuardCommands:
    """构造固定 argv；不接受 Shell 字符串、命令正文或交互式提权。"""

    def __init__(
        self,
        paths: WindowsProviderPaths,
        runner: CommandRunner,
        *,
        path_exists: Callable[[Path], bool] | None = None,
        is_administrator: Callable[[], bool] | None = None,
        platform_name: str | None = None,
    ) -> None:
        self.paths = paths
        self._runner = runner
        self._path_exists = path_exists or Path.exists
        self._is_administrator = is_administrator or windows_is_administrator
        self._platform_name = platform_name or os.name

    def preflight(self) -> WindowsProviderPreflight:
        platform_supported = self._platform_name == "nt"
        manager = self._path_exists(self.paths.wireguard_exe)
        wg = self._path_exists(self.paths.wg_exe)
        sc = self._path_exists(self.paths.sc_exe)
        route = self._path_exists(self.paths.route_exe)
        administrator = platform_supported and self._is_administrator()
        managed = platform_supported and manager and wg and sc and route and administrator
        if managed:
            error = None
        elif not platform_supported:
            error = "platform_unsupported"
        elif not (manager and wg and sc and route):
            error = "dependency_unavailable"
        else:
            error = "permission_denied"
        return WindowsProviderPreflight(
            mode=ProviderMode.MANAGED if managed else ProviderMode.OBSERVE_ONLY,
            platform_supported=platform_supported,
            wireguard_manager_available=manager,
            wg_available=wg,
            service_control_available=sc,
            route_tool_available=route,
            administrator=administrator,
            error_code=error,
        )

    async def show(self, interface_name: str, field: str) -> CommandResult:
        self._validate_interface(interface_name, managed_only=False)
        if field not in {
            "public-key",
            "peers",
            "endpoints",
            "allowed-ips",
            "latest-handshakes",
        }:
            raise ValueError("不允许的 WireGuard 观察字段")
        return await self._runner.run(
            (str(self.paths.wg_exe), "show", interface_name, field),
            5,
        )

    async def query_service(self, interface_name: str) -> CommandResult:
        self._validate_interface(interface_name, managed_only=False)
        return await self._runner.run(
            (str(self.paths.sc_exe), "query", self._service_name(interface_name)),
            5,
        )

    async def query_route(self, host_route: str) -> CommandResult:
        network = ipaddress.ip_network(host_route, strict=True)
        if network.prefixlen != network.max_prefixlen:
            raise ValueError("只允许查询 host route")
        family = "-6" if network.version == 6 else None
        arguments = (
            (str(self.paths.route_exe), "print", family, str(network.network_address))
            if family is not None
            else (str(self.paths.route_exe), "print", str(network.network_address))
        )
        return await self._runner.run(
            arguments,
            5,
        )

    async def route_table(self) -> CommandResult:
        """读取 IPv4 路由表；调用方必须只持久化冲突摘要。"""
        return await self._runner.run((str(self.paths.route_exe), "print", "-4"), 10)

    async def install_tunnel(self, interface_name: str, config_path: Path) -> CommandResult:
        self._validate_interface(interface_name, managed_only=True)
        resolved = self._validate_config_path(config_path)
        return await self._runner.run(
            (str(self.paths.wireguard_exe), "/installtunnelservice", str(resolved)),
            30,
        )

    async def uninstall_tunnel(self, interface_name: str) -> CommandResult:
        self._validate_interface(interface_name, managed_only=True)
        return await self._runner.run(
            (str(self.paths.wireguard_exe), "/uninstalltunnelservice", interface_name),
            30,
        )

    async def stop_tunnel(self, interface_name: str) -> CommandResult:
        self._validate_interface(interface_name, managed_only=True)
        return await self._runner.run(
            (str(self.paths.sc_exe), "stop", self._service_name(interface_name)),
            15,
        )

    def config_path(self, interface_name: str, revision: int) -> Path:
        self._validate_interface(interface_name, managed_only=True)
        if revision < 1:
            raise ValueError("配置 revision 必须为正数")
        return self.paths.config_root / f"{interface_name}.r{revision}.conf"

    def _validate_config_path(self, config_path: Path) -> Path:
        root = self.paths.config_root.resolve()
        resolved = config_path.resolve()
        if resolved.parent != root or resolved.suffix != ".conf":
            raise ValueError("配置路径必须位于固定受管目录")
        return resolved

    @staticmethod
    def _validate_interface(interface_name: str, *, managed_only: bool) -> None:
        valid = (
            _MANAGED_INTERFACE.fullmatch(interface_name) is not None
            or _MANAGED_RUNTIME_INTERFACE.fullmatch(interface_name) is not None
            if managed_only
            else _ANY_INTERFACE.fullmatch(interface_name) is not None
        )
        if not valid:
            raise ValueError("接口名称不符合固定格式")

    @staticmethod
    def _service_name(interface_name: str) -> str:
        return f"{_SERVICE_PREFIX}{interface_name}"


class WindowsWireGuardObserver:
    """只读联合官方 wg、SCM、route 和系统接口，不读取配置文件。"""

    def __init__(
        self,
        reader: SystemReader,
        commands: FixedWindowsWireGuardCommands,
        interface_index: Callable[[str], int | None] | None = None,
    ) -> None:
        self._reader = reader
        self._commands = commands
        self._interface_index = interface_index or system_interface_index

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        return await self._observe(interface_name)

    async def observe_candidates(self, interface_name: str) -> WindowsTunnelSnapshot:
        """只读取候选所需 WireGuard 事实，不读取任何路由。"""
        return await self._observe(interface_name, include_routes=False)

    async def observe_path(
        self,
        interface_name: str,
        *,
        peer_public_key: str,
        expected_host_route: str,
    ) -> WindowsTunnelSnapshot:
        """为 path probe 读取精确 target route；AllowedIPs 仅用于 ownership。"""
        return await self._observe(
            interface_name,
            peer_public_key=peer_public_key,
            expected_host_route=expected_host_route,
        )

    async def _observe(
        self,
        interface_name: str,
        *,
        peer_public_key: str | None = None,
        expected_host_route: str | None = None,
        include_routes: bool = True,
    ) -> WindowsTunnelSnapshot:
        interface = self._reader.interface(interface_name)
        service = await self._commands.query_service(interface_name)
        service_present = service.returncode == 0
        service_running = service_present and "RUNNING" in service.stdout.upper()
        if interface is None:
            return WindowsTunnelSnapshot(
                interface_name=interface_name,
                interface_present=False,
                interface_up=False,
                service_present=service_present,
                service_running=service_running,
                observed_error_code=None
                if service.returncode in {0, 1060}
                else "service_query_failed",
            )
        public_key = await self._commands.show(interface_name, "public-key")
        peers_result = await self._commands.show(interface_name, "peers")
        endpoints_result = await self._commands.show(interface_name, "endpoints")
        allowed_result = await self._commands.show(interface_name, "allowed-ips")
        handshake_result = await self._commands.show(interface_name, "latest-handshakes")
        if any(
            result.returncode != 0
            for result in (
                public_key,
                peers_result,
                endpoints_result,
                allowed_result,
                handshake_result,
            )
        ):
            return WindowsTunnelSnapshot(
                interface_name=interface_name,
                interface_present=True,
                interface_up=interface.is_up,
                addresses=_canonical_host_addresses(interface.addresses),
                service_present=service_present,
                service_running=service_running,
                observed_error_code="wireguard_query_failed",
            )
        allowed = _parse_peer_values(allowed_result.stdout)
        endpoints = _parse_peer_values(endpoints_result.stdout)
        handshakes = _parse_peer_values(handshake_result.stdout)
        peer_keys = tuple(
            line.strip() for line in peers_result.stdout.splitlines() if line.strip()
        )[:_MAX_PEERS]
        peers = tuple(
            _peer_snapshot(
                key,
                allowed_values=allowed.get(key, ()),
                endpoint_values=endpoints.get(key, ()),
                handshake_values=handshakes.get(key, ()),
            )
            for key in peer_keys
        )
        ownership_complete = all(peer.allowed_networks_complete for peer in peers)
        desired_routes = (
            tuple(dict.fromkeys(route for peer in peers for route in peer.allowed_host_routes))[
                :_MAX_ROUTES
            ]
            if ownership_complete and include_routes
            else ()
        )
        target_route = _safe_host_route(expected_host_route)
        target_owned = (
            target_route is not None
            and peer_public_key is not None
            and peer_owns_unique_target(peers, peer_public_key, target_route)
        )
        if target_route is not None:
            if target_owned:
                desired_routes = tuple(dict.fromkeys((*desired_routes, target_route)))[:_MAX_ROUTES]
            else:
                desired_routes = tuple(route for route in desired_routes if route != target_route)
        interface_addresses = _canonical_interface_ips(interface.addresses)
        interface_index = self._interface_index(interface_name)
        present_routes: list[str] = []
        for route in desired_routes:
            result = await self._commands.query_route(route)
            if result.returncode == 0 and windows_route_contains_exact_host(
                result.stdout,
                route,
                interface_addresses=interface_addresses,
                interface_index=interface_index,
            ):
                present_routes.append(route)
        public = public_key.stdout.strip()
        return WindowsTunnelSnapshot(
            interface_name=interface_name,
            interface_present=True,
            interface_up=interface.is_up,
            addresses=_canonical_host_addresses(interface.addresses),
            service_present=service_present,
            service_running=service_running,
            peers=peers,
            host_routes=tuple(present_routes),
            public_key_hash=canonical_sha256({"public_key": public}) if public else None,
            stable_interface_id=f"windows:{interface_name.casefold()}",
        )


def windows_route_contains_exact_host(
    stdout: str,
    host_route: str,
    *,
    interface_addresses: Collection[str],
    interface_index: int | None,
) -> bool:
    """解析固定 `route print` 活动表，只接受目标接口的精确 host route。"""
    try:
        network = ipaddress.ip_network(host_route, strict=True)
    except ValueError:
        return False
    if network.prefixlen != network.max_prefixlen or parse_safe_allowed_network(host_route) is None:
        return False

    active_routes = False
    header_seen = False
    target_addresses = _canonical_interface_ips(interface_addresses)
    for line in stdout.splitlines():
        text = line.strip()
        lowered = text.casefold()
        if lowered in _ACTIVE_ROUTE_LABELS:
            active_routes = True
            header_seen = False
            continue
        if not active_routes:
            continue
        if lowered in _PERSISTENT_ROUTE_LABELS:
            return False
        parts = text.split()
        lowered_parts = tuple(part.casefold() for part in parts)
        if network.version == 4:
            if lowered_parts in _IPV4_ROUTE_HEADERS:
                header_seen = True
                continue
            if not header_seen or len(parts) != 5:
                continue
            try:
                destination = ipaddress.IPv4Address(parts[0])
                netmask = ipaddress.IPv4Address(parts[1])
                interface = ipaddress.IPv4Address(parts[3])
                metric = int(parts[4])
            except ValueError:
                continue
            gateway = parts[2]
            gateway_v4: ipaddress.IPv4Address | None = None
            if gateway.casefold() not in _ON_LINK_GATEWAYS:
                try:
                    gateway_v4 = ipaddress.IPv4Address(gateway)
                except ValueError:
                    continue
            if (
                metric < 0
                or metric > 9999
                or destination != network.network_address
                or netmask != ipaddress.IPv4Address("255.255.255.255")
                or str(interface) not in target_addresses
                or gateway_v4 == destination
            ):
                continue
            return True
        else:
            if lowered_parts in _IPV6_ROUTE_HEADERS:
                header_seen = True
                continue
            if not header_seen or len(parts) != 4:
                continue
            try:
                route_interface = int(parts[0])
                metric = int(parts[1])
                destination = ipaddress.ip_network(parts[2], strict=False)
            except ValueError:
                continue
            gateway = parts[3]
            gateway_v6: ipaddress.IPv6Address | None = None
            if gateway.casefold() not in _ON_LINK_GATEWAYS:
                try:
                    gateway_v6 = ipaddress.IPv6Address(gateway)
                except ValueError:
                    continue
            if (
                interface_index is None
                or route_interface <= 0
                or route_interface != interface_index
                or metric < 0
                or metric > 9999
                or destination.version != 6
                or destination.prefixlen != 128
                or destination.network_address != network.network_address
                or gateway_v6 == destination.network_address
            ):
                continue
            return True
    return False


def _canonical_interface_ips(values: Collection[str]) -> frozenset[str]:
    addresses: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value.split("%", maxsplit=1)[0])
        except ValueError:
            continue
        addresses.add(str(address))
    return frozenset(addresses)


def system_interface_index(interface_name: str) -> int | None:
    try:
        return socket.if_nametoindex(interface_name)
    except (OSError, ValueError):
        return None


def _parse_peer_values(stdout: str) -> dict[str, tuple[str, ...]]:
    values: dict[str, tuple[str, ...]] = {}
    for line in stdout.splitlines():
        parts = tuple(part.strip() for part in line.split("\t"))
        if len(parts) >= 2 and parts[0]:
            key = parts[0]
            parsed = parts[1:]
            values[key] = (*values[key], "", *parsed) if key in values else parsed
    return values


def parse_safe_allowed_network(value: str) -> str | None:
    """返回可用于 peer ownership 的安全规范 network，拒绝过宽或特殊网段。"""
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    if (
        network.prefixlen == 0
        or network.num_addresses > _MAX_SAFE_ALLOWED_NETWORK_ADDRESSES
        or any(
            getattr(network.network_address, attribute)
            for attribute in (
                "is_multicast",
                "is_unspecified",
                "is_loopback",
                "is_reserved",
                "is_link_local",
            )
        )
        or str(network) != value
    ):
        return None
    return str(network)


def collect_safe_allowed_networks(values: Collection[str]) -> tuple[tuple[str, ...], bool]:
    """保留完整的有界安全 network 集合，并标记是否观察完整。"""
    networks: list[str] = []
    seen: set[str] = set()
    complete = bool(values)
    for value in values:
        parsed = parse_safe_allowed_network(value.strip())
        if parsed is None or parsed in seen:
            complete = False
            continue
        seen.add(parsed)
        if len(networks) == MAX_SAFE_ALLOWED_NETWORKS:
            complete = False
            continue
        networks.append(parsed)
    return tuple(networks), complete


def _peer_snapshot(
    public_key: str,
    *,
    allowed_values: tuple[str, ...],
    endpoint_values: tuple[str, ...],
    handshake_values: tuple[str, ...],
) -> WindowsPeerSnapshot:
    allowed_networks, allowed_networks_complete = collect_safe_allowed_networks(
        tuple(route for item in allowed_values for route in item.split(","))
    )
    return WindowsPeerSnapshot(
        public_key=public_key,
        endpoint_host=(
            parsed[0]
            if (parsed := parse_wireguard_endpoint(endpoint_values[0] if endpoint_values else ""))
            else None
        ),
        endpoint_port=parsed[1] if parsed is not None else None,
        allowed_host_routes=tuple(
            route for route in allowed_networks if _is_observable_host_route(route)
        )[:8],
        allowed_networks=allowed_networks,
        allowed_networks_complete=allowed_networks_complete,
        latest_handshake_epoch=_nonnegative_integer(
            handshake_values[0] if handshake_values else ""
        ),
    )


def _is_observable_host_route(value: str) -> bool:
    network_value = parse_safe_allowed_network(value)
    if network_value is None:
        return False
    network = ipaddress.ip_network(network_value, strict=True)
    address = network.network_address
    return network.prefixlen == network.max_prefixlen and not address.is_reserved


def _safe_host_route(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    if network.prefixlen != network.max_prefixlen:
        return None
    return parse_safe_allowed_network(value)


def peer_owns_unique_target(
    peers: tuple[WindowsPeerSnapshot, ...],
    peer_public_key: str,
    target_route: str,
) -> bool:
    safe_target = _safe_host_route(target_route)
    if safe_target is None or any(not peer.allowed_networks_complete for peer in peers):
        return False
    target = ipaddress.ip_network(safe_target, strict=True)
    owners = tuple(
        peer
        for peer in peers
        if any(
            target.network_address in ipaddress.ip_network(parsed, strict=True)
            for route in (*peer.allowed_networks, *peer.allowed_host_routes)
            if (parsed := parse_safe_allowed_network(route)) is not None
        )
    )
    return len(owners) == 1 and owners[0].public_key == peer_public_key


def _canonical_host_addresses(values: tuple[str, ...]) -> tuple[str, ...]:
    addresses: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value.split("%", maxsplit=1)[0])
        except ValueError:
            continue
        addresses.append(f"{address}/{address.max_prefixlen}")
    return tuple(sorted(set(addresses)))


def _nonnegative_integer(value: str) -> int | None:
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def parse_wireguard_endpoint(value: str) -> tuple[str, int] | None:
    """解析官方 `wg show ... endpoints` 的 IP:port 行，不接受主机名。"""
    text = value.strip()
    if not text or text in {"(none)", "<none>"}:
        return None
    if text.startswith("["):
        closing = text.find("]:")
        if closing < 0:
            return None
        host, raw_port = text[1:closing], text[closing + 2 :]
    else:
        if ":" not in text:
            return None
        host, raw_port = text.rsplit(":", maxsplit=1)
    try:
        ipaddress.ip_address(host)
        port = int(raw_port)
    except ValueError:
        return None
    return (host, port) if 1 <= port <= 65535 else None


def windows_is_administrator(
    *,
    platform_name: str | None = None,
    native_check: Callable[[], bool] | None = None,
) -> bool:
    """读取管理员令牌；测试可注入检查函数而不触发提权。"""
    if (platform_name or os.name) != "nt":
        return False
    return (native_check or _native_windows_is_administrator)()


def _native_windows_is_administrator() -> bool:  # pragma: no cover - Windows 原生 API 薄封装
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())  # pyright: ignore
