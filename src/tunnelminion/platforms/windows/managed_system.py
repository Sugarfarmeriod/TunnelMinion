"""Windows 官方 WireGuard 工具的固定参数、预检与只读观察边界。"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Callable
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
    latest_handshake_epoch: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_routes(self) -> Self:
        if (self.endpoint_host is None) != (self.endpoint_port is None):
            raise ValueError("peer endpoint 必须同时包含地址和端口")
        if self.endpoint_host is not None:
            ipaddress.ip_address(self.endpoint_host)
        for route in self.allowed_host_routes:
            network = ipaddress.ip_network(route, strict=True)
            if network.prefixlen != network.max_prefixlen:
                raise ValueError("Windows Provider 只接受 host route")
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
    ) -> None:
        self._reader = reader
        self._commands = commands

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
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
            WindowsPeerSnapshot(
                public_key=key,
                endpoint_host=(
                    parsed[0]
                    if (parsed := parse_wireguard_endpoint(endpoints.get(key, ("",))[0]))
                    else None
                ),
                endpoint_port=parsed[1] if parsed is not None else None,
                allowed_host_routes=tuple(
                    route.strip()
                    for route in (allowed.get(key, ("",))[0]).split(",")
                    if route.strip()
                )[:8],
                latest_handshake_epoch=_nonnegative_integer(handshakes.get(key, ("",))[0]),
            )
            for key in peer_keys
        )
        desired_routes = tuple(
            dict.fromkeys(route for peer in peers for route in peer.allowed_host_routes)
        )[:_MAX_ROUTES]
        present_routes: list[str] = []
        for route in desired_routes:
            result = await self._commands.query_route(route)
            if (
                result.returncode == 0
                and str(ipaddress.ip_network(route, strict=True).network_address) in result.stdout
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


def _parse_peer_values(stdout: str) -> dict[str, tuple[str, ...]]:
    values: dict[str, tuple[str, ...]] = {}
    for line in stdout.splitlines():
        parts = tuple(part.strip() for part in line.split("\t"))
        if len(parts) >= 2 and parts[0]:
            values[parts[0]] = parts[1:]
    return values


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
