"""macOS WireGuard 官方工具的固定参数、预检与只读观察边界。"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, model_validator

from tunnelminion.network.contracts import ProviderMode, canonical_sha256
from tunnelminion.platforms.macos.system import CommandResult, CommandRunner
from tunnelminion.platforms.windows.managed_system import (
    WindowsPeerSnapshot,
    WindowsProviderPreflight,
    WindowsTunnelSnapshot,
    collect_safe_allowed_networks,
    parse_safe_allowed_network,
    peer_owns_unique_target,
)

_MANAGED_INTERFACE = re.compile(r"^tmn-[a-z0-9-]{1,48}$")
_RUNTIME_INTERFACE = re.compile(r"^(?:utun[0-9]+|tmn-[a-z0-9-]{1,48})$")


@runtime_checkable
class MacOSOperationBinder(Protocol):
    """允许受限 runner 绑定已核准计划；普通 runner 无需实现。"""

    def bind_operation(self, plan_hash: str, creation_nonce: str) -> None: ...


@runtime_checkable
class MacOSRuntimeResourceReporter(Protocol):
    """向 Provider runtime hash 暴露脱敏的额外受管资源存在性。"""

    def runtime_resources(self) -> tuple[str, ...]: ...


class MacOSProviderPreflight(WindowsProviderPreflight):
    """沿用跨平台 Provider 前置状态字段；manager 为固定平台管理器。"""


class MacOSPeerSnapshot(WindowsPeerSnapshot):
    """macOS 公开 peer 状态，不含私钥或预共享密钥。"""


class MacOSTunnelSnapshot(WindowsTunnelSnapshot):
    """macOS `wg`、`ifconfig` 与路由表联合得到的有限快照。"""


class MacOSProviderPaths(BaseModel):
    """只允许预先配置的绝对工具路径和独立受管配置目录。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wg: Path
    wg_quick: Path
    ifconfig: Path
    netstat: Path
    config_root: Path

    @model_validator(mode="after")
    def validate_absolute_paths(self) -> Self:
        if not all(
            path.is_absolute()
            for path in (self.wg, self.wg_quick, self.ifconfig, self.netstat, self.config_root)
        ):
            raise ValueError("macOS Provider 路径必须全部为绝对路径")
        return self


class FixedMacOSWireGuardCommands:
    """构造固定 argv；禁止 Shell 字符串、`sudo` prompt 和动态配置路径。"""

    def __init__(
        self,
        paths: MacOSProviderPaths,
        runner: CommandRunner,
        *,
        path_exists: Callable[[Path], bool] | None = None,
        effective_uid: Callable[[], int] | None = None,
        platform_name: str | None = None,
    ) -> None:
        self.paths = paths
        self._runner = runner
        self._path_exists = path_exists or Path.exists
        self._effective_uid = effective_uid or macos_effective_uid
        self._platform_name = platform_name or sys.platform

    def preflight(self) -> MacOSProviderPreflight:
        supported = self._platform_name == "darwin"
        wg = self._path_exists(self.paths.wg)
        wg_quick = self._path_exists(self.paths.wg_quick)
        ifconfig = self._path_exists(self.paths.ifconfig)
        netstat = self._path_exists(self.paths.netstat)
        administrator = supported and self._effective_uid() == 0
        managed = supported and wg and wg_quick and ifconfig and netstat and administrator
        if managed:
            error = None
        elif not supported:
            error = "platform_unsupported"
        elif not (wg and wg_quick and ifconfig and netstat):
            error = "dependency_unavailable"
        else:
            error = "permission_denied"
        return MacOSProviderPreflight(
            mode=ProviderMode.MANAGED if managed else ProviderMode.OBSERVE_ONLY,
            platform_supported=supported,
            wireguard_manager_available=wg_quick,
            wg_available=wg,
            service_control_available=ifconfig,
            route_tool_available=netstat,
            administrator=administrator,
            error_code=error,
        )

    def bind_operation(self, plan_hash: str, creation_nonce: str) -> None:
        """仅在 runner 明确支持时传递计划绑定。"""
        if isinstance(self._runner, MacOSOperationBinder):
            self._runner.bind_operation(plan_hash, creation_nonce)

    def runtime_resources(self) -> tuple[str, ...]:
        if isinstance(self._runner, MacOSRuntimeResourceReporter):
            return self._runner.runtime_resources()
        return ()

    async def interfaces(self) -> CommandResult:
        return await self._runner.run((str(self.paths.wg), "show", "interfaces"), 5)

    async def show(self, interface_name: str, field: str) -> CommandResult:
        self.validate_runtime_interface(interface_name)
        if field not in {
            "public-key",
            "peers",
            "endpoints",
            "allowed-ips",
            "latest-handshakes",
        }:
            raise ValueError("不允许的 WireGuard 观察字段")
        return await self._runner.run((str(self.paths.wg), "show", interface_name, field), 5)

    async def inspect_interface(self, interface_name: str) -> CommandResult:
        self.validate_runtime_interface(interface_name)
        return await self._runner.run((str(self.paths.ifconfig), interface_name), 5)

    async def route_table(self, family: str = "inet") -> CommandResult:
        if family not in {"inet", "inet6"}:
            raise ValueError("macOS route family 不受支持")
        return await self._runner.run((str(self.paths.netstat), "-rn", "-f", family), 10)

    async def up(self, interface_name: str, config_path: Path) -> CommandResult:
        self._validate_managed_interface(interface_name)
        resolved = self._validate_config_path(config_path)
        return await self._runner.run((str(self.paths.wg_quick), "up", str(resolved)), 30)

    async def down(self, interface_name: str, config_path: Path) -> CommandResult:
        self._validate_managed_interface(interface_name)
        resolved = self._validate_config_path(config_path)
        return await self._runner.run((str(self.paths.wg_quick), "down", str(resolved)), 30)

    def config_path(self, interface_name: str, revision: int) -> Path:
        self._validate_managed_interface(interface_name)
        if revision < 1:
            raise ValueError("配置 revision 必须为正数")
        return self.paths.config_root / f"{interface_name}.r{revision}.conf"

    def _validate_config_path(self, config_path: Path) -> Path:
        root = self.paths.config_root.resolve()
        resolved = config_path.resolve()
        if resolved.parent != root or resolved.suffix != ".conf":
            raise ValueError("配置路径必须位于固定 macOS 受管目录")
        return resolved

    @staticmethod
    def _validate_managed_interface(interface_name: str) -> None:
        if _MANAGED_INTERFACE.fullmatch(interface_name) is None:
            raise ValueError("macOS 受管接口名称不符合固定格式")

    @staticmethod
    def validate_runtime_interface(interface_name: str) -> None:
        if _RUNTIME_INTERFACE.fullmatch(interface_name) is None:
            raise ValueError("macOS 运行时接口名称不符合固定格式")


class MacOSWireGuardObserver:
    """只读取公开 key、peer、host route 和接口状态。"""

    def __init__(self, commands: FixedMacOSWireGuardCommands) -> None:
        self._commands = commands

    async def observe(self, interface_name: str) -> MacOSTunnelSnapshot:
        return await self._observe(interface_name)

    async def observe_candidates(self, interface_name: str) -> MacOSTunnelSnapshot:
        """只读取候选所需 WireGuard 事实，不读取任何路由。"""
        return await self._observe(interface_name, include_routes=False)

    async def observe_path(
        self,
        interface_name: str,
        *,
        peer_public_key: str,
        expected_host_route: str,
    ) -> MacOSTunnelSnapshot:
        """为 path probe 保持统一入口；macOS 路由表本身已独立读取精确 host route。"""
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
    ) -> MacOSTunnelSnapshot:
        FixedMacOSWireGuardCommands.validate_runtime_interface(interface_name)
        discovered = await self._commands.interfaces()
        if discovered.returncode != 0:
            return self._absent(interface_name, "permission_denied")
        if interface_name not in discovered.stdout.split():
            return self._absent(interface_name)

        interface = await self._commands.inspect_interface(interface_name)
        public, peers, endpoints, allowed, handshakes, routes = await self._read_public_state(
            interface_name, include_routes=include_routes
        )
        public_text = public.stdout.strip() if public.returncode == 0 else ""
        peer_values = _peer_values(peers.stdout if peers.returncode == 0 else "")
        endpoint_values = _peer_values(endpoints.stdout if endpoints.returncode == 0 else "")
        allowed_values = _peer_values(allowed.stdout if allowed.returncode == 0 else "")
        handshake_values = _peer_values(handshakes.stdout if handshakes.returncode == 0 else "")
        peer_snapshots = tuple(
            _peer_snapshot(key, allowed_values, endpoint_values, handshake_values)
            for key in peer_values
        )
        host_routes = (
            _parse_host_routes(routes[0].stdout, interface_name)
            + _parse_host_routes(routes[1].stdout, interface_name)
            if routes
            else ()
        )
        target_route = _safe_host_route(expected_host_route)
        if target_route is not None and not (
            peer_public_key is not None
            and peer_owns_unique_target(peer_snapshots, peer_public_key, target_route)
        ):
            host_routes = tuple(route for route in host_routes if route != target_route)
        return MacOSTunnelSnapshot(
            interface_name=interface_name,
            interface_present=True,
            interface_up=interface.returncode == 0 and _interface_is_up(interface.stdout),
            addresses=_parse_addresses(interface.stdout),
            service_present=True,
            service_running=True,
            peers=peer_snapshots,
            host_routes=host_routes,
            public_key_hash=(
                canonical_sha256({"public_key": public_text}) if public_text else None
            ),
            stable_interface_id=interface_name,
            observed_error_code=(
                None
                if all(
                    item.returncode == 0
                    for item in (public, peers, endpoints, allowed, handshakes, *routes)
                )
                else "permission_denied"
            ),
        )

    async def _read_public_state(
        self,
        interface_name: str,
        *,
        include_routes: bool = True,
    ) -> tuple[
        CommandResult,
        CommandResult,
        CommandResult,
        CommandResult,
        CommandResult,
        tuple[CommandResult, ...],
    ]:
        public = await self._commands.show(interface_name, "public-key")
        peers = await self._commands.show(interface_name, "peers")
        endpoints = await self._commands.show(interface_name, "endpoints")
        allowed = await self._commands.show(interface_name, "allowed-ips")
        handshakes = await self._commands.show(interface_name, "latest-handshakes")
        route_results = (
            (
                await self._commands.route_table("inet"),
                await self._commands.route_table("inet6"),
            )
            if include_routes
            else ()
        )
        return public, peers, endpoints, allowed, handshakes, route_results

    @staticmethod
    def _absent(interface_name: str, error: str | None = None) -> MacOSTunnelSnapshot:
        return MacOSTunnelSnapshot(
            interface_name=interface_name,
            interface_present=False,
            interface_up=False,
            service_present=False,
            service_running=False,
            observed_error_code=error,
        )


def _parse_addresses(stdout: str) -> tuple[str, ...]:
    values: list[str] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "inet":
            try:
                address = ipaddress.IPv4Address(parts[1])
                if parts[2] == "netmask":
                    mask_text = parts[3]
                elif len(parts) >= 6 and parts[2] == "-->" and parts[4] == "netmask":
                    mask_text = parts[5]
                else:
                    continue
                mask = int(mask_text, 16) if mask_text.startswith("0x") else int(mask_text)
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{ipaddress.IPv4Address(mask)}").prefixlen
            except (ipaddress.AddressValueError, ValueError):
                continue
            values.append(f"{address}/{prefix}")
        elif len(parts) >= 4 and parts[0] == "inet6" and "prefixlen" in parts:
            try:
                address = ipaddress.IPv6Address(parts[1].split("%", maxsplit=1)[0])
                prefix_index = parts.index("prefixlen") + 1
                prefix = int(parts[prefix_index])
                if not 0 <= prefix <= address.max_prefixlen:
                    continue
            except (ipaddress.AddressValueError, ValueError, IndexError):
                continue
            values.append(f"{address}/{prefix}")
    return tuple(sorted(set(values)))


def _interface_is_up(stdout: str) -> bool:
    if "status: active" in stdout.lower():
        return True
    flags = re.search(r"flags=\d+<([^>]*)>", stdout)
    return flags is not None and "UP" in flags.group(1).split(",")


def _parse_host_routes(stdout: str, interface_name: str) -> tuple[str, ...]:
    values: list[str] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[-1] != interface_name:
            continue
        try:
            network = ipaddress.ip_network(parts[0], strict=False)
        except ValueError:
            continue
        if network.prefixlen == network.max_prefixlen and parse_safe_allowed_network(str(network)):
            values.append(str(network))
    return tuple(sorted(set(values)))


def _peer_values(stdout: str) -> dict[str, tuple[str, ...]]:
    values: dict[str, tuple[str, ...]] = {}
    for line in stdout.splitlines():
        parts = tuple(part.strip() for part in line.split("\t"))
        if parts and parts[0]:
            key = parts[0]
            parsed = tuple(
                value.strip() for item in parts[1:] for value in item.split(",") if value.strip()
            )
            values[key] = (*values[key], "", *parsed) if key in values else parsed
    return values


def _is_host_route(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    return network.prefixlen == network.max_prefixlen and parse_safe_allowed_network(value) == value


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


def _peer_snapshot(
    public_key: str,
    allowed_values: dict[str, tuple[str, ...]],
    endpoint_values: dict[str, tuple[str, ...]],
    handshake_values: dict[str, tuple[str, ...]],
) -> MacOSPeerSnapshot:
    networks, networks_complete = collect_safe_allowed_networks(allowed_values.get(public_key, ()))
    endpoint = parse_wireguard_endpoint(endpoint_values.get(public_key, ("",))[0])
    return MacOSPeerSnapshot(
        public_key=public_key,
        endpoint_host=endpoint[0] if endpoint is not None else None,
        endpoint_port=endpoint[1] if endpoint is not None else None,
        allowed_host_routes=tuple(route for route in networks if _is_host_route(route))[:8],
        allowed_networks=networks,
        allowed_networks_complete=networks_complete,
        latest_handshake_epoch=_nonnegative_integer(handshake_values.get(public_key, ("",))[0]),
    )


def _nonnegative_integer(value: str) -> int | None:
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def parse_wireguard_endpoint(value: str) -> tuple[str, int] | None:
    """解析官方 `wg show ... endpoints` 的 IP:port 行。"""
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


def macos_effective_uid() -> int:  # pragma: no cover - macOS 原生 API 薄封装
    """读取有效 UID；非 macOS 调用只用于静态导入，不触发提权。"""
    return os.geteuid()  # pyright: ignore
