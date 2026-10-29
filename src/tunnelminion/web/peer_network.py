"""判断本机去对端时走的是哪种组网，只读路由表和网卡信息，不改系统设置。"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PeerNetwork = Literal["wireguard", "n2n", "other"]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# 路由命令输出里的网卡名只用来拼固定的标记文件路径，先限制字符，防止路径穿越。
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_MACOS_ROUTE = re.compile(r"^\s*interface:\s*(\S+)\s*$", re.MULTILINE)
_LINUX_ROUTE = re.compile(r"\bdev\s+(\S+)")


@dataclass(frozen=True)
class RouteInterface:
    """系统认为去目标地址要走的那块网卡。"""

    name: str
    description: str = ""
    # 系统直接证实它是 WireGuard，例如 wireguard-go 的控制 socket 或 Linux 内核网卡类型。
    wireguard: bool = False


RouteLookup = Callable[[IPAddress], RouteInterface | None]
CommandRunner = Callable[[list[str]], str | None]


def classify_interface(interface: RouteInterface) -> PeerNetwork:
    """Windows 看网卡描述，其他系统看系统标记和网卡名；认不出就是 other。"""
    text = f"{interface.name} {interface.description}".casefold()
    if interface.wireguard or "wireguard" in text:
        return "wireguard"
    # n2n 在 Windows 上通常借用 TAP-Windows 网卡，在 macOS 和 Linux 上通常是 tap 设备。
    if "n2n" in text or "tap-windows" in text or interface.name.casefold().startswith("tap"):
        return "n2n"
    return "other"


def wireguard_marked(name: str, root: Path = Path("/")) -> bool:
    """wireguard-go 会在固定目录留下控制 socket；Linux 内核网卡会标明类型。"""
    if not _INTERFACE_NAME.fullmatch(name):
        return False
    if (root / "var" / "run" / "wireguard" / f"{name}.sock").exists():
        return True
    try:
        uevent = (root / "sys" / "class" / "net" / name / "uevent").read_text(encoding="utf-8")
    except OSError:
        return False
    return "DEVTYPE=wireguard" in uevent.splitlines()


def run_command(command: list[str]) -> str | None:
    """路由查询命令最多等两秒，失败时当作不知道。"""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def command_route_lookup(
    command: list[str],
    pattern: re.Pattern[str],
    run: CommandRunner = run_command,
    marked: Callable[[str], bool] = wireguard_marked,
) -> RouteLookup:
    """用系统自带的路由查询命令找出去目标地址的网卡。"""

    def lookup(address: IPAddress) -> RouteInterface | None:
        output = run([*command, str(address)])
        match = pattern.search(output) if output is not None else None
        if match is None or not _INTERFACE_NAME.fullmatch(match.group(1)):
            return None
        name = match.group(1)
        return RouteInterface(name=name, wireguard=marked(name))

    return lookup


def windows_route_interface(
    address: IPAddress,
) -> RouteInterface | None:  # pragma: no cover - Windows 原生 API 薄封装
    """用 GetBestInterfaceEx 按路由表选网卡，再从 GetAdaptersAddresses 读名字和描述。"""
    import ctypes
    from ctypes import wintypes

    class SockaddrIn(ctypes.Structure):
        _fields_ = (
            ("family", ctypes.c_ushort),
            ("port", ctypes.c_ushort),
            ("address", ctypes.c_ubyte * 4),
            ("zero", ctypes.c_ubyte * 8),
        )

    class SockaddrIn6(ctypes.Structure):
        _fields_ = (
            ("family", ctypes.c_ushort),
            ("port", ctypes.c_ushort),
            ("flowinfo", ctypes.c_ulong),
            ("address", ctypes.c_ubyte * 16),
            ("scope_id", ctypes.c_ulong),
        )

    class AdapterAddresses(ctypes.Structure):
        pass

    AdapterAddresses._fields_ = (
        ("length", ctypes.c_ulong),
        ("if_index", wintypes.DWORD),
        ("next", ctypes.POINTER(AdapterAddresses)),
        ("adapter_name", ctypes.c_char_p),
        ("first_unicast", ctypes.c_void_p),
        ("first_anycast", ctypes.c_void_p),
        ("first_multicast", ctypes.c_void_p),
        ("first_dns_server", ctypes.c_void_p),
        ("dns_suffix", ctypes.c_wchar_p),
        ("description", ctypes.c_wchar_p),
        ("friendly_name", ctypes.c_wchar_p),
    )

    try:
        iphlpapi = ctypes.WinDLL("iphlpapi")
        packed = address.packed
        socket_address: ctypes.Structure
        if address.version == 4:
            socket_address = SockaddrIn(2, 0, (ctypes.c_ubyte * 4)(*packed))
        else:
            socket_address = SockaddrIn6(23, 0, 0, (ctypes.c_ubyte * 16)(*packed), 0)
        index = wintypes.DWORD()
        if iphlpapi.GetBestInterfaceEx(ctypes.byref(socket_address), ctypes.byref(index)) != 0:
            return None
        size = wintypes.ULONG(16 * 1024)
        # 只要名字和描述，跳过各类地址列表。
        flags = 0x0001 | 0x0002 | 0x0004 | 0x0008
        result = 111
        buffer = ctypes.create_string_buffer(0)
        for _ in range(3):
            buffer = ctypes.create_string_buffer(size.value)
            result = iphlpapi.GetAdaptersAddresses(0, flags, None, buffer, ctypes.byref(size))
            if result != 111:
                break
        if result != 0:
            return None
        adapter = ctypes.cast(buffer, ctypes.POINTER(AdapterAddresses))
        while adapter:
            if adapter.contents.if_index == index.value:
                return RouteInterface(
                    name=adapter.contents.friendly_name or "",
                    description=adapter.contents.description or "",
                )
            adapter = adapter.contents.next
    except OSError:
        return None
    return None


def system_route_lookup(system: str = sys.platform) -> RouteLookup:
    """按当前操作系统选择只读的路由查询方式。"""
    if system == "win32":
        return windows_route_interface
    if system == "darwin":
        return command_route_lookup(["/sbin/route", "-n", "get"], _MACOS_ROUTE)
    if system.startswith("linux"):
        return command_route_lookup(["ip", "route", "get"], _LINUX_ROUTE)
    return lambda _address: None


class PeerNetworkProbe:
    """按对端地址缓存判断结果，避免每次刷新地图都查路由。"""

    def __init__(
        self,
        lookup: RouteLookup,
        *,
        ttl: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._lookup = lookup
        self._ttl = ttl
        self._clock = clock
        self._cache: dict[str, tuple[float, PeerNetwork | None]] = {}

    def network(self, host: str | None) -> PeerNetwork | None:
        """地址不是 IP 或系统查不到路由时返回 None，表示不知道。"""
        if host is None:
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None
        now = self._clock()
        cached = self._cache.get(host)
        if cached is not None and cached[0] > now:
            return cached[1]
        interface = self._lookup(address)
        value = classify_interface(interface) if interface is not None else None
        self._cache[host] = (now + self._ttl, value)
        return value
