"""主人自己装的 Windows 服务即使只听本机，也要在"可能是服务"里有入口；保护名单里的照旧不显示。"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from tests.agent.test_service_observation import Clock, FakeAdapter, collection
from tests.repair.factories import NODE

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_marks import ServiceMark
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.agent.service_tiers import ServiceTier, decide_tier
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.repair.contracts import RepairCommand, WindowsServiceInfo
from tunnelminion.web.service_map import build_local_service_map

# 进程号 → (服务名, 服务程序路径)；路径为 None 表示读不到服务信息。
SERVICES: dict[int, tuple[str, str | None]] = {
    401: ("tmacceptsvc", r"D:\tools\nssm.exe"),
    402: ("VendorHelper", r"C:\Program Files\Vendor\helper.exe"),
    403: ("WireGuardTunnel", r"C:\Program Files\WireGuard\wireguard.exe"),
    404: ("Spooler", r"C:\Windows\System32\spoolsv.exe"),
    405: ("Mystery", None),
    406: ("Broken", "error"),
}


class FakeWindowsServices:
    def __init__(self) -> None:
        self.inspected: list[str] = []

    def unsupported_reason(self) -> str | None:
        return None

    def services_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        return {pid: SERVICES[pid][0] for pid in pids if pid in SERVICES}

    def inspect(self, name: str) -> WindowsServiceInfo | None:
        self.inspected.append(name)
        path = next(path for service, path in SERVICES.values() if service == name)
        if path == "error":
            raise OSError("scm")
        if path is None:
            return None
        return WindowsServiceInfo(
            name=name,
            display_name=name,
            binary_path=path,
            start_type="automatic",
            running=True,
            granted=False,
        )

    async def set_granted(self, name: str, *, granted: bool) -> bool:
        raise AssertionError("不该改授权")

    async def start(self, name: str) -> RepairCommand:
        raise AssertionError("不该启动")

    async def stop(self, name: str) -> RepairCommand:
        raise AssertionError("不该停止")


def listener(pid: int, port: int, origin: ProcessOrigin) -> NetworkListener:
    return NetworkListener(
        protocol="tcp",
        address="127.0.0.1",
        port=port,
        pid=pid,
        process_name=f"svc{pid}.exe",
        origin=origin,
        has_web_page=False,
    )


def test_unprotected_loopback_windows_service_asks_the_owner() -> None:
    assert (
        decide_tier(
            protocol="tcp",
            address="127.0.0.1",
            process_name="python.exe",
            origin=ProcessOrigin.APP_SERVICE,
            has_web_page=False,
            own_windows_service=True,
        )
        is ServiceTier.REVIEW
    )
    assert (
        decide_tier(
            protocol="tcp",
            address="127.0.0.1",
            process_name="python.exe",
            origin=ProcessOrigin.APP_SERVICE,
            has_web_page=False,
        )
        is ServiceTier.HIDE
    )


def test_only_unprotected_windows_services_get_an_entry_and_protection_is_cached() -> None:
    clock = Clock()
    windows = FakeWindowsServices()
    listeners = [listener(pid, 18950 + pid - 400, ProcessOrigin.APP_SERVICE) for pid in SERVICES]
    # 不属于任何 Windows 服务的端口按原来的规则分档。
    listeners.append(listener(407, 18960, ProcessOrigin.TERMINAL))
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(collection(*listeners)),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        clock=clock,
        windows_services=windows,
    )
    snapshot = asyncio.run(observer.observe())
    own = {item.port: item.own_windows_service for item in snapshot.inventory}
    assert own == {
        18951: True,
        18952: True,
        18953: False,
        18954: False,
        18955: False,
        18956: False,
        18960: False,
    }
    view = build_local_service_map(NODE, snapshot, {})
    tiers = {endpoint.port: entry.tier for entry in view.services for endpoint in entry.endpoints}
    assert tiers == {18951: "review", 18952: "review", 18960: "show"}
    assert sorted(windows.inspected) == sorted(name for name, _ in SERVICES.values())

    # 标成"是我的服务"后直接显示，服务框里才有启停授权开关。
    marked = build_local_service_map(NODE, snapshot, {"program:svc401@18951": ServiceMark.MINE})
    entry = next(item for item in marked.services if item.key == "program:svc401@18951")
    assert entry.tier == "show" and entry.windows_service

    # 几分钟内不重读服务信息，过期后再读。
    clock.value += timedelta(seconds=60)
    asyncio.run(observer.observe())
    assert len(windows.inspected) == len(SERVICES)
    clock.value += timedelta(seconds=300)
    asyncio.run(observer.observe())
    assert len(windows.inspected) == 2 * len(SERVICES)
