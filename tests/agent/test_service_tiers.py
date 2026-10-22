"""首页三档：直接显示、可能是服务、不显示。"""

from __future__ import annotations

import pytest

from tunnelminion.agent.service_tiers import ServiceTier, decide_tier, is_wildcard_address
from tunnelminion.platforms.process_origin import ProcessOrigin


def tier(
    origin: ProcessOrigin | None,
    *,
    protocol: str = "tcp",
    address: str = "0.0.0.0",
    name: str | None = "server",
    container_running: bool | None = None,
) -> ServiceTier:
    return decide_tier(
        protocol=protocol,
        address=address,
        process_name=name,
        origin=origin,
        container_running=container_running,
    )


def test_running_containers_show_and_stopped_ones_hide() -> None:
    assert tier(None, container_running=True) is ServiceTier.SHOW
    assert tier(ProcessOrigin.CONTAINER_RUNTIME, container_running=True) is ServiceTier.SHOW
    assert tier(None, container_running=False) is ServiceTier.HIDE


def test_udp_endpoints_and_tunnelminion_itself_hide() -> None:
    assert tier(ProcessOrigin.TERMINAL, protocol="udp") is ServiceTier.HIDE
    assert tier(ProcessOrigin.USER_INSTALL, name="tunnelminion.exe") is ServiceTier.HIDE


@pytest.mark.parametrize("origin", [ProcessOrigin.TERMINAL, ProcessOrigin.USER_INSTALL])
def test_programs_you_started_or_installed_show(origin: ProcessOrigin) -> None:
    assert tier(origin, address="127.0.0.1") is ServiceTier.SHOW


def test_unknown_origin_asks_the_user() -> None:
    assert tier(ProcessOrigin.UNKNOWN, address="127.0.0.1") is ServiceTier.REVIEW


def test_interpreter_without_origin_counts_as_your_script() -> None:
    assert tier(None, address="127.0.0.1", name="python3.13") is ServiceTier.SHOW


@pytest.mark.parametrize("origin", [ProcessOrigin.APP_SERVICE, None])
def test_app_services_only_surface_when_listening_on_all_interfaces(
    origin: ProcessOrigin | None,
) -> None:
    assert tier(origin, address="::") is ServiceTier.REVIEW
    assert tier(origin, address="127.0.0.1") is ServiceTier.HIDE


@pytest.mark.parametrize(
    "origin", [ProcessOrigin.SYSTEM, ProcessOrigin.DESKTOP_APP, ProcessOrigin.CONTAINER_RUNTIME]
)
def test_system_desktop_and_runtime_processes_hide(origin: ProcessOrigin) -> None:
    assert tier(origin) is ServiceTier.HIDE


def test_wildcard_addresses() -> None:
    assert is_wildcard_address("0.0.0.0") and is_wildcard_address("::")
    assert not is_wildcard_address("127.0.0.1") and not is_wildcard_address("10.77.0.1")
