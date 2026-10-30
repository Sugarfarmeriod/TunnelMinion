"""地图连线的组网类型判断。"""

from __future__ import annotations

import asyncio
import ipaddress
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.agent.test_remote_service_presentation import cache, node
from tests.gateway.test_services import LOCAL, REMOTE
from tests.web.test_peers import configuration, peer

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.web import peer_network
from tunnelminion.web.peer_network import (
    IPAddress,
    PeerNetworkProbe,
    RouteInterface,
    classify_interface,
    command_route_lookup,
    run_command,
    system_route_lookup,
    windows_route_interface,
    wireguard_marked,
)
from tunnelminion.web.peers import PeerServicePoller, PeersView, create_peers_router
from tunnelminion.web.service_map import LocalServiceMap


@pytest.mark.parametrize(
    ("interface", "expected"),
    [
        (RouteInterface("tm-tunnel", "WireGuard Tunnel"), "wireguard"),
        (RouteInterface("utun8", wireguard=True), "wireguard"),
        (RouteInterface("wireguard0"), "wireguard"),
        (RouteInterface("本地连接", "TAP-Windows Adapter V9"), "n2n"),
        (RouteInterface("tap0"), "n2n"),
        (RouteInterface("n2n-edge"), "n2n"),
        (RouteInterface("Mihomo", "Meta Tunnel"), "other"),
        (RouteInterface("utun1024"), "other"),
        (RouteInterface("en0"), "other"),
    ],
)
def test_interface_kinds(interface: RouteInterface, expected: str) -> None:
    assert classify_interface(interface) == expected


def test_wireguard_markers_come_from_socket_or_kernel_type(tmp_path: Path) -> None:
    sockets = tmp_path / "var" / "run" / "wireguard"
    sockets.mkdir(parents=True)
    (sockets / "utun8.sock").write_text("")
    kernel = tmp_path / "sys" / "class" / "net" / "wg0"
    kernel.mkdir(parents=True)
    (kernel / "uevent").write_text("DEVTYPE=wireguard\nINTERFACE=wg0\n")
    ethernet = tmp_path / "sys" / "class" / "net" / "eth0"
    ethernet.mkdir(parents=True)
    (ethernet / "uevent").write_text("INTERFACE=eth0\n")
    assert wireguard_marked("utun8", tmp_path)
    assert wireguard_marked("wg0", tmp_path)
    assert not wireguard_marked("eth0", tmp_path)
    assert not wireguard_marked("utun1024", tmp_path)
    assert not wireguard_marked("../utun8", tmp_path)


def test_run_command_returns_output_only_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_command([sys.executable, "-c", "print('interface: en0')"]) == "interface: en0\n"
    assert run_command([sys.executable, "-c", "raise SystemExit(1)"]) is None
    assert run_command([str(Path(__file__).parent / "missing-command")]) is None

    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("route", 2)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert run_command(["route"]) is None


def test_command_lookup_parses_macos_and_linux_route_output() -> None:
    outputs = {
        "10.0.0.2": "   route to: 10.0.0.2\n  interface: utun8\n      flags: <UP>\n",
        "10.0.0.3": "10.0.0.3 dev wg0 src 10.0.0.1 uid 501\n",
        "10.0.0.4": "  interface: ../etc\n",
        "10.0.0.5": "no route\n",
    }
    commands: list[list[str]] = []

    def run(command: list[str]) -> str | None:
        commands.append(command)
        return outputs.get(command[-1])

    macos = command_route_lookup(
        ["/sbin/route", "-n", "get"],
        peer_network._MACOS_ROUTE,  # pyright: ignore[reportPrivateUsage]
        run,
        lambda name: name == "utun8",
    )
    linux = command_route_lookup(
        ["ip", "route", "get"],
        peer_network._LINUX_ROUTE,  # pyright: ignore[reportPrivateUsage]
        run,
        lambda _name: False,
    )
    assert macos(ipaddress.ip_address("10.0.0.2")) == RouteInterface("utun8", wireguard=True)
    assert linux(ipaddress.ip_address("10.0.0.3")) == RouteInterface("wg0")
    assert macos(ipaddress.ip_address("10.0.0.4")) is None
    assert macos(ipaddress.ip_address("10.0.0.5")) is None
    assert macos(ipaddress.ip_address("10.0.0.6")) is None
    assert commands[0] == ["/sbin/route", "-n", "get", "10.0.0.2"]


def test_system_lookup_matches_operating_system() -> None:
    assert system_route_lookup("win32") is windows_route_interface
    assert system_route_lookup("darwin") is not system_route_lookup("linux")
    assert system_route_lookup("freebsd")(ipaddress.ip_address("10.0.0.2")) is None


def test_probe_skips_unknown_hosts_and_caches_each_answer() -> None:
    now = 0.0
    calls: list[str] = []
    answers: dict[str, RouteInterface | None] = {
        "10.0.0.2": RouteInterface("tm-tunnel", "WireGuard Tunnel"),
        "10.0.0.3": None,
    }

    def lookup(address: IPAddress) -> RouteInterface | None:
        calls.append(str(address))
        return answers[str(address)]

    probe = PeerNetworkProbe(lookup, ttl=60, clock=lambda: now)
    assert probe.network(None) is None
    assert probe.network("peer.example") is None
    assert probe.network("10.0.0.2") == "wireguard"
    assert probe.network("10.0.0.3") is None
    answers["10.0.0.2"] = RouteInterface("本地连接", "TAP-Windows Adapter V9")
    assert probe.network("10.0.0.2") == "wireguard"
    now = 61.0
    assert probe.network("10.0.0.2") == "n2n"
    assert calls == ["10.0.0.2", "10.0.0.3", "10.0.0.2"]


def test_peers_list_reports_network_for_configured_peers_only(tmp_path: Path) -> None:
    directory_only = NodeId("node_" + "f" * 32)
    poller = PeerServicePoller(configuration(tmp_path, peer()), LOCAL, InMemoryAuditSink())
    probe = PeerNetworkProbe(lambda _address: RouteInterface("tap0"))
    app = FastAPI()
    app.include_router(
        create_peers_router(
            LOCAL,
            Platform.MACOS,
            lambda: "本机",
            poller,
            lambda: LocalServiceMap(node_id=LOCAL),
            cache(node(LOCAL), node(directory_only)),
            probe,
        )
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            response = await client.get("/api/peers")
            peers = PeersView.model_validate_json(response.content).peers
            networks = {str(p.node_id): p.network for p in peers}
            assert networks == {str(LOCAL): None, str(REMOTE): "n2n", str(directory_only): None}
            assert "192.0.2.2" not in response.text

    asyncio.run(scenario())
