"""地图对端目录、缓存刷新及轮询生命周期。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.agent.test_remote_service_presentation import cache, node
from tests.gateway.test_configuration import MemorySecrets
from tests.gateway.test_services import LOCAL, REMOTE, TOKEN, services

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
)
from tunnelminion.gateway.contracts import PeerServiceEntry, ServicePort
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.web.peers import (
    PeerCache,
    PeerServicePoller,
    PeerServicesView,
    PeersView,
    create_peers_router,
    peer_services_lifespan,
)
from tunnelminion.web.request_guard import install_local_request_guard
from tunnelminion.web.service_map import LocalServiceMap


def peer(
    identifier: NodeId = REMOTE, name: str | None = None, platform: Platform | None = Platform.MACOS
) -> GatewayPeerConfig:
    return GatewayPeerConfig(
        node_id=identifier,
        display_name=name,
        platform=platform,
        host="192.0.2.2",
        allowed_tools=frozenset({"get_node_summary"}),
    )


def configuration(root: Path, *peers: GatewayPeerConfig) -> GatewayConfigurationService:
    result = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"), MemorySecrets()
    )
    result.configure_local(GatewayBindConfig(host="192.0.2.1"))
    for item in peers:
        result.provision_peer(GatewayPeerInput(peer=item, token=TOKEN))
    return result


def snapshot() -> httpx.Response:
    value = services().model_copy(
        update={
            "services": (
                PeerServiceEntry(
                    key="python:app.py@8080",
                    name="示例服务",
                    kind="python",
                    ports=(ServicePort(port=8080, protocol="tcp"),),
                ),
            )
        }
    )
    return httpx.Response(200, content=value.model_dump_json())


@pytest.mark.parametrize(
    "mode", ["unreachable", "rejected", "forbidden", "error", "timeout", "bad_response"]
)
def test_poller_retains_last_list_and_reports_each_outcome(tmp_path: Path, mode: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1 or (mode == "forbidden" and calls == 4):
            return snapshot()
        if mode == "forbidden" and calls == 3:
            raise httpx.ConnectError("fake", request=request)
        if mode == "unreachable":
            raise httpx.ConnectError("fake", request=request)
        if mode == "timeout":
            raise httpx.ReadTimeout("fake", request=request)
        if mode == "bad_response":
            return httpx.Response(200, text="invalid")
        if mode == "rejected":
            return httpx.Response(
                401, json={"error": {"code": "unauthenticated", "message": "示例失败"}}
            )
        return httpx.Response(
            403 if mode == "forbidden" else 503,
            json={
                "error": {
                    "code": "delegation_not_allowed"
                    if mode == "forbidden"
                    else "delegation_unavailable",
                    "message": "示例失败",
                }
            },
        )

    async def scenario() -> None:
        poller = PeerServicePoller(
            configuration(tmp_path, peer()),
            LOCAL,
            InMemoryAuditSink(),
            transport=httpx.MockTransport(handler),
        )
        assert poller.read(REMOTE).reachable is None
        await poller.refresh()
        first = poller.read(REMOTE)
        assert first.outcome == "ok" and first.reachable is True
        assert first.fetched_at is not None and first.last_seen_at == first.fetched_at
        assert first.snapshot is not None and len(first.snapshot.services) == 1
        await poller.refresh()
        second = poller.read(REMOTE)
        expected = (
            "unreachable"
            if mode in {"unreachable", "timeout"}
            else "error"
            if mode == "bad_response"
            else mode
        )
        assert second.outcome == expected and second.snapshot == first.snapshot
        assert second.fetched_at is not None and second.fetched_at >= first.fetched_at
        if expected in {"unreachable", "rejected"}:
            assert second.reachable is False and second.last_seen_at == first.last_seen_at
        else:
            assert second.reachable is True and second.last_seen_at == second.fetched_at
        if mode == "forbidden":
            assert not second.services_visible
            await poller.refresh()
            assert poller.read(REMOTE).outcome == "unreachable"
            assert not poller.read(REMOTE).services_visible
            await poller.refresh()
            assert poller.read(REMOTE).outcome == "ok" and poller.read(REMOTE).services_visible

    asyncio.run(scenario())
    assert calls == (4 if mode == "forbidden" else 2)
    assert "示例服务" not in (tmp_path / "gateway.json").read_text(encoding="utf-8")


def test_refresh_is_sequential_and_skips_an_inflight_refresh(tmp_path: Path) -> None:
    other = NodeId("node_" + "c" * 32)

    async def scenario() -> None:
        started, finish = asyncio.Event(), asyncio.Event()
        calls: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            started.set()
            await finish.wait()
            identifier = REMOTE if len(calls) == 1 else other
            return httpx.Response(
                200, content=services().model_copy(update={"node_id": identifier}).model_dump_json()
            )

        config = configuration(tmp_path, peer(), peer(other))
        poller = PeerServicePoller(
            config, LOCAL, InMemoryAuditSink(), transport=httpx.MockTransport(handler)
        )
        active = asyncio.create_task(poller.refresh())
        await started.wait()
        await poller.refresh()
        assert len(calls) == 1
        finish.set()
        await active
        assert len(calls) == 2 and poller.read(other).outcome == "ok"
        config.revoke_peer(other)
        await poller.refresh()
        assert poller.read(other).outcome is None

    asyncio.run(scenario())


def test_lifespan_cancels_inflight_request(tmp_path: Path) -> None:
    async def scenario() -> None:
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def handler(_request: httpx.Request) -> httpx.Response:
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
            raise AssertionError("不应完成")

        poller = PeerServicePoller(
            configuration(tmp_path, peer()),
            LOCAL,
            InMemoryAuditSink(),
            transport=httpx.MockTransport(handler),
        )
        app = FastAPI()
        async with poller.lifespan(app):
            await started.wait()
        assert cancelled.is_set() and poller.read(REMOTE).outcome is None

    asyncio.run(scenario())


def test_loop_keeps_running_without_peers_and_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        asleep = asyncio.Event()
        requests: list[httpx.Request] = []

        async def sleep(_seconds: float) -> None:
            asleep.set()
            await asyncio.Event().wait()

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return snapshot()

        monkeypatch.setattr("tunnelminion.web.peers.asyncio.sleep", sleep)
        poller = PeerServicePoller(
            configuration(tmp_path, peer()),
            LOCAL,
            InMemoryAuditSink(),
            transport=httpx.MockTransport(handler),
        )
        poller.configuration.revoke_peer(REMOTE)
        async with poller.lifespan(FastAPI()):
            await asleep.wait()
            assert requests == [] and poller.read(REMOTE).outcome is None

    asyncio.run(scenario())


def test_loop_waits_sixty_seconds_and_composes_lifespan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        asleep = asyncio.Event()
        calls: list[object] = []

        async def sleep(seconds: float) -> None:
            calls.append(seconds)
            asleep.set()
            await asyncio.Event().wait()

        @asynccontextmanager
        async def base(_app: FastAPI) -> AsyncGenerator[None]:
            calls.append("start")
            try:
                yield
            finally:
                calls.append("stop")

        monkeypatch.setattr("tunnelminion.web.peers.asyncio.sleep", sleep)
        poller = PeerServicePoller(
            configuration(tmp_path, peer()),
            LOCAL,
            InMemoryAuditSink(),
            transport=httpx.MockTransport(lambda _: snapshot()),
        )
        async with peer_services_lifespan(base, poller)(FastAPI()):
            await asleep.wait()
            assert poller.read(REMOTE).outcome == "ok"
        assert calls == ["start", 60, "stop"]

    asyncio.run(scenario())


def test_poller_bounds_transport_and_handles_local_configuration_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        async def timeout() -> None:
            raise TimeoutError

        class ImmediateTimeout:
            async def __aenter__(self) -> None:
                await timeout()

            async def __aexit__(self, *_args: object) -> None:
                return None

        poller = PeerServicePoller(configuration(tmp_path, peer()), LOCAL, InMemoryAuditSink())

        def immediate_timeout(_seconds: float) -> ImmediateTimeout:
            return ImmediateTimeout()

        with monkeypatch.context() as patch:
            patch.setattr("tunnelminion.web.peers.asyncio.timeout", immediate_timeout)
            await poller.refresh()
        assert poller.read(REMOTE).outcome == "unreachable"

        def missing(_node_id: NodeId) -> tuple[str, str]:
            raise RuntimeError("缺少凭据")

        monkeypatch.setattr(poller.configuration, "resolve_service_peer", missing)
        await poller.refresh()
        assert poller.read(REMOTE).outcome == "error" and poller.read(REMOTE).reachable is False

    asyncio.run(scenario())


def test_local_peers_routes_order_names_merge_directory_and_serve_cache(tmp_path: Path) -> None:
    online = NodeId("node_" + "c" * 32)
    pending = NodeId("node_" + "d" * 32)
    offline = NodeId("node_" + "e" * 32)
    directory_only = NodeId("node_" + "f" * 32)
    config = configuration(
        tmp_path,
        peer(REMOTE, "Z"),
        peer(online, "A"),
        peer(pending, platform=None),
        peer(offline, "B"),
    )
    directory = cache(node(LOCAL), node(REMOTE), node(directory_only))
    value = directory.read()
    assert value is not None
    directory.replace(
        value.model_copy(update={"expires_at": datetime.now(UTC) + timedelta(minutes=1)})
    )
    poller = PeerServicePoller(
        config, LOCAL, InMemoryAuditSink(), transport=httpx.MockTransport(lambda _: snapshot())
    )
    app = FastAPI()
    install_local_request_guard(app)
    app.include_router(
        create_peers_router(
            LOCAL,
            Platform.WINDOWS,
            lambda: "本机",
            poller,
            lambda: LocalServiceMap(node_id=LOCAL),
            directory,
        )
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8765"
        ) as client:
            first = await client.get("/api/peers")
            assert (
                first.status_code == 200
                and "192.0.2.2" not in first.text
                and TOKEN not in first.text
            )
            initial = PeersView.model_validate_json(first.content)
            assert initial.peers[0].is_local
            assert next(p for p in initial.peers if p.node_id == pending).display_name == "电脑"
            assert all(p.reachable is None for p in initial.peers if p.source == "gateway")
            await poller.refresh()
            poller._cache[str(online)] = poller.read(REMOTE)  # pyright: ignore[reportPrivateUsage]
            poller._cache[str(pending)] = PeerCache()  # pyright: ignore[reportPrivateUsage]
            poller._cache[str(offline)] = PeerCache(outcome="unreachable", reachable=False)  # pyright: ignore[reportPrivateUsage]
            response = await client.get("/api/peers")
            peers = PeersView.model_validate_json(response.content).peers
            assert [p.node_id for p in peers] == [
                LOCAL,
                online,
                directory_only,
                REMOTE,
                pending,
                offline,
            ]
            assert len({str(p.node_id) for p in peers}) == len(peers)
            assert next(p for p in peers if p.node_id == directory_only).source == "coordinator"
            saved = await client.get(f"/api/peers/{REMOTE}/services")
            body = PeerServicesView.model_validate_json(saved.content)
            assert body.display_name == "Z"
            assert body.host == "192.0.2.2" and body.outcome == "ok" and len(body.services) == 1
            assert body.fetched_at is not None and body.observed_at is not None
            waiting = PeerServicesView.model_validate_json(
                (await client.get(f"/api/peers/{pending}/services")).content
            )
            assert waiting.outcome is None and not waiting.services
            coordinator = PeerServicesView.model_validate_json(
                (await client.get(f"/api/peers/{directory_only}/services")).content
            )
            assert coordinator.host is None and not coordinator.services
            assert (await client.get("/api/peers/invalid/services")).status_code == 404
            assert (await client.get(f"/api/peers/{LOCAL}/services")).status_code == 404
            assert (
                await client.get("/api/peers", headers={"Host": "untrusted.example"})
            ).status_code == 403
            poller._cache[str(REMOTE)] = PeerCache(  # pyright: ignore[reportPrivateUsage]
                snapshot=poller.read(REMOTE).snapshot,
                outcome="forbidden",
                reachable=True,
                services_visible=False,
            )
            forbidden = PeerServicesView.model_validate_json(
                (await client.get(f"/api/peers/{REMOTE}/services")).content
            )
            assert forbidden.outcome == "forbidden" and not forbidden.services
            final = PeersView.model_validate_json((await client.get("/api/peers")).content)
            remote = next(p for p in final.peers if p.node_id == REMOTE)
            assert not remote.services_visible and remote.service_count == 0
            assert not remote.auth_rejected
            poller._cache[str(REMOTE)] = PeerCache(  # pyright: ignore[reportPrivateUsage]
                outcome="rejected", reachable=False
            )
            rejected = PeersView.model_validate_json((await client.get("/api/peers")).content)
            remote = next(p for p in rejected.peers if p.node_id == REMOTE)
            assert remote.auth_rejected and remote.reachable is False
            directory.replace(
                value.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
            )
            stale = PeersView.model_validate_json((await client.get("/api/peers")).content)
            assert not next(p for p in stale.peers if p.node_id == directory_only).reachable

    asyncio.run(scenario())


def test_platform_fallback_and_unknown_services_without_a_directory(tmp_path: Path) -> None:
    poller = PeerServicePoller(configuration(tmp_path, peer()), LOCAL, InMemoryAuditSink())
    app = FastAPI()
    app.include_router(
        create_peers_router(
            LOCAL,
            Platform.LINUX,
            lambda: "Linux 电脑",
            poller,
            lambda: LocalServiceMap(node_id=LOCAL),
        )
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1"
        ) as client:
            peers = PeersView.model_validate_json((await client.get("/api/peers")).content).peers
            assert peers[1].display_name == "Mac"
            assert (await client.get("/api/peers/invalid/services")).status_code == 404

    asyncio.run(scenario())


def test_local_computer_configured_as_a_peer_is_not_listed_or_polled(tmp_path: Path) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return snapshot()

    poller = PeerServicePoller(
        configuration(tmp_path, peer(LOCAL, "自己"), peer(REMOTE, "对端")),
        LOCAL,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
    )
    app = FastAPI()
    install_local_request_guard(app)
    app.include_router(
        create_peers_router(
            LOCAL, Platform.WINDOWS, lambda: "本机", poller, lambda: LocalServiceMap(node_id=LOCAL)
        )
    )

    async def scenario() -> None:
        await poller.refresh()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8765"
        ) as client:
            peers = PeersView.model_validate_json((await client.get("/api/peers")).content).peers
            assert [p.node_id for p in peers] == [LOCAL, REMOTE]
            assert peers[0].is_local and peers[0].display_name == "本机"
            assert (await client.get(f"/api/peers/{LOCAL}/services")).status_code == 404
            repair = f"/api/peers/{LOCAL}/repairs/op_{'a' * 32}/approve"
            assert (await client.post(repair)).status_code == 404

    asyncio.run(scenario())
    assert calls == 1
