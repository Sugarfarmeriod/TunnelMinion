"""两个平台的地图路由、轮询生命周期和网关服务接入。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.test_peer_names import JOINER, TOKEN

from tunnelminion import app as windows
from tunnelminion import macos_app as macos
from tunnelminion.agent.service_observation import (
    DeterministicServiceObserver,
    ServiceObservationSnapshot,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.gateway.contracts import GatewayServices
from tunnelminion.gateway.names import load_node_name, save_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.web.peers import PeerServicePoller, PeersView


def configure(root: Path) -> None:
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        configure_gateway_secret_store(root, GatewaySecretStoreKind.RESTRICTED_FILE),
    )
    service.configure_local(GatewayBindConfig(host="192.0.2.1"))
    service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=JOINER,
                host="192.0.2.2",
                display_name="对端",
                allow_delegation=True,
                allowed_tools=frozenset({"get_node_summary"}),
            ),
            token=TOKEN,
        )
    )


@pytest.mark.parametrize("module", [windows, macos])
def test_local_app_registers_guarded_routes_and_starts_and_stops_poller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: object
) -> None:
    configure(tmp_path)
    events: list[str] = []

    @asynccontextmanager
    async def base(_app: FastAPI) -> AsyncGenerator[None]:
        yield

    def incident_lifespan(*_args: object) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        return base

    async def run(_self: PeerServicePoller) -> None:
        events.append("started")
        try:
            await asyncio.Event().wait()
        finally:
            events.append("stopped")

    monkeypatch.setattr(module, "incident_observation_lifespan", incident_lifespan)
    monkeypatch.setattr(PeerServicePoller, "run", run)
    bundle = (
        windows.build_windows_application(tmp_path)
        if module is windows
        else macos.build_macos_local_application(tmp_path)
    )
    local_node_id = (
        bundle.node_id if isinstance(bundle, windows.WindowsApplication) else bundle.node.node_id
    )

    async def scenario() -> None:
        async with bundle.app.router.lifespan_context(bundle.app):
            await asyncio.sleep(0)
            assert events == ["started"]
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(bundle.app), base_url="http://127.0.0.1:8765"
            ) as client:
                response = await client.get("/api/peers")
                assert response.status_code == 200
                peers = PeersView.model_validate_json(response.content).peers
                assert peers[0].node_id == local_node_id and peers[0].is_local
                assert peers[1].display_name == "对端" and peers[1].reachable is None
                save_node_name(tmp_path, "新名字")
                updated = PeersView.model_validate_json((await client.get("/api/peers")).content)
                assert updated.peers[0].display_name == "新名字"
                assert (await client.get(f"/api/peers/{JOINER}/services")).status_code == 200
                headers = {"X-TunnelMinion-Request": "same-origin"}
                thread = (await client.post("/api/threads", headers=headers)).json()
                response = await client.post(
                    f"/api/threads/{thread['thread_id']}/runs",
                    headers=headers,
                    json={
                        "question": "看看对端服务",
                        "tool_names": ["get_node_summary"],
                        "about": {"node_id": str(JOINER), "service_key": "missing"},
                    },
                )
                assert response.status_code == 422
                assert "服务不在当前可见清单" in response.json()["detail"]
                assert (
                    await client.get("/api/peers", headers={"Host": "untrusted.example"})
                ).status_code == 403
        assert events == ["started", "stopped"]

    asyncio.run(scenario())


@pytest.mark.parametrize("module", [windows, macos])
def test_gateway_exports_services_with_the_saved_local_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: object
) -> None:
    configure(tmp_path)
    save_node_name(tmp_path, "网关名字")
    calls: list[str] = []

    async def observe(_self: DeterministicServiceObserver) -> ServiceObservationSnapshot:
        calls.append("observed")
        return ServiceObservationSnapshot(observed_at=datetime.now(UTC), services=())

    monkeypatch.setattr(DeterministicServiceObserver, "observe", observe)
    bundle = (
        windows.build_windows_gateway_application(tmp_path)
        if module is windows
        else macos.build_macos_gateway_application(tmp_path)
    )

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(bundle.app), base_url="http://127.0.0.1:8765"
        ) as client:
            assert (await client.get("/v1/services")).status_code == 401
            assert not calls
            response = await client.get(
                "/v1/services", headers={"Authorization": f"Bearer {TOKEN}"}
            )
            assert response.status_code == 200
            value = GatewayServices.model_validate_json(response.content)
            assert value.node_id == bundle.node_id and value.display_name == "网关名字"
            assert load_node_name(tmp_path, Platform.LINUX) == "网关名字"

    asyncio.run(scenario())
    assert calls == ["observed"]
