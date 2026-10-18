"""预览入口只读采集、保留调查和禁用后台执行的组装回归。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.incident.test_snapshot_and_storage import (
    _changed_pair,  # pyright: ignore[reportPrivateUsage]
)
from tests.test_app import configured_managed_application, local_service

from tunnelminion.agent.managed_application import ManagedNodeApplication
from tunnelminion.agent.service_observation import ServiceObservationSnapshot
from tunnelminion.app import build_windows_application
from tunnelminion.domain.identifiers import NodeId, RunId
from tunnelminion.domain.tools import Platform
from tunnelminion.incident.contracts import IncidentStatus
from tunnelminion.incident.observer import IncidentObservationService
from tunnelminion.incident.snapshot import SnapshotDiffDetector
from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.model.configuration import ModelConfigurationService


@pytest.mark.parametrize("platform", ["windows", "macos"])
@pytest.mark.parametrize("configuration", ["local", "managed", "peer"])
def test_preview_refreshes_inventory_without_investigation_or_managed_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, configuration: str
) -> None:
    module = "tunnelminion.app" if platform == "windows" else "tunnelminion.macos_app"
    root = tmp_path / "preview"
    store = SQLiteIncidentStore(root / "incidents.sqlite3")
    baseline, current = _changed_pair()
    store.put_snapshot(baseline)
    store.put_snapshot(current)
    event = SnapshotDiffDetector(confirmations_required=1).compare(baseline, current)[0]
    original = store.record_event(event).transition(
        IncidentStatus.INVESTIGATING,
        at=current.observed_at + timedelta(seconds=1),
        run_id=RunId.new(),
    )
    store.put_incident(original)
    services = [local_service(f"service_{'a' * 32}", 18081)]
    observer: IncidentObservationService | None = None

    async def observe(_self: object) -> ServiceObservationSnapshot:
        return ServiceObservationSnapshot(observed_at=datetime.now(UTC), services=tuple(services))

    def forbidden_model(_self: ModelConfigurationService) -> None:
        raise AssertionError("预览不得创建模型提供者")

    async def forbidden_remote(_self: object) -> None:
        raise AssertionError("预览不得发起远端观察")

    @asynccontextmanager
    async def forbidden_managed(_app: object) -> AsyncGenerator[None, None]:
        raise AssertionError("预览不得启动托管后台任务")
        yield

    def managed_lifespan(
        _managed: ManagedNodeApplication,
    ) -> Callable[[object], AbstractAsyncContextManager[None]]:
        return forbidden_managed

    def capture(*args: object, **kwargs: object) -> IncidentObservationService:
        nonlocal observer
        kwargs["interval_seconds"] = 3600
        observer = IncidentObservationService(*args, **kwargs)  # pyright: ignore[reportArgumentType]
        return observer

    monkeypatch.setattr(f"{module}.IncidentObservationService", capture)
    monkeypatch.setattr(f"{module}.managed_application_lifespan", managed_lifespan)
    monkeypatch.setattr(ModelConfigurationService, "create_provider", forbidden_model)
    monkeypatch.setattr(f"{module}.DeterministicServiceObserver.observe", observe)
    monkeypatch.setattr(f"{module}.StaticPeerServiceObserver.refresh", forbidden_remote)
    monkeypatch.setattr(
        f"{module}.RemoteServicePresentationObserver.refresh",
        forbidden_remote,
    )
    if configuration == "managed":

        def managed_fixture(
            _root: Path, node_id: NodeId, platform: Platform, *_args: object, **_kwargs: object
        ) -> ManagedNodeApplication:
            return configured_managed_application(node_id, platform)

        monkeypatch.setattr(
            f"{module}.build_managed_node_application",
            managed_fixture,
        )
    elif configuration == "peer":
        (root / "peer-observation.json").write_text(
            f'{{"enabled": true, "node_id": "{NodeId.new()}", "port": 43123}}', encoding="utf-8"
        )
    bundle = (
        build_windows_application(root, read_only_preview=True)
        if platform == "windows"
        else build_macos_local_application(root, read_only_preview=True)
    )
    client: Any
    with TestClient(bundle.app, base_url="http://127.0.0.1") as client:
        assert observer is not None
        assert observer.read_only_preview
        assert store.get(original.incident_id) == original
        overview = client.get("/api/ui/overview").json()
        local = [
            item for item in overview["services"]["items"] if item["source"] == "local_observation"
        ]
        assert [item["port"] for item in local] == [18081]
        if configuration == "peer":
            remote = [item for item in overview["services"]["items"] if item["port"] == 43123]
            assert len(remote) == 1 and remote[0]["state"] == "unknown"
        services.append(local_service(f"service_{'b' * 32}", 18082))
        for _ in range(3):
            assert asyncio.run(observer.observe_once()).incidents == ()
        assert store.latest_snapshot() == current
        assert store.list_recent() == (original,)
        assert client.get("/api/threads").json() == []
        for path in ("/api/threads", "/api/model-config/validate", "/api/operations"):
            response = client.post(path)
            assert response.status_code == 403
            assert response.json()["detail"]["code"] == "read_only_preview"
        assert client.get("/api/operations/example/access/").status_code == 403
