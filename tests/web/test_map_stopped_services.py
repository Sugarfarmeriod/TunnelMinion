"""服务停止后保留稳定身份，所有容器信息均来自替身。"""

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agent.test_service_observation import Clock, FakeAdapter, collection
from tests.repair.factories import container, launch_record
from tests.repair.fakes import RepairHarness
from tests.web.test_service_map import NODE, NOW, ApiClient, Cache, item

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_marks import InMemoryServiceMarkStore, ServiceMark
from tunnelminion.agent.service_observation import (
    DeterministicServiceObserver,
    ServiceObservationSnapshot,
)
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.windows.models import DockerService
from tunnelminion.repair.contracts import PortOwner
from tunnelminion.web.service_map import build_local_service_map, create_service_map_router


def test_stopped_services_keep_keys_and_only_eligible_containers_are_included() -> None:
    inventory = (
        item(container_name="photos", container_running=False),
        item(container_name="cache", container_running=False, port=0),
        item(process_name="python", python_entrypoint="app.py", origin=ProcessOrigin.TERMINAL),
    )
    snapshot = ServiceObservationSnapshot(observed_at=NOW, services=(), inventory=inventory)
    launch = launch_record(service_key="python:app.py@8000", ports=(8000,))
    data = build_local_service_map(NODE, snapshot, {}, launch_records=(launch,))
    by_key = {entry.key: entry for entry in data.services}
    assert set(by_key) == {"docker:photos", "python:app.py@8000"}
    assert by_key["docker:photos"].state == "stopped"
    assert by_key["python:app.py@8000"].state == "running"
    running = snapshot.model_copy(
        update={"inventory": (inventory[0].model_copy(update={"container_running": True}),)}
    )
    assert build_local_service_map(NODE, running, {}).services[0].key == "docker:photos"
    stopped = build_local_service_map(
        NODE, snapshot.model_copy(update={"inventory": ()}), {}, launch_records=(launch,)
    ).services[0]
    assert stopped.key == "python:app.py@8000" and stopped.state == "stopped"
    assert [endpoint.port for endpoint in stopped.endpoints] == [8000]


def test_mine_and_launch_records_survive_disappearance_and_hidden_marks() -> None:
    snapshot = ServiceObservationSnapshot(observed_at=NOW, services=())
    launch = launch_record()
    marks = {"program:site@8080": ServiceMark.MINE, launch.service_key: ServiceMark.HIDDEN}
    data = build_local_service_map(NODE, snapshot, marks, launch_records=(launch,))
    assert [(entry.key, entry.state, entry.tier) for entry in data.services] == [
        ("program:site@8080", "stopped", "show"),
        (launch.service_key, "stopped", "hidden"),
    ]
    for key, kind in (("python:app.py@8000", "python"), ("docker:photos", "docker")):
        entry = build_local_service_map(NODE, snapshot, {key: ServiceMark.MINE}).services[0]
        assert entry.key == key and entry.kind == kind and entry.state == "stopped"
    udp = item(protocol="udp", process_name="server")
    assert (
        build_local_service_map(
            NODE,
            snapshot.model_copy(update={"inventory": (udp,)}),
            {"program:server@8000": ServiceMark.MINE},
        ).services
        == ()
    )


def test_marked_container_without_ports_is_visible_and_unnamed_container_stays_out() -> None:
    container_fact = DockerService(
        container_id="a" * 64, name="photos", image="photos", ports="", status="Exited (0)"
    )
    snapshot = ServiceObservationSnapshot(
        observed_at=NOW, services=(), containers=(container_fact,)
    )
    assert build_local_service_map(NODE, snapshot, {}).services == ()
    entry = build_local_service_map(NODE, snapshot, {"docker:photos": ServiceMark.MINE}).services[0]
    assert entry.state == "stopped" and entry.endpoints == ()
    compose = container_fact.model_copy(
        update={"compose_project": "photos", "status": "Up 1 minute"}
    )
    entry = build_local_service_map(
        NODE,
        snapshot.model_copy(update={"containers": (compose,)}),
        {"docker:compose:photos": ServiceMark.MINE},
    ).services[0]
    assert entry.key == "docker:compose:photos" and entry.state == "running"


def test_route_and_conversation_read_the_same_cached_observation_without_scanning(
    tmp_path: Path,
) -> None:
    h = RepairHarness(tmp_path)
    docker = DockerService(
        container_id="a" * 64,
        name="photos-web-1",
        image="photos",
        ports="",
        status="Exited (1)",
        compose_project="photos",
    )
    clock = Clock(NOW)
    docker_adapter = FakeAdapter(collection(docker))
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(interval_seconds=5),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        docker_adapter,
        clock=clock,
        containers=h.containers,
        launch_records=h.launch_records,
        host=h.host,
    )
    cache = Cache(None)
    app = FastAPI()
    h.launch_records.put(launch_record())
    app.include_router(
        create_service_map_router(
            NODE,
            InMemoryServiceMarkStore(),
            cache.read,
            cache.replace,
            h.launch_records,
        )
    )
    with TestClient(app, base_url="http://127.0.0.1") as test_client:
        client = cast(ApiClient, test_client)
        cache.replace(asyncio.run(observer.observe()))
        queries, host_reads, replaced = len(h.containers.queries), len(h.host.calls), cache.replaced
        body = client.get("/api/services/local").json()
        entries = {entry["key"]: entry for entry in body["services"]}
        assert entries["docker:compose:photos"]["state"] == "stopped"
        assert entries["docker:compose:photos"]["endpoints"][0]["port"] == 8080
        assert entries["python:http.server@8765"]["state"] == "stopped"
        assert cache.snapshot is not None and cache.snapshot.inventory[0].container_id == "a" * 64
        for _ in range(3):
            assert client.get("/api/services/local").json() == body
        conversation = build_local_service_map(
            NODE, cache.read(), {}, launch_records=h.launch_records.list_all()
        )
        assert conversation.model_dump(mode="json") == body
        assert (len(h.containers.queries), len(h.host.calls), cache.replaced) == (
            queries,
            host_reads,
            replaced,
        )
        h.containers.items = (container(running=True),)
        h.host.owners[8765] = PortOwner(pid=1234, process_name="python", matches_launch=True)
        assert client.get("/api/services/local").json() == body
        docker_adapter.value = collection(
            docker.model_copy(update={"status": "Up 1 minute", "ports": "127.0.0.1:8080->80/tcp"})
        )
        clock.value += timedelta(seconds=5)
        cache.replace(asyncio.run(observer.observe()))
        repaired = client.get("/api/services/local").json()
        assert all(entry["state"] == "running" for entry in repaired["services"])
        assert (
            build_local_service_map(
                NODE, cache.read(), {}, launch_records=h.launch_records.list_all()
            ).model_dump(mode="json")
            == repaired
        )
        h.host.owners[8765] = PortOwner(pid=4321, process_name="other", matches_launch=False)
        clock.value += timedelta(seconds=5)
        cache.replace(asyncio.run(observer.observe()))
        blocked = client.get("/api/services/local").json()
        assert (
            next(entry for entry in blocked["services"] if entry["kind"] == "python")["state"]
            == "stopped"
        )
        cache.snapshot = None
        assert client.get("/api/services/local").json()["services"] == []
