"""停服事实在后台补齐，请求只消费观察快照。"""

import asyncio
import threading
from datetime import timedelta

import pytest
from tests.agent.test_service_observation import Clock, FakeAdapter, collection
from tests.repair.factories import NODE, container, launch_agent_record, launch_record
from tests.repair.fakes import (
    FakeContainers,
    FakeHost,
    FakeLaunchAgents,
    MemoryLaunchRecordStore,
)

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_marks import ServiceMark
from tunnelminion.agent.service_observation import DeterministicServiceObserver
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.platforms.windows.models import DockerService, NetworkListener
from tunnelminion.repair.contracts import (
    ContainerSnapshot,
    PortOwner,
    ProcessLaunchRecord,
    ProgramLaunchRecord,
    RepairCommand,
    WindowsServiceRecord,
)
from tunnelminion.web.service_map import build_local_service_map


def docker_fact(suffix: str = "a", **values: str) -> DockerService:
    return DockerService.model_validate(
        {
            "container_id": suffix * 64,
            "name": "photos-web-1",
            "image": "photos",
            "ports": "",
            "status": "Exited (1)",
            "compose_project": "photos",
            **values,
        }
    )


def test_stopped_container_ports_are_cached_by_id_and_replaced_on_recreation() -> None:
    runtime = FakeContainers()
    adapter = FakeAdapter(collection(docker_fact()))
    clock = Clock()
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        adapter,
        clock=clock,
        containers=runtime,
    )
    first = asyncio.run(observer.observe())
    assert first.inventory[0].port == 8080 and first.inventory[0].container_running is False
    assert len(runtime.queries) == 1
    clock.value += timedelta(seconds=30)
    cached = asyncio.run(observer.observe())
    assert cached.inventory == first.inventory and len(runtime.queries) == 1
    adapter.value = collection(docker_fact("b"))
    runtime.items = (container("b", ports=(9090,)),)
    clock.value += timedelta(seconds=30)
    recreated = asyncio.run(observer.observe())
    assert recreated.inventory[0].port == 9090 and len(runtime.queries) == 2
    assert [entry.key for entry in build_local_service_map(NODE, first, {}).services] == [
        entry.key for entry in build_local_service_map(NODE, recreated, {}).services
    ]
    adapter.value = collection(docker_fact("b", status="Up", ports="127.0.0.1:9090->80/tcp"))
    clock.value += timedelta(seconds=30)
    running = asyncio.run(observer.observe())
    assert running.inventory[0].container_running is True and len(runtime.queries) == 2


@pytest.mark.parametrize("details", [None, (), (container("b"),), (container(ports=()),)])
def test_unavailable_missing_and_unshown_containers_do_not_get_fake_ports(
    details: tuple[ContainerSnapshot, ...] | None,
) -> None:
    runtime = FakeContainers()
    runtime.items = details
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        FakeAdapter(collection(docker_fact())),
        containers=runtime,
    )
    snapshot = asyncio.run(observer.observe())
    assert snapshot.inventory == ()
    assert build_local_service_map(NODE, snapshot, {}).services == ()


def test_published_stopped_container_and_running_container_skip_inspect() -> None:
    runtime = FakeContainers()
    adapter = FakeAdapter(
        collection(
            docker_fact(ports="127.0.0.1:8080->80/tcp"), docker_fact("b", name="cache", status="Up")
        )
    )
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        adapter,
        containers=runtime,
    )
    snapshot = asyncio.run(observer.observe())
    assert snapshot.inventory[0].container_running is False and not runtime.queries


def test_invalid_container_name_is_skipped_without_failing_the_snapshot() -> None:
    class NameCheckingRuntime(FakeContainers):
        async def list_containers(
            self, *, compose_project: str | None, container_name: str | None
        ) -> tuple[ContainerSnapshot, ...] | None:
            if container_name == "bad/name":
                raise ValueError("项目或容器名无效")
            return await super().list_containers(
                compose_project=compose_project, container_name=container_name
            )

    runtime = NameCheckingRuntime()
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        FakeAdapter(
            collection(docker_fact("b", name="bad/name", compose_project="invalid"), docker_fact())
        ),
        containers=runtime,
    )
    snapshot = asyncio.run(observer.observe())
    assert snapshot.complete and len(snapshot.inventory) == 1
    assert build_local_service_map(NODE, snapshot, {}).services[0].key == "docker:compose:photos"


@pytest.mark.parametrize("source", ["docker", "host"])
@pytest.mark.parametrize("failure", ["exception", "timeout"])
def test_repair_checks_are_best_effort_and_keep_cached_ports(source: str, failure: str) -> None:
    failing = False
    release = threading.Event()

    class Runtime(FakeContainers):
        async def list_containers(
            self, *, compose_project: str | None, container_name: str | None
        ) -> tuple[ContainerSnapshot, ...] | None:
            if failing and source == "docker":
                if failure == "exception":
                    raise RuntimeError("fake unavailable")
                await asyncio.Event().wait()
            return await super().list_containers(
                compose_project=compose_project, container_name=container_name
            )

    class Host(FakeHost):
        def port_owner(
            self, port: int, launch: ProcessLaunchRecord | None = None
        ) -> PortOwner | None:
            if failing and source == "host":
                if failure == "exception":
                    raise RuntimeError("fake unavailable")
                release.wait(timeout=2)
            return super().port_owner(port, launch)

    runtime, host, records, clock = Runtime(), Host(), MemoryLaunchRecordStore(), Clock()
    launch = launch_record()
    records.put(launch)
    host.owners[8765] = PortOwner(pid=101, process_name="python", matches_launch=True)
    docker = FakeAdapter(collection(docker_fact()))
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(timeout_seconds=0.1),
        FakeAdapter(collection(NetworkListener(protocol="tcp", address="127.0.0.1", port=9000))),
        FakeAdapter(collection()),
        docker,
        clock=clock,
        containers=runtime,
        launch_records=records,
        host=host,
    )

    async def scenario() -> None:
        nonlocal failing
        first = await observer.observe()
        assert {item.port for item in first.inventory} == {9000, 8080}
        assert first.running_launch_keys == frozenset({launch.service_key})
        docker.value = collection(docker_fact(), docker_fact("b", name="photos-web-2"))
        clock.value += timedelta(seconds=30)
        failing = True
        try:
            snapshot = await observer.observe()
        finally:
            release.set()
        assert snapshot.complete and observer.last_snapshot is snapshot
        assert {item.port for item in snapshot.inventory} == {9000}
        assert not snapshot.running_launch_keys
        assert observer.status.last_success_at == clock.value
        assert observer.status.last_error_code is None
        failing = False
        runtime.items = (container("b", name="photos-web-2", ports=(9090,)),)
        clock.value += timedelta(seconds=30)
        recovered = await observer.observe()
        assert {item.port for item in recovered.inventory} == {9000, 8080, 9090}
        assert recovered.running_launch_keys == first.running_launch_keys
        assert runtime.queries.count((None, "photos-web-1")) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("with_records", [False, True])
@pytest.mark.parametrize("with_host", [False, True])
def test_launch_running_check_is_background_only_and_uses_matching_identity(
    with_records: bool, with_host: bool
) -> None:
    caller = threading.get_ident()

    class Host(FakeHost):
        def port_owner(
            self, port: int, launch: ProcessLaunchRecord | None = None
        ) -> PortOwner | None:
            assert threading.get_ident() != caller
            return super().port_owner(port, launch)

    records = MemoryLaunchRecordStore()
    launch = launch_record(ports=(8765, 8766, 8767))
    records.put(launch)
    host = Host()
    host.owners[8766] = PortOwner(pid=100, process_name="other", matches_launch=False)
    host.owners[8767] = PortOwner(pid=101, process_name="python", matches_launch=True)
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        launch_records=records if with_records else None,
        host=host if with_host else None,
    )
    snapshot = asyncio.run(observer.observe())
    assert snapshot.running_launch_keys == (
        frozenset({launch.service_key}) if with_records and with_host else frozenset()
    )
    assert "running_launch_keys" not in snapshot.model_dump(mode="json")
    assert build_local_service_map(NODE, snapshot, {}, launch_records=records.list_all()).services[
        0
    ].state == ("running" if with_records and with_host else "stopped")


@pytest.mark.parametrize("case", ["tagged", "error", "none"])
def test_launch_agent_ports_get_label_identity_and_stopped_entries(case: str) -> None:
    agents = FakeLaunchAgents()
    agents.labels = {300: "local.photos.web"} if case != "none" else {}
    agents.error_on_labels = case == "error"
    records = MemoryLaunchRecordStore()
    records.put(launch_agent_record())
    records.put(launch_agent_record("local.gone", ports=(9100,)))
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(
            collection(
                NetworkListener(
                    protocol="tcp",
                    address="127.0.0.1",
                    port=8765,
                    pid=300,
                    process_name="python3",
                    python_entrypoint="http.server",
                    origin=ProcessOrigin.USER_INSTALL,
                ),
                NetworkListener(
                    protocol="tcp",
                    address="127.0.0.1",
                    port=9000,
                    pid=301,
                    process_name="node",
                    origin=ProcessOrigin.USER_INSTALL,
                ),
            )
        ),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        launch_records=records,
        host=FakeHost(),
        launch_agents=agents,
    )
    snapshot = asyncio.run(observer.observe())
    labels = [item.launch_agent_label for item in snapshot.inventory]
    services = {
        entry.key: entry
        for entry in build_local_service_map(
            NODE, snapshot, {}, launch_records=records.list_all()
        ).services
    }
    gone = services["launchd:local.gone"]
    assert gone.state == "stopped" and gone.launch_agent and gone.kind == "program"
    assert gone.name == "local.gone"
    if case != "tagged":
        assert labels == [None, None]
        assert services["launchd:local.photos.web"].state == "stopped"
        assert "python:http.server@8765" in services
        return
    assert labels == ["local.photos.web", None]
    assert snapshot.running_launch_keys == frozenset({"launchd:local.photos.web"})
    photos = services["launchd:local.photos.web"]
    assert photos.state == "running" and photos.launch_agent and photos.kind == "program"
    assert photos.name == "local.photos.web" and photos.tier == "show"
    assert not services["program:node@9000"].launch_agent
    assert "local.photos.web · 8765" in snapshot.display_names.values()


class FakeWindowsTagger:
    """只认进程号到服务名的 Windows 服务替身。"""

    def __init__(self, names: dict[int, str], *, error: bool = False) -> None:
        self.names = names
        self.error = error

    def unsupported_reason(self) -> str | None:
        return None

    def services_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        if self.error:
            raise OSError("scm")
        return {pid: name for pid, name in self.names.items() if pid in pids}

    def inspect(self, name: str) -> None:
        return None

    async def set_granted(self, name: str, *, granted: bool) -> bool:
        return False

    async def start(self, name: str) -> RepairCommand:
        raise ValueError(name)

    async def stop(self, name: str) -> RepairCommand:
        raise ValueError(name)


@pytest.mark.parametrize("case", ["tagged", "error", "none"])
def test_windows_service_ports_are_tagged_and_records_show_when_stopped(case: str) -> None:
    records = MemoryLaunchRecordStore()
    records.put(
        WindowsServiceRecord(
            service_key="program:sunshine@47984",
            service_name="SunshineService",
            ports=(47984,),
            rule_shown=False,
            recorded_at=launch_record().recorded_at,
        )
    )
    records.put(
        WindowsServiceRecord(
            service_key="program:gone@9100",
            service_name="GoneService",
            ports=(9100,),
            rule_shown=False,
            recorded_at=launch_record().recorded_at,
        )
    )
    records.put(
        ProgramLaunchRecord(
            service_key="program:gost@805",
            executable="/opt/gost",
            executable_size=1,
            executable_mtime_ns=1,
            working_directory="/home/me",
            username="me",
            ports=(805,),
            rule_shown=True,
            process_id=9,
            process_started_at=launch_record().process_started_at,
            recorded_at=launch_record().recorded_at,
        )
    )
    observer = DeterministicServiceObserver(
        NODE,
        ServiceObservationConfig(),
        FakeAdapter(
            collection(
                NetworkListener(
                    protocol="tcp",
                    address="0.0.0.0",
                    port=47984,
                    pid=400,
                    process_name="sunshine.exe",
                    origin=ProcessOrigin.APP_SERVICE,
                )
            )
        ),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        launch_records=records,
        host=FakeHost(),
        windows_services=FakeWindowsTagger(
            {400: "SunshineService"} if case != "none" else {}, error=case == "error"
        ),
    )
    snapshot = asyncio.run(observer.observe())
    services = {
        entry.key: entry
        for entry in build_local_service_map(
            NODE,
            snapshot,
            {"program:sunshine@47984": ServiceMark.MINE},
            launch_records=records.list_all(),
        ).services
    }
    gone, gost = services["program:gone@9100"], services["program:gost@805"]
    assert gone.state == "stopped" and gone.windows_service and gone.kind == "program"
    assert gost.state == "stopped" and not gost.windows_service and gost.name == "gost"
    sunshine = services["program:sunshine@47984"]
    if case != "tagged":
        assert [item.windows_service_name for item in snapshot.inventory] == [None]
        assert not sunshine.windows_service
        return
    assert [item.windows_service_name for item in snapshot.inventory] == ["SunshineService"]
    assert snapshot.running_launch_keys == frozenset({"program:sunshine@47984"})
    assert sunshine.windows_service and sunshine.state == "running"
