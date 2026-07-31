"""本机确定性服务观察、完整性与预算测试。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from pydantic import BaseModel, JsonValue

from tunnelminion.agent.managed_node import ServiceObservationConfig
from tunnelminion.agent.service_observation import (
    DeterministicServiceObserver,
    ServiceObservationError,
)
from tunnelminion.coordinator.contracts import ServiceAccessibility, ServiceProtocol
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.platforms.windows.models import (
    Availability,
    CollectionResult,
    DockerService,
    NetworkListener,
    ProcessInfo,
)
from tunnelminion.tools.contracts import ToolCancellationToken

NOW = datetime(2026, 7, 31, tzinfo=UTC)


class Clock:
    """可推进的确定性时钟。"""

    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class FakeAdapter:
    """返回结构化集合或受控失败的只读适配器。"""

    def __init__(
        self,
        value: JsonValue,
        *,
        error: BaseException | None = None,
        wait: asyncio.Event | None = None,
    ) -> None:
        self.value = value
        self.error = error
        self.wait = wait
        self.calls: list[dict[str, JsonValue]] = []

    async def execute(
        self,
        arguments: dict[str, JsonValue],
        cancellation: ToolCancellationToken,
    ) -> JsonValue:
        assert not cancellation.cancelled
        self.calls.append(arguments)
        if self.wait is not None:
            await self.wait.wait()
        if self.error is not None:
            raise self.error
        return self.value


def collection(
    *items: BaseModel,
    availability: Availability = Availability.AVAILABLE,
) -> JsonValue:
    """构造平台适配器标准集合结果。"""
    return cast(
        JsonValue,
        CollectionResult(
            availability=availability,
            items=tuple(cast(dict[str, object], item.model_dump(mode="json")) for item in items),
        ).model_dump(mode="json"),
    )


def observer(
    listeners: FakeAdapter,
    processes: FakeAdapter,
    docker: FakeAdapter,
    *,
    clock: Clock | None = None,
    **config: object,
) -> DeterministicServiceObserver:
    values: dict[str, object] = {
        "interval_seconds": 5,
        "timeout_seconds": 1,
    }
    values.update(config)
    return DeterministicServiceObserver(
        NodeId("node_0123456789abcdef0123456789abcdef"),
        ServiceObservationConfig.model_validate(values),
        listeners,
        processes,
        docker,
        clock=clock or Clock(),
    )


def test_observation_merges_listener_process_docker_udp_and_dual_stack() -> None:
    listeners = FakeAdapter(
        collection(
            NetworkListener(protocol="tcp", address="0.0.0.0", port=8080, pid=7),
            NetworkListener(protocol="tcp", address="::", port=8080, pid=7),
            NetworkListener(protocol="udp", address="127.0.0.1", port=5353),
        )
    )
    processes = FakeAdapter(collection(ProcessInfo(pid=7, name="safe-name")))
    docker = FakeAdapter(
        collection(
            DockerService(
                container_id="container",
                name="web",
                image="image",
                ports="0.0.0.0:8080->80/tcp",
                status="Up",
            )
        )
    )
    value = observer(listeners, processes, docker)
    assert value.interval_seconds == 5

    snapshot = asyncio.run(value.observe())

    assert snapshot.complete
    assert len(snapshot.services) == 2
    tcp = next(item for item in snapshot.services if item.protocol is ServiceProtocol.TCP)
    udp = next(item for item in snapshot.services if item.protocol is ServiceProtocol.UDP)
    assert tcp.protocol is ServiceProtocol.TCP
    assert tcp.accessibility is ServiceAccessibility.NETWORK
    assert tcp.confidence == 0.95
    assert udp.protocol is ServiceProtocol.UDP
    assert udp.accessibility is ServiceAccessibility.LOOPBACK
    assert "safe-name" not in snapshot.model_dump_json()
    assert value.status.service_count == 2
    assert processes.calls == [{"limit": 1024}]


def test_docker_failure_is_degraded_but_listener_snapshot_is_complete() -> None:
    listeners = FakeAdapter(
        collection(NetworkListener(protocol="tcp", address="10.77.0.2", port=8787))
    )
    processes = FakeAdapter(collection())
    docker = FakeAdapter(collection(), error=RuntimeError("docker secret output"))
    value = observer(listeners, processes, docker)

    snapshot = asyncio.run(value.observe())

    assert len(snapshot.services) == 1
    assert snapshot.degraded_sources == ("list_docker_services",)
    assert "secret" not in snapshot.model_dump_json()
    assert value.status.last_error_code is None


def test_disabled_sources_do_not_execute_and_active_probe_defaults_off() -> None:
    listeners = FakeAdapter(collection())
    processes = FakeAdapter(collection())
    docker = FakeAdapter(collection())
    value = observer(
        listeners,
        processes,
        docker,
        listeners_enabled=False,
        processes_enabled=False,
        docker_enabled=False,
    )

    snapshot = asyncio.run(value.observe())

    assert not listeners.calls and not processes.calls and not docker.calls
    assert snapshot.degraded_sources == ()
    assert snapshot.disabled_sources == (
        "list_network_listeners",
        "get_process_summary",
        "list_docker_services",
        "active_probe",
    )


def test_service_disappearance_replaces_complete_snapshot_and_ids_are_stable() -> None:
    clock = Clock()
    listeners = FakeAdapter(
        collection(NetworkListener(protocol="tcp", address="10.77.0.2", port=8787))
    )
    value = observer(listeners, FakeAdapter(collection()), FakeAdapter(collection()), clock=clock)
    first = asyncio.run(value.observe())
    same = observer(
        FakeAdapter(collection(NetworkListener(protocol="tcp", address="10.77.0.2", port=8787))),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
    )
    assert asyncio.run(same.observe()).services[0].service_id == first.services[0].service_id
    with pytest.raises(ServiceObservationError, match="频繁") as limited:
        asyncio.run(value.observe())
    assert limited.value.code == "refresh_limited"
    listeners.value = collection()
    clock.value += timedelta(seconds=5)

    second = asyncio.run(value.observe())

    assert second.services == ()
    assert value.last_snapshot == second


def test_failure_timeout_and_budgets_keep_last_complete_snapshot() -> None:
    clock = Clock()
    listeners = FakeAdapter(
        collection(NetworkListener(protocol="tcp", address="10.77.0.2", port=8000))
    )
    value = observer(listeners, FakeAdapter(collection()), FakeAdapter(collection()), clock=clock)
    first = asyncio.run(value.observe())
    clock.value += timedelta(seconds=5)
    listeners.error = PermissionError("sensitive path")
    with pytest.raises(ServiceObservationError) as failed:
        asyncio.run(value.observe())
    assert failed.value.code == "observation_failed"
    assert value.last_snapshot == first
    assert "sensitive" not in value.status.model_dump_json()

    many = tuple(
        NetworkListener(protocol="tcp", address="10.77.0.2", port=9000 + index)
        for index in range(2)
    )
    oversized = observer(
        FakeAdapter(collection(*many)),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        max_services=1,
    )
    with pytest.raises(ServiceObservationError) as count_error:
        asyncio.run(oversized.observe())
    assert count_error.value.code == "snapshot_too_large"

    byte_heavy = tuple(
        NetworkListener(protocol="tcp", address=f"10.77.0.{index + 1}", port=9100 + index)
        for index in range(10)
    )
    bytes_observer = observer(
        FakeAdapter(collection(*byte_heavy)),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        max_snapshot_bytes=1024,
    )
    with pytest.raises(ServiceObservationError) as byte_error:
        asyncio.run(bytes_observer.observe())
    assert byte_error.value.code == "snapshot_too_large"


def test_timeout_concurrency_cancellation_and_invalid_clock_fail_closed() -> None:
    async def concurrency_scenario() -> None:
        release = asyncio.Event()
        listeners = FakeAdapter(collection(), wait=release)
        value = observer(listeners, FakeAdapter(collection()), FakeAdapter(collection()))
        running = asyncio.create_task(value.observe())
        await asyncio.sleep(0)
        with pytest.raises(ServiceObservationError) as limited:
            await value.observe()
        assert limited.value.code == "concurrency_limited"
        release.set()
        await running

    asyncio.run(concurrency_scenario())

    slow = observer(
        FakeAdapter(collection(), wait=asyncio.Event()),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        timeout_seconds=0.001,
    )
    with pytest.raises(ServiceObservationError) as timeout:
        asyncio.run(slow.observe())
    assert timeout.value.code == "observation_timeout"

    cancelled = observer(
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        FakeAdapter(collection(), error=asyncio.CancelledError()),
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled.observe())

    invalid = observer(
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        FakeAdapter(collection()),
        clock=Clock(datetime(2026, 7, 31)),
    )
    with pytest.raises(ServiceObservationError) as clock_error:
        asyncio.run(invalid.observe())
    assert clock_error.value.code == "invalid_clock"
