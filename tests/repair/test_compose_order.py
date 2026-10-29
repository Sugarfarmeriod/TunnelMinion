"""compose 依赖标签分层、命令顺序和等待容器准备好的测试。"""

from __future__ import annotations

import asyncio

import pytest
from tests.repair.factories import container
from tests.repair.fakes import FakeClock, FakeContainers

from tunnelminion.repair.compose_order import (
    ContainerStep,
    all_at_once_steps,
    container_ready,
    container_steps,
    dependency_layers,
    describe_order,
    ordered_steps,
    parse_depends_on,
    wait_until_ready,
)
from tunnelminion.repair.contracts import ContainerSnapshot

DB = container("a", name="photos-db-1", service="db", running=True)
CACHE = container("b", name="photos-cache-1", service="cache")
WEB = container("c", name="photos-web-1", service="web", depends_on=("db", "cache"))
WORKER = container("d", name="photos-worker-1", service="web", depends_on=("db",))


def names(layers: tuple[tuple[ContainerSnapshot, ...], ...] | None) -> list[list[str]] | None:
    if layers is None:
        return None
    return [[item.name for item in layer] for layer in layers]


@pytest.mark.parametrize(
    ("label", "expected"),
    (
        (None, ()),
        ("", ()),
        ("db:service_started:false,redis:service_healthy:true", ("db", "redis")),
        (" db , ,:x,db:service_started,cache", ("db", "cache")),
    ),
)
def test_parse_depends_on(label: str | None, expected: tuple[str, ...]) -> None:
    assert parse_depends_on(label) == expected


def test_layers_put_dependencies_first_and_group_same_service() -> None:
    assert names(dependency_layers((WEB, WORKER, DB, CACHE))) == [
        ["photos-cache-1", "photos-db-1"],
        ["photos-web-1", "photos-worker-1"],
    ]


def test_dependency_outside_group_is_ignored() -> None:
    lonely = container("e", name="photos-web-1", service="web", depends_on=("elsewhere",))
    assert names(dependency_layers((lonely,))) == [["photos-web-1"]]


@pytest.mark.parametrize(
    "items",
    (
        (
            container("a", service="a", depends_on=("b",)),
            container("b", name="b", service="b", depends_on=("a",)),
        ),
        (container("a", service="a", depends_on=("a",)),),
        (DB, container("e", name="photos-x-1")),
    ),
)
def test_cycle_or_missing_service_label_falls_back(
    items: tuple[ContainerSnapshot, ...],
) -> None:
    assert dependency_layers(items) is None
    assert ordered_steps(items) is None
    steps, ordered = container_steps(items, compose=True)
    assert not ordered and steps == all_at_once_steps(items)


def test_only_stopped_containers_start_in_order() -> None:
    steps = ordered_steps((WEB, DB, CACHE))
    assert steps is not None
    assert steps == (
        ContainerStep(action="start", containers=(CACHE,), wait_ready=True),
        ContainerStep(action="start", containers=(WEB,), wait_ready=False),
    )
    assert describe_order(steps) == "先启动 cache，再启动 web"


def test_all_running_restart_stops_dependents_first_then_starts_in_order() -> None:
    db = DB
    web = WEB.model_copy(update={"running": True})
    cache = CACHE.model_copy(update={"running": True})
    steps, ordered = container_steps((web, db, cache), compose=True)
    assert ordered
    assert [(step.action, step.container_ids, step.wait_ready) for step in steps] == [
        ("stop", (web.container_id,), False),
        ("stop", (cache.container_id, db.container_id), False),
        ("start", (cache.container_id, db.container_id), True),
        ("start", (web.container_id,), False),
    ]
    assert describe_order(steps) == ("先停下 web，再停下 cache、db，再启动 cache、db，再启动 web")


def test_single_container_and_unlabelled_name_use_all_at_once() -> None:
    steps, ordered = container_steps((WEB,), compose=False)
    assert not ordered and [step.action for step in steps] == ["start"]
    running = container("e", running=True)
    assert all_at_once_steps((running, WEB)) == (
        ContainerStep(action="start", containers=(WEB,)),
        ContainerStep(action="restart", containers=(running,)),
    )
    assert describe_order((ContainerStep(action="restart", containers=(running,)),)) == (
        "先重启 photos-web-1"
    )


@pytest.mark.parametrize(
    ("running", "health", "ready"),
    ((False, None, False), (True, None, True), (True, "starting", False), (True, "healthy", True)),
)
def test_container_ready(running: bool, health: str | None, ready: bool) -> None:
    assert container_ready(container(running=running, health=health)) is ready


def test_wait_until_healthy_polls_without_real_sleep() -> None:
    clock = FakeClock()
    runtime = FakeContainers()
    runtime.items = (container(running=True, health="starting"),)
    runtime.responses = [None, ()]

    def turn_healthy() -> None:
        if len(clock.sleeps) == 3:
            runtime.items = (container(running=True, health="healthy"),)

    clock.on_sleep = turn_healthy
    pending = asyncio.run(
        wait_until_ready(
            runtime,
            compose_project="photos",
            container_name=None,
            waiting=(container(),),
            clock=clock,
            sleep=clock.sleep,
        )
    )
    assert pending is None
    assert clock.sleeps == [1, 1, 1]
    assert runtime.queries == [("photos", None)] * 4


def test_wait_until_ready_times_out() -> None:
    clock = FakeClock()
    runtime = FakeContainers()
    runtime.items = (container(running=True, health="unhealthy"),)
    pending = asyncio.run(
        wait_until_ready(
            runtime,
            compose_project="photos",
            container_name=None,
            waiting=(container(),),
            clock=clock,
            sleep=clock.sleep,
            limit=2.5,
        )
    )
    assert pending is not None and pending.health == "unhealthy"
    assert clock.sleeps == [1, 1, 0.5]
