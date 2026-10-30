"""按 compose 写在容器上的依赖标签排出启动和重启顺序；不读、不改 compose 文件。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from tunnelminion.repair.contracts import ContainerRuntime, ContainerSnapshot

# 每一层容器准备好的最长等待时间；等不到就按执行失败收场。
COMPOSE_READY_SECONDS = 60.0

ContainerAction = Literal["start", "restart", "stop"]


@dataclass(frozen=True)
class ContainerStep:
    """一条固定的 Docker 命令：对哪些容器做什么，以及之后要不要等它们准备好。"""

    action: ContainerAction
    containers: tuple[ContainerSnapshot, ...]
    wait_ready: bool = False

    @property
    def container_ids(self) -> tuple[str, ...]:
        return tuple(item.container_id for item in self.containers)


def parse_depends_on(label: str | None) -> tuple[str, ...]:
    """解析 `com.docker.compose.depends_on`，例如 `db:service_started:false,redis:...`。

    逗号分隔，每项冒号分隔的第一段是服务名；空项跳过，重复的只留一个。
    """
    names: list[str] = []
    for entry in (label or "").split(","):
        name = entry.split(":", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return tuple(names)


def dependency_layers(
    items: tuple[ContainerSnapshot, ...],
) -> tuple[tuple[ContainerSnapshot, ...], ...] | None:
    """把组内容器按依赖分层，被依赖的在前。

    依赖指向组外或不存在的服务名时忽略那条边；有容器读不出服务名或依赖成环时返回 None，
    调用方退回一次全部启动或重启。
    """
    services: dict[str, list[ContainerSnapshot]] = {}
    for item in items:
        if item.compose_service is None:
            return None
        services.setdefault(item.compose_service, []).append(item)
    needs = {
        name: {
            dependency
            for member in members
            for dependency in member.depends_on
            if dependency in services
        }
        for name, members in services.items()
    }
    layers: list[tuple[ContainerSnapshot, ...]] = []
    placed: set[str] = set()
    while len(placed) < len(services):
        ready = sorted(name for name in services if name not in placed and needs[name] <= placed)
        if not ready:
            return None
        placed.update(ready)
        layers.append(
            tuple(
                sorted(
                    (member for name in ready for member in services[name]),
                    key=lambda value: value.name,
                )
            )
        )
    return tuple(layers)


def all_at_once_steps(items: tuple[ContainerSnapshot, ...]) -> tuple[ContainerStep, ...]:
    """不排顺序：没在跑的一次全部启动，在跑的一次全部重启。"""
    steps: list[ContainerStep] = []
    pairs: tuple[tuple[bool, ContainerAction], ...] = ((False, "start"), (True, "restart"))
    for running, action in pairs:
        members = tuple(item for item in items if item.running is running)
        if members:
            steps.append(ContainerStep(action=action, containers=members))
    return tuple(steps)


def ordered_steps(items: tuple[ContainerSnapshot, ...]) -> tuple[ContainerStep, ...] | None:
    """按依赖顺序生成命令；排不出顺序时返回 None。

    组里有停掉的容器时，只按顺序启动停掉的那些，在跑的不动；全在跑时整组先按反向顺序停下，
    再按正向顺序启动。每一步启动后等容器准备好再进行下一步，最后一步交给验证。
    """
    layers = dependency_layers(items)
    if layers is None:
        return None
    steps: list[ContainerStep] = []
    if any(not item.running for item in items):
        starts = [tuple(item for item in layer if not item.running) for layer in layers]
    else:
        steps.extend(ContainerStep(action="stop", containers=layer) for layer in reversed(layers))
        starts = list(layers)
    starts = [layer for layer in starts if layer]
    steps.extend(
        ContainerStep(action="start", containers=layer, wait_ready=index < len(starts) - 1)
        for index, layer in enumerate(starts)
    )
    return tuple(steps)


def container_steps(
    items: tuple[ContainerSnapshot, ...], *, compose: bool
) -> tuple[tuple[ContainerStep, ...], bool]:
    """返回要执行的命令，以及是否按依赖顺序；单个容器和排不出顺序的组一次全部处理。"""
    ordered = ordered_steps(items) if compose else None
    if ordered is None:
        return all_at_once_steps(items), False
    return ordered, True


def describe_order(steps: tuple[ContainerStep, ...]) -> str:
    """把按依赖顺序的命令写成给主人看的一句话，例如“先启动 db，再启动 web”。"""
    verbs = {"start": "启动", "restart": "重启", "stop": "停下"}
    parts: list[str] = []
    for index, step in enumerate(steps):
        names = "、".join(
            dict.fromkeys(item.compose_service or item.name for item in step.containers)
        )
        parts.append(f"{'先' if index == 0 else '再'}{verbs[step.action]} {names}")
    return "，".join(parts)


def container_ready(item: ContainerSnapshot) -> bool:
    """容器在运行；有健康检查的还要已经健康。"""
    return item.running and (item.health is None or item.health == "healthy")


async def wait_until_ready(
    runtime: ContainerRuntime,
    *,
    compose_project: str | None,
    container_name: str | None,
    waiting: tuple[ContainerSnapshot, ...],
    clock: Callable[[], datetime],
    sleep: Callable[[float], Awaitable[None]],
    limit: float = COMPOSE_READY_SECONDS,
) -> ContainerSnapshot | None:
    """反复只读查询，直到这些容器都准备好；超时返回最后看到的一个没准备好的容器。"""
    started = clock()
    elapsed = 0.0
    while True:
        observed = await runtime.list_containers(
            compose_project=compose_project, container_name=container_name
        )
        by_id = {item.container_id: item for item in observed or ()}
        pending = next(
            (
                by_id.get(item.container_id, item)
                for item in waiting
                if item.container_id not in by_id or not container_ready(by_id[item.container_id])
            ),
            None,
        )
        if pending is None:
            return None
        if elapsed >= limit:
            return pending
        delay = min(1, limit - elapsed)
        await sleep(delay)
        elapsed = max(elapsed + delay, (clock() - started).total_seconds())
