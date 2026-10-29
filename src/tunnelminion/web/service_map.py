"""本机服务清单与"是我的服务 / 隐藏"标记 API，供首页的服务弹出框使用。

清单按服务身份合并端口：同一个 compose 项目、同一个脚本或同一个程序显示成一项。
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.service_marks import (
    ServiceMark,
    ServiceMarkStore,
    is_mark_key,
    service_mark_keys,
)
from tunnelminion.agent.service_observation import (
    ServiceObservationSnapshot,
    apply_service_marks,
    service_presentation,
    service_tier,
)
from tunnelminion.agent.service_tiers import ServiceTier
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceSummary,
    ServiceAccessibility,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.platforms.python_entrypoint import is_python_process
from tunnelminion.repair.contracts import (
    AnyLaunchRecord,
    LaunchAgentRecord,
    LaunchRecord,
    LaunchRecordStore,
    WindowsServiceRecord,
)

ServiceKind = Literal["docker", "python", "program"]
EntryTier = Literal["show", "review", "hidden"]


class ServiceEndpoint(BaseModel):
    """服务的一个入口。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: Literal["tcp", "udp"]
    address: str
    port: int = Field(ge=1, le=65535)
    has_web_page: bool | None = None


class ServiceEntry(BaseModel):
    """首页上的一项服务。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=160)
    name: str = Field(min_length=1, max_length=80)
    kind: ServiceKind
    tier: EntryTier
    state: Literal["running", "stopped"] = "running"
    # 当前用户的 macOS 后台服务（LaunchAgent）；`kind` 仍是 `program`，旧版本照常能读。
    launch_agent: bool = False
    # 由某个 Windows 服务拉起的程序；`kind` 仍是 `program`。
    windows_service: bool = False
    mark: ServiceMark | None = None
    web_title: str | None = None
    endpoints: tuple[ServiceEndpoint, ...]


class LocalServiceMap(BaseModel):
    """这台电脑上的服务：直接显示的、可能是服务的，以及用户隐藏过的。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NodeId
    observed_at: datetime | None = None
    services: tuple[ServiceEntry, ...] = ()


class MarkInput(BaseModel):
    """一次标记。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mark: ServiceMark


_TIER_ORDER: dict[EntryTier, int] = {"show": 0, "review": 1, "hidden": 2}


def _kind(item: RemoteServiceSummary) -> ServiceKind:
    if item.container_running is not None:
        return "docker"
    if item.launch_agent_label:
        return "program"
    return "python" if is_python_process(item.process_name) else "program"


def _entry(
    node_id: NodeId,
    key: str,
    items: list[RemoteServiceSummary],
    marks: Mapping[str, ServiceMark],
) -> ServiceEntry | None:
    tiers = [
        service_tier(
            item.model_copy(update={"container_running": True})
            if item.container_running is False and item.port > 0
            else item,
            marks,
            key=key,
        )
        for item in items
    ]
    mark = marks.get(key)
    tier: EntryTier
    if ServiceTier.SHOW in tiers:
        tier = "show"
    elif ServiceTier.REVIEW in tiers:
        tier = "review"
    elif mark is ServiceMark.HIDDEN:
        # 用户隐藏过的服务仍然列出，方便在"高级"里撤销。
        tier = "hidden"
    else:
        return None
    visible = [
        item for item, value in zip(items, tiers, strict=True) if value is not ServiceTier.HIDE
    ]
    shown = (
        visible
        or [item for item in items if item.protocol == "tcp" or item.container_running is not None]
        or items
    )
    first = shown[0]
    _, label, application = service_presentation(node_id, first)
    name = application.name if application is not None else label.rsplit(" · ", 1)[0]
    unique = {
        (item.port, item.protocol, item.address): ServiceEndpoint(
            protocol="udp" if item.protocol == "udp" else "tcp",
            address=item.address,
            port=item.port,
            has_web_page=item.has_web_page,
        )
        for item in shown
        if item.port > 0
    }
    endpoints = [unique[endpoint] for endpoint in sorted(unique)]
    return ServiceEntry(
        key=key,
        name=name[:80],
        kind=_kind(first),
        tier=tier,
        state="stopped" if all(item.container_running is False for item in items) else "running",
        launch_agent=key.startswith("launchd:"),
        windows_service=any(item.windows_service_name for item in items),
        mark=mark,
        web_title=next((item.web_title for item in shown if item.web_title), None),
        endpoints=tuple(endpoints),
    )


def build_local_service_map(
    node_id: NodeId,
    snapshot: ServiceObservationSnapshot | None,
    marks: Mapping[str, ServiceMark],
    *,
    excluded_pid: int | None = None,
    launch_records: tuple[AnyLaunchRecord, ...] = (),
) -> LocalServiceMap:
    """按服务身份合并端口，并按"直接显示、可能是服务、已隐藏"排序。"""
    if snapshot is None:
        return LocalServiceMap(node_id=node_id)
    groups: dict[str, list[RemoteServiceSummary]] = {}
    keys = service_mark_keys(snapshot.inventory)
    for item, key in zip(snapshot.inventory, keys, strict=True):
        if excluded_pid is not None and item.process_pid == excluded_pid:
            continue
        groups.setdefault(key, []).append(item)
    for container in snapshot.containers:
        key = (
            f"docker:compose:{container.compose_project}"
            if container.compose_project
            else f"docker:{container.name}"
        )
        if key not in groups and marks.get(key) is ServiceMark.MINE:
            groups.setdefault(key, []).append(
                RemoteServiceSummary(
                    node_id=node_id,
                    protocol="tcp",
                    address="127.0.0.1",
                    port=0,
                    container_name=container.name,
                    compose_project=container.compose_project,
                    container_running=container.running,
                    accessibility=ServiceAccessibility.UNKNOWN,
                    confidence=EvidenceConfidence.LOW,
                    evidence=(),
                )
            )
    entries = [
        entry
        for key, items in groups.items()
        if (entry := _entry(node_id, key, items, marks)) is not None
    ]
    present = {entry.key for entry in entries}
    for launch in launch_records:
        if launch.service_key in groups:
            continue
        mark = marks.get(launch.service_key)
        agent = isinstance(launch, LaunchAgentRecord)
        entries.append(
            ServiceEntry(
                key=launch.service_key,
                name=(
                    launch.label if agent else launch.service_key.split(":", 1)[1].rsplit("@", 1)[0]
                )[:80],
                kind="python" if isinstance(launch, LaunchRecord) else "program",
                launch_agent=agent,
                windows_service=isinstance(launch, WindowsServiceRecord),
                tier="hidden" if mark is ServiceMark.HIDDEN else "show",
                state="running"
                if launch.service_key in snapshot.running_launch_keys
                else "stopped",
                mark=mark,
                endpoints=tuple(
                    ServiceEndpoint(protocol="tcp", address="127.0.0.1", port=port)
                    for port in launch.ports
                ),
            )
        )
        present.add(launch.service_key)
    for key, mark in marks.items():
        if mark is not ServiceMark.MINE or key in present or key in keys:
            continue
        prefix, name = key.split(":", 1)
        entries.append(
            ServiceEntry(
                key=key,
                name=name.rsplit("@", 1)[0][:80],
                kind="docker"
                if prefix == "docker"
                else "python"
                if prefix == "python"
                else "program",
                launch_agent=prefix == "launchd",
                tier="show",
                state="stopped",
                mark=mark,
                endpoints=(),
            )
        )
    entries.sort(key=lambda entry: (_TIER_ORDER[entry.tier], entry.name.lower(), entry.key))
    return LocalServiceMap(
        node_id=node_id, observed_at=snapshot.observed_at, services=tuple(entries)
    )


def create_service_map_router(
    node_id: NodeId,
    marks: ServiceMarkStore,
    read_snapshot: Callable[[], ServiceObservationSnapshot | None],
    replace_snapshot: Callable[[ServiceObservationSnapshot], None],
    launch_records: LaunchRecordStore | None = None,
) -> APIRouter:
    """创建只由本机应用挂载的服务清单与标记路由。"""
    router = APIRouter()
    own_pid = os.getpid()

    def current() -> LocalServiceMap:
        return build_local_service_map(
            node_id,
            read_snapshot(),
            marks.all(),
            excluded_pid=own_pid,
            launch_records=launch_records.list_all() if launch_records is not None else (),
        )

    def checked(key: str) -> str:
        if not is_mark_key(key):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "服务标记身份无效")
        return key

    def refresh() -> LocalServiceMap:
        # 标记改变后立刻重新分档，首页不用等下一轮观察。
        snapshot = read_snapshot()
        if snapshot is not None:
            replace_snapshot(
                apply_service_marks(node_id, snapshot, marks.all(), excluded_pid=own_pid)
            )
        return current()

    def list_services() -> LocalServiceMap:
        return current()

    def set_mark(key: str, payload: MarkInput) -> LocalServiceMap:
        marks.set(checked(key), payload.mark)
        return refresh()

    def clear_mark(key: str) -> LocalServiceMap:
        marks.clear(checked(key))
        return refresh()

    router.add_api_route(
        "/api/services/local", list_services, methods=["GET"], response_model=LocalServiceMap
    )
    router.add_api_route(
        "/api/services/marks/{key}", set_mark, methods=["PUT"], response_model=LocalServiceMap
    )
    router.add_api_route(
        "/api/services/marks/{key}", clear_mark, methods=["DELETE"], response_model=LocalServiceMap
    )
    return router
