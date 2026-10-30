"""修复计划只从服务身份、标记和本机记录生成。"""

import asyncio
from pathlib import Path

import pytest
from tests.repair.factories import container
from tests.repair.fakes import RepairHarness, local_launch

from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.repair.contracts import (
    ContainerRepairTarget,
    PythonRepairTarget,
    RepairErrorCode,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
)
from tunnelminion.repair.eligibility import RepairRefusal

ORIGIN = RepairOrigin(kind=RepairOriginKind.LOCAL_CLI)


@pytest.mark.parametrize("reason", ["", " \n ", "x" * 501])
def test_reason_validation(tmp_path: Path, reason: str) -> None:
    h = RepairHarness(tmp_path)
    with pytest.raises(ValueError, match="reason"):
        asyncio.run(
            h.planner.propose(
                "docker:compose:photos", RepairKind.RESTART_CONTAINERS, reason, ORIGIN
            )
        )


@pytest.mark.parametrize(
    ("key", "kind", "message"),
    [
        (
            "program:svc",
            RepairKind.RESTART_CONTAINERS,
            "这种修法不适用于这个服务。",
        ),
        (
            "port:8080",
            RepairKind.RESTART_CONTAINERS,
            "只能修 Docker 容器、Python 脚本、普通程序、macOS 后台服务和 Windows 服务。",
        ),
        (
            "docker:a/b",
            RepairKind.RESTART_CONTAINERS,
            "只能修 Docker 容器、Python 脚本、普通程序、macOS 后台服务和 Windows 服务。",
        ),
        ("docker:photos", RepairKind.RELAUNCH_PYTHON, "这种修法不适用于这个服务。"),
        ("python:app.py@8765", RepairKind.RESTART_CONTAINERS, "这种修法不适用于这个服务。"),
    ],
)
def test_identity_refusals(tmp_path: Path, key: str, kind: RepairKind, message: str) -> None:
    h = RepairHarness(tmp_path)
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(h.planner.propose(key, kind, "退出了", ORIGIN))
    assert caught.value.error.code is RepairErrorCode.NOT_ELIGIBLE
    assert str(caught.value) == message
    assert not h.containers.queries and not h.host.calls


@pytest.mark.parametrize("python", [False, True])
def test_hidden_is_checked_before_runtime(tmp_path: Path, python: bool) -> None:
    h = RepairHarness(tmp_path)
    key = "python:app.py@8765" if python else "docker:compose:photos"
    h.marks[key] = ServiceMark.HIDDEN
    kind = RepairKind.RELAUNCH_PYTHON if python else RepairKind.RESTART_CONTAINERS
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(h.planner.propose(key, kind, "退出了", ORIGIN))
    assert caught.value.error.message == "这个服务被标成了隐藏，Agent 不能动它。"
    assert caught.value.error.next_step == '想修的话，先在首页把它标成"是我的服务"。'
    assert not h.containers.queries and not h.host.calls


@pytest.mark.parametrize("case", ["unavailable", "missing", "image", "k8s", "not_mine"])
def test_container_refusals(tmp_path: Path, case: str) -> None:
    h = RepairHarness(tmp_path)
    if case == "unavailable":
        h.containers.items = None
        code = RepairErrorCode.DOCKER_UNAVAILABLE
    elif case == "missing":
        h.containers.items = ()
        code = RepairErrorCode.CONTAINER_MISSING
    elif case == "image":
        h.containers.items = (container().model_copy(update={"image": "docker/desktop-storage"}),)
        code = RepairErrorCode.PROTECTED_TARGET
    elif case == "k8s":
        h.containers.items = (container(name="k8s_system"),)
        code = RepairErrorCode.PROTECTED_TARGET
    else:
        h.containers.items = (container(ports=()),)
        code = RepairErrorCode.NOT_ELIGIBLE
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(
            h.planner.propose(
                "docker:compose:photos", RepairKind.RESTART_CONTAINERS, "退出了", ORIGIN
            )
        )
    assert caught.value.error.code is code
    assert (
        caught.value.error.next_step is not None
        if case != "image" and case != "k8s"
        else caught.value.error.next_step is None
    )


@pytest.mark.parametrize("mine", [False, True])
def test_compose_plan_all_ports_and_reason_are_display_only(tmp_path: Path, mine: bool) -> None:
    h = RepairHarness(tmp_path)
    if mine:
        h.marks["docker:compose:photos"] = ServiceMark.MINE
    h.containers.items = (
        container(ports=() if mine else (8080,)),
        container("b", name="photos-db-1", ports=()),
    )
    reason = "rm -rf / && docker compose up"
    p = asyncio.run(
        h.planner.propose(
            "docker:compose:photos", RepairKind.RESTART_CONTAINERS, f"  {reason}  ", ORIGIN
        )
    )
    assert isinstance(p.target, ContainerRepairTarget)
    assert p.reason == reason
    assert reason not in p.model_dump_json(exclude={"reason"})
    assert h.containers.queries == [("photos", None)]
    assert p.service_name == "Docker 容器组 photos"
    assert p.action_summary == "重启 Docker 容器组 photos（2 个容器）"
    assert p.verification_summary == (
        "重启后我会确认容器在运行。"
        if mine
        else "重启后我会确认容器在运行、端口在听，并再打开一次首页。"
    )
    again = asyncio.run(
        h.planner.propose(
            "docker:compose:photos", RepairKind.RESTART_CONTAINERS, "另一个理由", ORIGIN
        )
    )
    assert p.idempotency_key == again.idempotency_key


def test_compose_plan_names_dependency_order(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.containers.items = (
        container(service="web", depends_on=("db",)),
        container("b", name="photos-db-1", service="db"),
    )
    p = asyncio.run(
        h.planner.propose("docker:compose:photos", RepairKind.RESTART_CONTAINERS, "退出了", ORIGIN)
    )
    assert p.action_summary == "按依赖顺序处理 Docker 容器组 photos：先启动 db，再启动 web"
    assert "最多 60 秒" in p.impact_summary
    long_name = "s" * 128
    h.containers.items = tuple(
        container(
            chr(ord("a") + index),
            name=f"photos-{index}",
            service=f"{long_name[:-2]}{index:02d}",
            depends_on=(f"{long_name[:-2]}{index - 1:02d}",) if index else (),
        )
        for index in range(6)
    )
    p = asyncio.run(
        h.planner.propose("docker:compose:photos", RepairKind.RESTART_CONTAINERS, "退出了", ORIGIN)
    )
    assert len(p.action_summary) == 300


def test_single_container_plan_and_safe_truncation(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    name = "x" * 128
    h.containers.items = (container(name=name, compose_project=None),)
    p = asyncio.run(
        h.planner.propose(f"docker:{name}", RepairKind.RESTART_CONTAINERS, "退出了", ORIGIN)
    )
    assert p.service_name == f"Docker 容器 {name}"[:120]
    assert p.action_summary == f"重启 Docker 容器 {name}"
    assert h.containers.queries == [(None, name)]


def test_python_no_launch_record_and_not_shown(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    key = "python:app.py@8765"
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(h.planner.propose(key, RepairKind.RELAUNCH_PYTHON, "退出了", ORIGIN))
    assert caught.value.error.code is RepairErrorCode.NO_LAUNCH_RECORD
    launch = local_launch(tmp_path).model_copy(update={"rule_shown": False})
    h.launch_records.put(launch)
    with pytest.raises(RepairRefusal) as caught:
        asyncio.run(h.planner.propose(key, RepairKind.RELAUNCH_PYTHON, "退出了", ORIGIN))
    assert caught.value.error.code is RepairErrorCode.NOT_ELIGIBLE


@pytest.mark.parametrize("mine", [False, True])
def test_python_plan_from_record(tmp_path: Path, mine: bool) -> None:
    h = RepairHarness(tmp_path)
    launch = local_launch(tmp_path).model_copy(
        update={"rule_shown": not mine, "ports": (8766, 8765)}
    )
    h.launch_records.put(launch)
    if mine:
        h.marks[launch.service_key] = ServiceMark.MINE
    p = asyncio.run(
        h.planner.propose(launch.service_key, RepairKind.RELAUNCH_PYTHON, "退出了", ORIGIN)
    )
    assert isinstance(p.target, PythonRepairTarget)
    assert p.target.launch == launch
    assert p.service_name == "Python 脚本 app.py"
    assert p.action_summary == "按上次的启动方式在后台重新运行 app.py（端口 8765、8766）"
    assert p.verification_summary == "启动后我会确认端口 8765、8766 在听，并再打开一次首页。"
