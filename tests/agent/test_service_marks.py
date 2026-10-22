"""用户标记："是我的服务 / 隐藏"的身份、存储与优先级。"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from tunnelminion.agent.service_marks import (
    InMemoryServiceMarkStore,
    ServiceMark,
    is_mark_key,
    service_mark_key,
)
from tunnelminion.agent.service_observation import (
    ServiceObservationSnapshot,
    apply_service_marks,
    select_review_services,
    select_service_presentations,
    service_tier,
)
from tunnelminion.agent.service_tiers import ServiceTier
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceSummary,
    ServiceAccessibility,
    ServiceEvidence,
)
from tunnelminion.domain.identifiers import NodeId, ToolRunId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.platforms.process_origin import ProcessOrigin

NODE = NodeId("node_0123456789abcdef0123456789abcdef")
NOW = datetime(2026, 10, 22, tzinfo=UTC)


def service(**values: object) -> RemoteServiceSummary:
    base: dict[str, object] = {
        "node_id": NODE,
        "protocol": "tcp",
        "address": "0.0.0.0",
        "port": 47990,
        "process_pid": 12,
        "process_name": "sunshine.exe",
        "origin": ProcessOrigin.APP_SERVICE,
        "accessibility": ServiceAccessibility.NETWORK_LISTENING,
        "confidence": EvidenceConfidence.MEDIUM,
        "evidence": (
            ServiceEvidence(
                tool_name="list_network_listeners", tool_run_id=ToolRunId.new(), observed_at=NOW
            ),
        ),
    }
    base.update(values)
    return RemoteServiceSummary.model_validate(base)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (
            {"container_running": True, "compose_project": "penpot", "container_name": "x"},
            "docker:compose:penpot",
        ),
        ({"container_running": True, "container_name": " gimp "}, "docker:gimp"),
        ({"container_running": False, "container_name": " "}, "port:tcp:47990"),
        ({"process_name": "python3.12", "python_entrypoint": "app.py"}, "python:app.py"),
        ({"process_name": "python3.12"}, "port:tcp:47990"),
        ({"process_name": "Sunshine.EXE"}, "program:sunshine"),
        ({"process_name": None}, "port:tcp:47990"),
    ],
)
def test_mark_keys_follow_the_program_not_the_process_id(
    values: dict[str, object], expected: str
) -> None:
    key = service_mark_key(service(**values))
    assert key == expected and is_mark_key(key)
    # 进程号变了，身份不变。
    assert service_mark_key(service(**{**values, "process_pid": 999})) == expected


def test_without_process_id_the_name_is_not_trusted_as_identity() -> None:
    assert service_mark_key(service(process_pid=None)) == "port:tcp:47990"


@pytest.mark.parametrize(
    "value", ["program:", "unknown:x", "program:a/b", "program:a\\b", "program:\x00"]
)
def test_invalid_mark_keys_are_rejected(value: str) -> None:
    assert not is_mark_key(value)


def test_marks_override_rules_for_every_port_of_the_program() -> None:
    web = service()
    stream = service(port=47984, has_web_page=False)
    udp = service(protocol="udp", port=47998)
    assert [service_tier(item) for item in (web, stream, udp)] == [
        ServiceTier.REVIEW,
        ServiceTier.HIDE,
        ServiceTier.HIDE,
    ]
    mine = {"program:sunshine": ServiceMark.MINE}
    # UDP 端口仍然不显示：它们是底层通信，不是可以打开的入口。
    assert [service_tier(item, mine) for item in (web, stream, udp)] == [
        ServiceTier.SHOW,
        ServiceTier.SHOW,
        ServiceTier.HIDE,
    ]
    hidden = {"program:sunshine": ServiceMark.HIDDEN}
    assert service_tier(service(origin=ProcessOrigin.TERMINAL), hidden) is ServiceTier.HIDE
    assert service_tier(service(origin=ProcessOrigin.TERMINAL), {}) is ServiceTier.SHOW


def test_apply_marks_moves_a_service_between_tiers_without_new_observation() -> None:
    items = (service(), service(port=47984, has_web_page=False))
    names, applications = select_service_presentations(NODE, items)
    snapshot = ServiceObservationSnapshot(
        observed_at=NOW,
        services=(),
        display_names=names,
        applications=applications,
        review_names=select_review_services(NODE, items),
        inventory=items,
    )
    assert snapshot.display_names == {} and len(snapshot.review_names) == 1
    marked = apply_service_marks(NODE, snapshot, {"program:sunshine": ServiceMark.MINE})
    assert sorted(marked.display_names.values()) == ["sunshine · 47984", "sunshine · 47990"]
    assert marked.review_names == {} and marked.observed_at == NOW
    assert len({value.group_id for value in marked.applications.values()}) == 1
    hidden = apply_service_marks(NODE, marked, {"program:sunshine": ServiceMark.HIDDEN})
    assert hidden.display_names == {} and hidden.review_names == {}
    own = apply_service_marks(
        NODE, snapshot, {"program:sunshine": ServiceMark.MINE}, excluded_pid=12
    )
    assert own.display_names == {} and own.review_names == {}


def test_in_memory_store_round_trip() -> None:
    store = InMemoryServiceMarkStore()
    store.set("program:a", ServiceMark.MINE)
    store.set("program:a", ServiceMark.HIDDEN)
    assert store.all() == {"program:a": ServiceMark.HIDDEN}
    store.clear("program:a")
    store.clear("program:missing")
    assert store.all() == {}


def test_sqlite_store_survives_reopening(tmp_path: Path) -> None:
    path = tmp_path / "runtime.sqlite3"
    first = SQLiteStores.open(path).service_marks
    first.set("docker:compose:penpot", ServiceMark.MINE)
    first.set("program:steam", ServiceMark.HIDDEN)
    first.set("program:steam", ServiceMark.MINE)
    reopened = SQLiteStores.open(path).service_marks
    assert reopened.all() == {
        "docker:compose:penpot": ServiceMark.MINE,
        "program:steam": ServiceMark.MINE,
    }
    reopened.clear("program:steam")
    assert SQLiteStores.open(path).service_marks.all() == {
        "docker:compose:penpot": ServiceMark.MINE
    }
