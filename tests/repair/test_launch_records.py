"""启动记录的资格、虚拟环境路径与单项失败隔离测试。"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import psutil
import pytest
from pydantic import ValidationError

from tunnelminion.agent.service_marks import ServiceMark
from tunnelminion.agent.services import (
    EvidenceConfidence,
    RemoteServiceSummary,
    ServiceAccessibility,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.platforms.process_origin import ProcessOrigin
from tunnelminion.repair.contracts import LaunchRecord, LaunchRecordStore
from tunnelminion.repair.launch_records import (
    LaunchRecorder,
    ProcessLaunchFacts,
    ProcessLaunchReader,
    PsutilProcessLaunchReader,
)

NOW = datetime(2026, 10, 25, tzinfo=UTC)


class FakeProcess:
    def __init__(self) -> None:
        self.command = ["python", "app.py"]
        self.directory = "fixture/site"
        self.executable = "fixture/base/python"
        self.process_name = "python"
        self.parent_process: FakeProcess | None = None
        self.environment: dict[str, str] = {}
        self.environment_reads = 0
        self.error: Exception | None = None

    def name(self) -> str:
        if self.error is not None:
            raise self.error
        return self.process_name

    def cmdline(self) -> list[str]:
        return self.command

    def cwd(self) -> str:
        return self.directory

    def exe(self) -> str:
        return self.executable

    def username(self) -> str:
        return "fixture-user"

    def create_time(self) -> float:
        return NOW.timestamp()

    def parent(self) -> psutil.Process | None:
        return (
            cast(psutil.Process, self.parent_process) if self.parent_process is not None else None
        )

    def environ(self) -> dict[str, str]:
        self.environment_reads += 1
        return self.environment


def factory(process: FakeProcess) -> Callable[[int], psutil.Process]:
    return lambda pid: cast(psutil.Process, process)


@pytest.mark.parametrize(
    "case", ("launcher", "no-parent", "not-python", "different-args", "same-exe")
)
def test_windows_keeps_venv_launcher_only_for_matching_python_parent(case: str) -> None:
    process, parent = FakeProcess(), FakeProcess()
    parent.executable = "fixture/venv/Scripts/python.exe"
    process.parent_process = parent
    if case == "no-parent":
        process.parent_process = None
    if case == "not-python":
        parent.process_name = "terminal.exe"
    if case == "different-args":
        parent.command = ["python", "other.py"]
    if case == "same-exe":
        parent.executable = process.executable
    reader: ProcessLaunchReader = PsutilProcessLaunchReader("win32", factory(process))
    facts = reader.read(101)
    assert facts is not None
    expected = parent.executable if case == "launcher" else process.executable
    assert facts.interpreter == expected
    assert facts.arguments == ("app.py",) and facts.started_at == NOW
    assert facts.working_directory == "fixture/site" and facts.username == "fixture-user"
    assert process.environment_reads == 0
    assert "environment" not in facts.model_dump()


@pytest.mark.parametrize(
    "case",
    (
        "absolute",
        "relative",
        "venv",
        "missing-absolute",
        "missing-relative",
        "missing-venv",
        "bare",
    ),
)
def test_macos_uses_process_venv_paths_without_resolving_them(tmp_path: Path, case: str) -> None:
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"fixture")
    process = FakeProcess()
    process.directory = str(tmp_path)
    commands = {
        "absolute": str(interpreter),
        "relative": "venv/bin/python",
        "venv": "python3",
        "missing-absolute": str(tmp_path / "missing-python"),
        "missing-relative": "missing/python",
        "missing-venv": "python3",
        "bare": "python3",
    }
    process.command[0] = commands[case]

    class Environment:
        def __init__(self, **values: str) -> None:
            self.values = values

        def get(self, key: str) -> str | None:
            assert key == "VIRTUAL_ENV"
            return self.values.get(key)

    process.environment = cast(
        dict[str, str],
        (
            Environment(
                VIRTUAL_ENV=str(
                    interpreter.parent.parent if case != "missing-venv" else tmp_path / "missing"
                ),
                PRIVATE_FIXTURE="fixture-secret",
            )
            if case != "bare"
            else Environment()
        ),
    )
    facts = PsutilProcessLaunchReader("darwin", factory(process)).read(101)
    assert facts is not None
    assert facts.interpreter == (
        str(interpreter) if case in {"absolute", "relative", "venv"} else process.executable
    )
    assert process.environment_reads == (1 if case in {"venv", "missing-venv", "bare"} else 0)
    assert "fixture-secret" not in facts.model_dump_json()


def test_existing_path_is_not_resolved(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    process = FakeProcess()
    process.command[0] = str(tmp_path / "venv" / "bin" / "python")

    def exists(path: Path) -> bool:
        return True

    monkeypatch.setattr(Path, "is_file", exists)

    def unexpected_resolve(path: Path, *args: object, **kwargs: object) -> Path:
        raise AssertionError("不能解析虚拟环境链接")

    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    facts = PsutilProcessLaunchReader("darwin", factory(process)).read(101)
    assert facts is not None and facts.interpreter == process.command[0]


@pytest.mark.parametrize(
    "case", ("not-python", "empty", "denied", "missing", "os-error", "parent-error")
)
def test_unreadable_or_non_python_process_has_no_facts(case: str) -> None:
    process = FakeProcess()
    if case == "not-python":
        process.process_name = "python-helper"
    if case == "empty":
        process.command = []
    errors = {
        "denied": psutil.AccessDenied(101),
        "missing": psutil.NoSuchProcess(101),
        "os-error": OSError("fixture denied"),
    }
    process.error = errors.get(case)
    if case == "parent-error":
        process.parent_process = FakeProcess()
        process.parent_process.error = psutil.AccessDenied(100)
    assert PsutilProcessLaunchReader("win32", factory(process)).read(101) is None


def facts(**changes: object) -> ProcessLaunchFacts:
    values: dict[str, object] = {
        "interpreter": "fixture/python",
        "arguments": ("app.py",),
        "working_directory": "fixture/site",
        "username": "fixture-user",
        "started_at": NOW,
    }
    values.update(changes)
    return ProcessLaunchFacts.model_validate(values)


def service(pid: int | None = 101, port: int = 8080, **changes: object) -> RemoteServiceSummary:
    values: dict[str, object] = {
        "node_id": NodeId("node_0123456789abcdef0123456789abcdef"),
        "protocol": "tcp",
        "address": "127.0.0.1",
        "port": port,
        "process_pid": pid,
        "process_name": "python",
        "python_entrypoint": "app.py",
        "origin": ProcessOrigin.TERMINAL,
        "accessibility": ServiceAccessibility.LOCAL_ONLY,
        "confidence": EvidenceConfidence.HIGH,
        "evidence": (),
    }
    values.update(changes)
    return RemoteServiceSummary.model_validate(values)


class MemoryLaunchStore:
    def __init__(self) -> None:
        self.records: dict[str, LaunchRecord] = {}
        self.writes: list[LaunchRecord] = []
        self.error: Exception | None = None

    def put(self, record: LaunchRecord) -> None:
        if self.error is not None:
            raise self.error
        self.records[record.service_key] = record
        self.writes.append(record)

    def get(self, service_key: str) -> LaunchRecord | None:
        return self.records.get(service_key)

    def list_all(self) -> tuple[LaunchRecord, ...]:
        return tuple(self.records.values())


class FakeLaunchReader:
    def __init__(self, values: dict[int, ProcessLaunchFacts | Exception | None]) -> None:
        self.values = values
        self.calls: list[int] = []

    def read(self, pid: int) -> ProcessLaunchFacts | None:
        self.calls.append(pid)
        value = self.values[pid]
        if isinstance(value, Exception):
            raise value
        return value


def test_facts_are_frozen_utc_and_exclude_environment() -> None:
    value = facts(started_at=NOW.astimezone(timezone(timedelta(hours=8))))
    assert value.started_at == NOW and value.started_at.tzinfo is UTC
    with pytest.raises(ValidationError):
        value.username = "other"
    with pytest.raises(ValidationError):
        facts(started_at=datetime(2026, 10, 25))
    with pytest.raises(ValidationError):
        facts(environment={"secret": "fixture-secret"})


def test_records_mine_and_rule_shown_only_and_reads_pid_once() -> None:
    reader = FakeLaunchReader({101: facts(), 102: facts(arguments=("-m", "http.server"))})
    memory = MemoryLaunchStore()
    store: LaunchRecordStore = memory
    recorder = LaunchRecorder(store, reader=reader, clock=lambda: NOW, own_pid=999)
    inventory = (
        service(101, 8081),
        service(101, 8080),
        service(101, 8080, address="::"),
        service(101, 7070, protocol="udp"),
        service(102, 9000, origin=ProcessOrigin.UNKNOWN, python_entrypoint="http.server"),
        service(103, 9001, origin=ProcessOrigin.UNKNOWN),
        service(104, 9002),
        service(105, 9003, origin=ProcessOrigin.SYSTEM),
        service(106, 9004, process_name="node"),
        service(None, 9005),
        service(107, 9006, container_running=True, container_name="web"),
        service(108, 9007, python_entrypoint=None),
        service(999, 9008),
    )
    marks = {"python:http.server@9000": ServiceMark.MINE, "python:app.py@9002": ServiceMark.HIDDEN}
    assert recorder.record(inventory, marks) == 2
    assert reader.calls == [101, 102]
    assert len(store.list_all()) == 2
    record = store.get("python:app.py@8080")
    assert record is not None and record.ports == (8080, 8081)
    assert record.rule_shown and record.recorded_at == NOW and record.process_started_at == NOW
    mine = store.get("python:http.server@9000")
    assert mine is not None and not mine.rule_shown and mine.arguments == ("-m", "http.server")
    assert set(record.model_dump()) == {
        "service_key",
        "interpreter",
        "arguments",
        "working_directory",
        "ports",
        "username",
        "rule_shown",
        "process_id",
        "process_started_at",
        "recorded_at",
    }
    assert recorder.record(inventory, marks) == 0
    assert len(memory.writes) == 2 and reader.calls == [101, 102, 101, 102]


@pytest.mark.parametrize(
    "arguments",
    (
        (),
        ("-c", "print('fixture')"),
        ("-m", "tunnelminion"),
        ("-m", "tunnelminion.cli"),
        ("fixture/tunnelminion/app.py",),
        (r"fixture\TunnelMinion\app.py",),
    ),
)
def test_interactive_and_tunnelminion_entries_are_never_recorded(
    arguments: tuple[str, ...],
) -> None:
    reader = FakeLaunchReader({101: facts(arguments=arguments)})
    store = MemoryLaunchStore()
    assert LaunchRecorder(store, reader=reader).record((service(),), {}) == 0
    assert not store.writes


@pytest.mark.parametrize(
    "failure", (None, OSError("fixture denied"), RuntimeError("fixture reader"))
)
def test_unreadable_pid_is_read_once_and_other_processes_still_record(
    failure: Exception | None,
) -> None:
    reader = FakeLaunchReader({101: failure, 102: facts()})
    store = MemoryLaunchStore()
    inventory = (
        service(101, 8080),
        service(101, 8081),
        service(101, 8082, python_entrypoint="other.py"),
        service(102, 9000),
    )
    assert LaunchRecorder(store, reader=reader).record(inventory, {}) == 1
    assert reader.calls == [101, 102]
    assert store.get("python:app.py@9000") is not None


def test_store_failure_is_isolated_and_invalid_facts_do_not_escape() -> None:
    reader = FakeLaunchReader({101: facts(interpreter=""), 102: facts()})
    store = MemoryLaunchStore()
    recorder = LaunchRecorder(store, reader=reader)
    assert recorder.record((service(), service(102, 9000)), {}) == 1
    store.error = OSError("fixture store")
    assert recorder.record((service(102, 9001),), {}) == 0


@pytest.mark.parametrize(
    "field,value",
    (
        ("interpreter", "fixture/other-python"),
        ("arguments", ("app.py", "--debug")),
        ("working_directory", "fixture/other-site"),
        ("username", "fixture-other-user"),
        ("ports", (8080, 8081)),
        ("process_id", 102),
        ("rule_shown", False),
    ),
)
def test_every_recorded_launch_field_triggers_an_update(field: str, value: object) -> None:
    store = MemoryLaunchStore()
    reader = FakeLaunchReader({101: facts()})
    recorder = LaunchRecorder(store, reader=reader, clock=lambda: NOW)
    assert recorder.record((service(),), {}) == 1
    original = store.records["python:app.py@8080"]
    store.records[original.service_key] = original.model_copy(update={field: value})
    assert recorder.record((service(),), {}) == 1
    assert store.records[original.service_key] == original


def test_same_pid_can_have_distinct_service_keys_but_is_read_once() -> None:
    reader = FakeLaunchReader({101: facts()})
    store = MemoryLaunchStore()
    assert (
        LaunchRecorder(store, reader=reader).record(
            (service(), service(101, 8081, python_entrypoint="other.py")), {}
        )
        == 2
    )
    assert reader.calls == [101]
    assert store.list_all()[0].recorded_at.tzinfo is UTC


def test_default_own_pid_is_never_read() -> None:
    reader = FakeLaunchReader({})
    assert (
        LaunchRecorder(MemoryLaunchStore(), reader=reader).record((service(os.getpid()),), {}) == 0
    )
    assert not reader.calls


def test_default_reader_construction_does_not_query_processes() -> None:
    assert LaunchRecorder(MemoryLaunchStore()).record((), {}) == 0
