"""本机 Agent 的修复取证、计划和权限边界；只使用容器、进程替身。"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue
from tests.repair.factories import NODE, NOW, container, launch_record
from tests.repair.fakes import RepairHarness, local_launch
from tests.repair.test_docker import FIRST, FakeRunner, inspect_row, ps_row, result

from tunnelminion.domain.identifiers import OperationId, RunId, ThreadId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.operation.contracts import OperationLevel
from tunnelminion.repair.agent_tools import (
    ReadContainerLogsAdapter,
    register_repair_agent_tools,
    repair_approval_instruction,
)
from tunnelminion.repair.contracts import REPAIR_TOOL_NAMES, PortOwner
from tunnelminion.repair.docker import DockerContainerRuntime
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest, ToolExecutionStatus
from tunnelminion.tools.runtime import ToolRuntime, current_tool_call_context

TOOL_NAMES = ("read_container_logs", "list_launch_records", "propose_repair")


def runtime(
    harness: RepairHarness, data_dir: Path, platform: Platform = Platform.WINDOWS
) -> ToolRuntime:
    register_repair_agent_tools(
        harness.registry,
        containers=harness.containers,
        launch_records=harness.launch_records,
        host=harness.host,
        marks=lambda: harness.marks,
        repair_service=harness.service,
        data_dir=data_dir,
    )
    return ToolRuntime(harness.registry, platform, InMemoryAuditSink())


def context() -> ToolCallContext:
    return ToolCallContext(
        thread_id=ThreadId.new(), run_id=RunId.new(), caller_node_id=NODE, execution_node_id=NODE
    )


def call(
    executor: ToolRuntime, name: str, arguments: dict[str, JsonValue] | None = None
) -> dict[str, JsonValue]:
    response = asyncio.run(
        executor.execute(
            ToolExecutionRequest(context=context(), tool_name=name, arguments=arguments or {})
        )
    )
    assert response.status is ToolExecutionStatus.SUCCESS, response.error
    assert isinstance(response.output, dict)
    return response.output


@pytest.mark.parametrize("platform", (Platform.WINDOWS, Platform.MACOS))
def test_registered_tools_are_l0_and_execution_tools_stay_private(
    tmp_path: Path, platform: Platform
) -> None:
    harness = RepairHarness(tmp_path)
    runtime(harness, tmp_path, platform)
    available = {tool.name for tool in harness.registry.model_tools(platform)}
    assert set(TOOL_NAMES) <= available
    assert not set(REPAIR_TOOL_NAMES.values()) & available
    for name in TOOL_NAMES:
        entry = harness.registry.lookup(name)
        assert entry is not None
        assert entry.operation_level is OperationLevel.L0
        assert entry.definition.risk_level is RiskLevel.READ_ONLY
        assert entry.definition.input_schema["additionalProperties"] is False


@pytest.mark.parametrize(
    ("service_key", "lines"),
    (("docker:photos-web-1", None), ("docker:compose:photos", 10), ("docker:compose:photos", 80)),
)
def test_container_logs_scope_limit_and_defaults(
    tmp_path: Path, service_key: str, lines: int | None
) -> None:
    harness = RepairHarness(tmp_path)
    if "compose:" in service_key:
        harness.containers.items = tuple(container(char, name=char) for char in "abcdef")
    arguments: dict[str, JsonValue] = {"service_key": service_key}
    if lines is not None:
        arguments["lines"] = lines
    output = call(runtime(harness, tmp_path), "read_container_logs", arguments)
    assert output["docker_available"] is True
    containers = cast(list[dict[str, JsonValue]], output["containers"])
    assert len(containers) == (5 if "compose:" in service_key else 1)
    assert all(set(item) == {"name", "status", "running", "log_tail"} for item in containers)
    assert containers[0]["log_tail"] == "startup failed"
    assert harness.containers.queries == (
        [("photos", None)] if "compose:" in service_key else [(None, "photos-web-1")]
    )
    assert [size for _, size in harness.containers.log_calls] == [lines or 40] * len(containers)
    assert not harness.containers.calls


@pytest.mark.parametrize("available", (False, True))
def test_missing_docker_or_container_is_a_normal_result(tmp_path: Path, available: bool) -> None:
    harness = RepairHarness(tmp_path)
    harness.containers.items = () if available else None
    output = call(runtime(harness, tmp_path), "read_container_logs", {"service_key": "docker:web"})
    assert output["docker_available"] is available
    assert output["containers"] == []
    assert ("没有找到" if available else "Docker 没开") in str(output["message"])
    assert not harness.containers.log_calls


def test_log_tool_reuses_docker_redaction_and_only_read_commands(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    executor = runtime(harness, tmp_path)
    runner = FakeRunner(
        result(ps_row(FIRST, "photos-web-1")),
        result(json.dumps([inspect_row(FIRST, "photos-web-1")])),
        result("password=secret-value\nAuthorization: Bearer private-token\nmissing config"),
    )
    entry = harness.registry.lookup("read_container_logs")
    assert entry is not None
    assert isinstance(entry.adapter, ReadContainerLogsAdapter)
    entry.adapter._containers = DockerContainerRuntime(  # pyright: ignore[reportPrivateUsage]
        runner, "docker-fixture"
    )
    output = call(executor, "read_container_logs", {"service_key": "docker:photos-web-1"})
    serialized = json.dumps(output)
    assert "secret-value" not in serialized and "private-token" not in serialized
    assert "missing config" in serialized
    assert [argv[1] for argv, _ in runner.calls] == ["ps", "inspect", "logs"]


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("read_container_logs", {}),
        ("read_container_logs", {"service_key": "python:app.py@8000"}),
        ("read_container_logs", {"service_key": "docker:bad name"}),
        ("read_container_logs", {"service_key": "docker:-flag"}),
        ("read_container_logs", {"service_key": "docker:web;docker rm"}),
        ("read_container_logs", {"service_key": "docker:../web"}),
        ("read_container_logs", {"service_key": "docker:web\n"}),
        ("read_container_logs", {"service_key": "docker:" + "a" * 129}),
        ("read_container_logs", {"service_key": "docker:web", "lines": 9}),
        ("read_container_logs", {"service_key": "docker:web", "lines": 81}),
        ("read_container_logs", {"service_key": "docker:web", "lines": True}),
        ("read_container_logs", {"service_key": "docker:web", "lines": 10.5}),
        ("read_container_logs", {"service_key": "docker:web", "command": "docker rm"}),
        ("list_launch_records", {"interpreter": "python"}),
        ("propose_repair", {"service_key": "docker:web", "kind": "restart_containers"}),
        (
            "propose_repair",
            {"service_key": "docker:web", "kind": "shell", "reason": "退出了"},
        ),
        (
            "propose_repair",
            {"service_key": "docker:web", "kind": "restart_containers", "reason": ""},
        ),
        (
            "propose_repair",
            {"service_key": "docker:web", "kind": "restart_containers", "reason": "x" * 501},
        ),
        (
            "propose_repair",
            {"service_key": "docker:/web", "kind": "restart_containers", "reason": "退出了"},
        ),
        (
            "propose_repair",
            {
                "service_key": "docker:web",
                "kind": "restart_containers",
                "reason": "退出了",
                "origin": {"kind": "local_cli"},
            },
        ),
    ],
)
def test_invalid_or_extra_arguments_never_reach_adapters(
    tmp_path: Path, tool: str, arguments: dict[str, JsonValue]
) -> None:
    harness = RepairHarness(tmp_path)
    response = asyncio.run(
        runtime(harness, tmp_path).execute(
            ToolExecutionRequest(context=context(), tool_name=tool, arguments=arguments)
        )
    )
    assert response.status is ToolExecutionStatus.FAILED
    assert response.error is not None and response.error.code.value == "invalid_argument"
    assert not harness.containers.queries and not harness.store.records


def test_launch_records_are_recent_summaries_and_check_script_identity(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    for index in range(22):
        harness.launch_records.put(
            launch_record(
                service_key=f"python:app{index}.py@{8000 + index}", ports=(8000 + index,)
            ).model_copy(update={"recorded_at": NOW + timedelta(minutes=index)})
        )
    harness.marks["python:app21.py@8021"] = ServiceMark.MINE
    harness.marks["python:app20.py@8020"] = ServiceMark.HIDDEN
    harness.host.owners[8021] = PortOwner(pid=1, process_name="python", matches_launch=True)
    harness.host.owners[8020] = PortOwner(pid=2, process_name="other", matches_launch=False)
    output = call(runtime(harness, tmp_path), "list_launch_records")
    records = cast(list[dict[str, JsonValue]], output["records"])
    assert len(records) == 20
    assert records[0]["service_key"] == "python:app21.py@8021"
    assert records[-1]["service_key"] == "python:app2.py@8002"
    assert records[0]["running"] is True and records[0]["mark"] == "mine"
    assert records[1]["running"] is False and records[1]["mark"] == "hidden"
    assert records[2]["running"] is False and records[2]["mark"] is None
    assert records[1]["summary"] == ("有启动记录：app20.py，上次在 8020 端口，现在没有在运行")
    for item in records:
        assert set(item) == {
            "service_key",
            "kind",
            "entry",
            "ports",
            "recorded_at",
            "running",
            "mark",
            "summary",
        }
    serialized = json.dumps(output)
    for private in ("C:/Python311", "C:/work/site", "username", "process_id", "arguments"):
        assert private not in serialized
    assert all(launch is not None for _, launch in harness.host.calls)


def test_launch_records_empty_and_multiple_ports(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    executor = runtime(harness, tmp_path)
    assert call(executor, "list_launch_records") == {"records": []}
    launch = launch_record(ports=(8000, 8001, 8002))
    harness.launch_records.put(launch)
    harness.host.owners[8001] = PortOwner(pid=1, process_name="python", matches_launch=True)
    output = call(executor, "list_launch_records")
    assert cast(list[dict[str, JsonValue]], output["records"])[0]["running"] is True
    assert harness.host.calls == [(8000, launch), (8001, launch)]


@pytest.mark.parametrize("reason", ("; rm -rf /", "docker rm photos", "容器已退出"))
def test_proposal_is_only_text_and_preserves_conversation_origin(
    tmp_path: Path, reason: str
) -> None:
    harness = RepairHarness(tmp_path)
    executor = runtime(harness, tmp_path)
    ctx = context()
    response = asyncio.run(
        executor.execute(
            ToolExecutionRequest(
                context=ctx,
                tool_name="propose_repair",
                arguments={
                    "service_key": "docker:compose:photos",
                    "kind": "restart_containers",
                    "reason": reason,
                },
            )
        )
    )
    assert response.status is ToolExecutionStatus.SUCCESS
    output = cast(dict[str, JsonValue], response.output)
    assert output["proposed"] is True and output["status"] == "awaiting_authorization"
    record = harness.store.get(OperationId(cast(str, output["repair_id"])))
    assert record is not None
    assert record.plan.reason == reason
    assert record.plan.origin.kind.value == "conversation"
    assert record.plan.origin.thread_id == ctx.thread_id and record.plan.origin.run_id == ctx.run_id
    assert record.plan.origin.delegation_id is None
    assert record.audit[0].actor == "agent"
    assert record.authorization is None and record.execution is None
    assert not harness.containers.calls and not harness.launcher.calls
    assert output["expires_in_minutes"] == 10
    assert output["action"] == record.plan.action_summary
    assert output["impact"] == record.plan.impact_summary
    assert output["verification"] == record.plan.verification_summary
    assert output["on_failure"] == record.plan.failure_summary
    assert output["how_to_approve"] == repair_approval_instruction(
        record.plan.operation_id, tmp_path
    )
    with pytest.raises(LookupError):
        current_tool_call_context.get()


def test_python_proposal_never_returns_the_launch_command_or_paths(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    harness.launch_records.put(local_launch(tmp_path))
    output = call(
        runtime(harness, tmp_path),
        "propose_repair",
        {"service_key": "python:app.py@8765", "kind": "relaunch_python", "reason": "脚本退出了"},
    )
    assert output["proposed"] is True
    public = json.dumps({key: value for key, value in output.items() if key != "how_to_approve"})
    assert "python.exe" not in public and str(tmp_path) not in public
    assert "app.py" in public
    assert not harness.launcher.calls


@pytest.mark.parametrize(
    ("service_key", "kind", "reason", "code"),
    (
        ("python:app.py@8000", "restart_containers", "退出了", "not_eligible"),
        ("python:app.py@8000", "relaunch_python", "退出了", "no_launch_record"),
        ("docker:compose:photos", "restart_containers", "   ", "invalid_argument"),
    ),
)
def test_refusals_and_bad_values_are_normal_tool_results(
    tmp_path: Path, service_key: str, kind: str, reason: str, code: str
) -> None:
    harness = RepairHarness(tmp_path)
    output = call(
        runtime(harness, tmp_path),
        "propose_repair",
        {"service_key": service_key, "kind": kind, "reason": reason},
    )
    assert set(output) - {"manual_steps"} == {"proposed", "code", "message", "next_step"}
    assert output["proposed"] is False and output["code"] == code and output["message"]
    assert not harness.store.records


def test_approval_instruction_uses_custom_directory_only_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repair_id = OperationId.new()
    monkeypatch.setattr(
        "tunnelminion.repair.agent_tools.default_runtime_data_dir", lambda: tmp_path
    )
    command = f"tunnelminion repair-approve --repair-id {repair_id}"
    prefix = (
        "点地图上这台电脑头上的红色感叹号批准"
        "（10 分钟内有效；不批准就什么都不会做）。\n命令行后备："
    )
    assert repair_approval_instruction(repair_id, tmp_path) == f"{prefix}{command}"
    custom = tmp_path / "custom data"
    assert repair_approval_instruction(repair_id, custom) == (
        f'{prefix}{command} --data-dir "{custom.resolve()}"'
    )
    plain = Path("/tunnelminion-data")
    assert repair_approval_instruction(repair_id, plain) == (
        f"{prefix}{command} --data-dir {plain.resolve()}"
    )
    assert repair_approval_instruction(repair_id) == (
        "请到对方电脑的地图上点感叹号批准（10 分钟内有效；不批准就什么都不会做）。"
        f"\n命令行后备：{command}"
    )
