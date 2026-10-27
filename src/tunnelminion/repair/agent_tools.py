"""本机 Agent 的补充取证与待批准修复工具。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from tunnelminion.agent.delegation import current_delegation
from tunnelminion.domain.delegation import DelegationProposedRepair
from tunnelminion.domain.identifiers import DelegationId, OperationId
from tunnelminion.domain.service_marks import MARK_KEY_PATTERN, ServiceMark
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.repair.contracts import (
    REPAIR_AUTHORIZATION_SECONDS,
    ContainerRuntime,
    HostInspector,
    LaunchRecordStore,
    RepairKind,
    RepairOrigin,
    RepairOriginKind,
    RepairStore,
)
from tunnelminion.repair.eligibility import RepairRefusal
from tunnelminion.repair.service import RepairService
from tunnelminion.runtime.profile import default_runtime_data_dir
from tunnelminion.tools.contracts import ToolAdapter, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import current_tool_call_context


def repair_approval_instruction(repair_id: OperationId, data_dir: Path | None = None) -> str:
    """优先引导地图批准，命令行只作后备且不向对端透露数据目录。"""
    prefix = (
        "请到对方电脑的地图上点感叹号批准"
        if data_dir is None
        else "点地图上这台电脑头上的红色感叹号批准"
    )
    command = f"tunnelminion repair-approve --repair-id {repair_id}"
    if data_dir is not None and data_dir.resolve() != default_runtime_data_dir().resolve():
        path = str(data_dir.resolve())
        # 模型转述时常把英文引号换成中文引号，命令就跑不了；路径没有空格时不加引号。
        command += (
            f' --data-dir "{path}"' if any(c.isspace() for c in path) else f" --data-dir {path}"
        )
    return f"{prefix}（10 分钟内有效；不批准就什么都不会做）。\n命令行后备：{command}"


def proposed_repairs_for_delegation(
    store: RepairStore, delegation_id: DelegationId
) -> tuple[DelegationProposedRepair, ...]:
    """从本机记录提取本次委派的修复摘要，不回传路径、启动参数或执行命令。"""
    return tuple(
        DelegationProposedRepair(
            repair_id=item.plan.operation_id,
            service_name=item.plan.service_name,
            action=item.plan.action_summary,
            status=item.status.value,
            how_to_approve=repair_approval_instruction(item.plan.operation_id),
            expires_at=item.plan.created_at + timedelta(seconds=REPAIR_AUTHORIZATION_SECONDS),
        )
        for item in store.list_all()
        if item.plan.origin.kind is RepairOriginKind.DELEGATION
        and item.plan.origin.delegation_id == delegation_id
    )[:3]


class ReadContainerLogsAdapter:
    def __init__(self, containers: ContainerRuntime) -> None:
        self._containers = containers

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        service_key = cast(str, arguments["service_key"])
        compose = service_key.startswith("docker:compose:")
        name = service_key.removeprefix("docker:compose:" if compose else "docker:")
        items = await self._containers.list_containers(
            compose_project=name if compose else None,
            container_name=None if compose else name,
        )
        output: dict[str, JsonValue] = {
            "service_key": service_key,
            "docker_available": items is not None,
            "containers": [],
            "message": "",
        }
        if items is None:
            output["message"] = "Docker 没开，请先打开 Docker Desktop 或 OrbStack。"
            return output
        if not items:
            output["message"] = "没有找到这个容器或容器组，可能已经被删除了。"
            return output
        output["containers"] = [
            {
                "name": item.name,
                "status": item.status,
                "running": item.running,
                "log_tail": await self._containers.logs_tail(
                    item.container_id, lines=int(cast(int, arguments.get("lines", 40)))
                ),
            }
            for item in items[:5]
        ]
        output["message"] = "已读取最后几行日志，密码、令牌等敏感内容已去掉；最多显示前 5 个容器。"
        return output


class ListLaunchRecordsAdapter:
    def __init__(
        self,
        records: LaunchRecordStore,
        host: HostInspector,
        marks: Callable[[], Mapping[str, ServiceMark]],
    ) -> None:
        self._records = records
        self._host = host
        self._marks = marks

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        records: list[JsonValue] = []
        marks = self._marks()
        for launch in sorted(
            self._records.list_all(), key=lambda item: item.recorded_at, reverse=True
        )[:20]:
            entry = launch.service_key.removeprefix("python:").rsplit("@", 1)[0]
            running = any(
                (owner := self._host.port_owner(port, launch)) is not None and owner.matches_launch
                for port in launch.ports
            )
            mark = marks.get(launch.service_key)
            ports = "、".join(str(port) for port in launch.ports)
            state = "现在正在运行" if running else "现在没有在运行"
            records.append(
                {
                    "service_key": launch.service_key,
                    "entry": entry,
                    "ports": list(launch.ports),
                    "recorded_at": launch.recorded_at.isoformat(),
                    "running": running,
                    "mark": mark.value if mark is not None else None,
                    "summary": f"有启动记录：入口 {entry}，上次在 {ports} 端口，{state}",
                }
            )
        return {"records": records}


class ProposeRepairAdapter:
    def __init__(self, service: RepairService, data_dir: Path) -> None:
        self._service = service
        self._data_dir = data_dir

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        context = current_tool_call_context.get()
        delegation = current_delegation.get()
        origin = RepairOrigin(
            kind=RepairOriginKind.DELEGATION if delegation else RepairOriginKind.CONVERSATION,
            thread_id=context.thread_id,
            run_id=context.run_id,
            delegation_id=delegation.delegation_id if delegation else None,
        )
        try:
            record = await self._service.propose(
                cast(str, arguments["service_key"]),
                RepairKind(cast(str, arguments["kind"])),
                cast(str, arguments["reason"]),
                origin,
                actor=f"delegation:{delegation.caller_node_id}" if delegation else "agent",
            )
        except RepairRefusal as exc:
            return {"proposed": False, **exc.error.model_dump(mode="json")}
        except ValueError:
            return {
                "proposed": False,
                "code": "invalid_argument",
                "message": "服务身份、修法或理由不合适，不能生成这个修复。",
                "next_step": (
                    "请逐字使用工具给出的服务身份，并选择对应的修法，理由用一句大白话说明。"
                ),
            }
        plan = record.plan
        return {
            "proposed": True,
            "repair_id": str(plan.operation_id),
            "status": record.status.value,
            "service_name": plan.service_name,
            "action": plan.action_summary,
            "impact": plan.impact_summary,
            "verification": plan.verification_summary,
            "on_failure": plan.failure_summary,
            "expires_in_minutes": 10,
            "how_to_approve": repair_approval_instruction(
                plan.operation_id, None if delegation else self._data_dir
            ),
        }


def register_repair_agent_tools(
    registry: ToolRegistry,
    *,
    containers: ContainerRuntime,
    launch_records: LaunchRecordStore,
    host: HostInspector,
    marks: Callable[[], Mapping[str, ServiceMark]],
    repair_service: RepairService,
    data_dir: Path,
) -> tuple[ToolDefinition, ...]:
    definitions: tuple[tuple[str, str, dict[str, JsonValue], list[JsonValue], ToolAdapter], ...] = (
        (
            "read_container_logs",
            "读取一个 Docker 容器（或 compose 组里每个容器）最后几十行日志，"
            "已去掉密码、令牌等敏感内容，"
            "用来判断容器为什么退出或不正常。只读，不会启动或重启容器。"
            "service_key 用 docker:<容器名> 或 docker:compose:<项目名>。",
            {
                "service_key": {
                    "type": "string",
                    "pattern": r"^docker:(?:compose:)?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?![\s\S])",
                },
                "lines": {"type": "integer", "minimum": 10, "maximum": 80, "default": 40},
            },
            ["service_key"],
            ReadContainerLogsAdapter(containers),
        ),
        (
            "list_launch_records",
            "列出这台电脑记得启动方式的 Python 脚本：入口文件、上次监听的端口、记下的时间、"
            "现在是否还在运行、用户标记。只给摘要，不含完整命令和路径。"
            "脚本退出后，靠这里判断能不能按原来的方式重新拉起。",
            {},
            [],
            ListLaunchRecordsAdapter(launch_records, host, marks),
        ),
        (
            "propose_repair",
            "提出一个修法，交给这台电脑的主人批准。它只生成一条待批准的修复，不会执行任何东西；"
            "主人批准后由本机固定流程执行并自己验证。只有两种修法：restart_containers"
            "（重启 Docker 容器或 compose 组，service_key 用 docker:<容器名> 或 "
            "docker:compose:<项目名>）；"
            "relaunch_python（按启动记录重新拉起已经退出的 Python 脚本，service_key 用 "
            "list_launch_records 给出的身份）。reason 用一句大白话写清依据，不要写命令，"
            "写了也不会执行。修不了时会返回原因和下一步，照实告诉用户。",
            {
                "service_key": {"type": "string", "pattern": MARK_KEY_PATTERN},
                "kind": {"type": "string", "enum": [kind.value for kind in RepairKind]},
                "reason": {"type": "string", "minLength": 1, "maxLength": 500},
            },
            ["service_key", "kind", "reason"],
            ProposeRepairAdapter(repair_service, data_dir),
        ),
    )
    registered: list[ToolDefinition] = []
    for name, description, properties, required, adapter in definitions:
        definition = ToolDefinition(
            name=name,
            version=ProtocolVersion(major=1, minor=0),
            description=description,
            input_schema={
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
            output_schema={"type": "object"},
            risk_level=RiskLevel.READ_ONLY,
            platforms=frozenset({Platform.WINDOWS, Platform.MACOS}),
            timeout_seconds=120,
            max_result_bytes=64_000,
            data_sensitivity=DataSensitivity.SYSTEM_METADATA,
        )
        registry.register(definition, adapter)
        registered.append(definition)
    return tuple(registered)
