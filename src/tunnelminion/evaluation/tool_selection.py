"""按问题挑工具的固定口径评测：同一组问题，检查模型每一轮实际看到了哪些工具。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from statistics import fmean
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import AgentTurnResult, LangChainReadOnlyAgent, ServiceCheckTarget
from tunnelminion.agent.service_observation import compute_observed_service_id
from tunnelminion.agent.tool_selection import REQUEST_MORE_TOOLS, ToolSelectionSettings
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.domain.tools import Platform
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ToolCall,
)
from tunnelminion.patrol.service import PATROL_TOOL_NAMES
from tunnelminion.platforms.windows.definitions import windows_tool_definitions
from tunnelminion.repair.agent_tools import register_repair_agent_tools
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolCallContext, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

# 网页对话每次允许的工具，与 frontend/src/features/chat/api.ts 的 allowedToolNames 一致。
WEB_TOOL_NAMES = (
    "get_node_summary",
    "get_wireguard_status",
    "list_network_listeners",
    "get_process_summary",
    "list_docker_services",
    "probe_service_reachability",
    "read_container_logs",
    "list_launch_records",
    "propose_repair",
)
TOOL_SETS: dict[str, tuple[str, ...]] = {"web": WEB_TOOL_NAMES, "patrol": PATROL_TOOL_NAMES}


class ToolSelectionCase(BaseModel):
    """一个问题和它期望的工具。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^[a-z0-9-]+$")
    question: str = Field(min_length=1)
    tool_set: Literal["web", "patrol"] = "web"
    application_kind: Literal["docker", "python", "program"] | None = None
    with_target: bool = False
    max_tools: int | None = Field(default=None, ge=3, le=12)
    must_see: tuple[str, ...] = Field(description="第一轮一定要看到的工具")
    must_hide: tuple[str, ...] = Field(default=(), description="第一轮不该看到的工具")
    acceptable_first_tools: tuple[str, ...] = Field(
        min_length=1, description="真实模型最先调用的诊断工具应该是其中之一"
    )
    expected_tools: tuple[str, ...] = Field(
        default=(), description="真实模型这次至少应该调用到的工具"
    )


class ToolSelectionDataset(BaseModel):
    """固定口径的数据集，连同假世界里各工具的固定返回值。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    dataset_id: str
    tool_outputs: dict[str, JsonValue]
    cases: tuple[ToolSelectionCase, ...] = Field(min_length=1)


class SelectionCaseResult(BaseModel):
    """一个问题在离线评测里的结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    visible_first_round: tuple[str, ...]
    visible_after_expand: tuple[str, ...]
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    over_limit: bool
    expansion_restores_all: bool
    passed: bool


class SelectionReport(BaseModel):
    """离线评测报告：全部通过才算挑选逻辑没有回归。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_id: str
    cases: int
    passed: int
    results: tuple[SelectionCaseResult, ...]


class CannedToolAdapter:
    """返回数据集里固定值的假工具，不访问系统。"""

    def __init__(self, output: JsonValue) -> None:
        self._output = output

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        del arguments, cancellation
        return self._output


class SelectionProbeProvider:
    """记录每一轮看到的工具；第一轮先请求更多工具，第二轮结束。"""

    def __init__(self) -> None:
        self.seen: list[tuple[str, ...]] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        del cancellation
        names = tuple(tool.name for tool in request.tools)
        self.seen.append(names)
        if len(self.seen) == 1 and REQUEST_MORE_TOOLS in names:
            return ModelResponse(
                tool_calls=(ToolCall(call_id="more", name=REQUEST_MORE_TOOLS, arguments={}),)
            )
        return ModelResponse(content="评测结束。")


def load_dataset(path: Path) -> ToolSelectionDataset:
    """读取并校验数据集。"""
    return ToolSelectionDataset.model_validate_json(path.read_text(encoding="utf-8"))


def build_registry(tool_outputs: dict[str, JsonValue]) -> ToolRegistry:
    """用真实的工具名字和说明、固定返回值的假适配器组装注册表。"""
    source = ToolRegistry()
    # 只借用修复工具的定义；适配器不会被调用，依赖用占位值。
    placeholder = cast(Any, None)
    repair_definitions = register_repair_agent_tools(
        source,
        containers=placeholder,
        launch_records=placeholder,
        host=placeholder,
        marks=placeholder,
        repair_service=placeholder,
        data_dir=Path("."),
    )
    registry = ToolRegistry()
    for definition in (*windows_tool_definitions(), *repair_definitions):
        output = tool_outputs.get(definition.name, {"items": []})
        registry.register(definition, CannedToolAdapter(output))
    return registry


def build_agent(
    provider: ModelProvider,
    registry: ToolRegistry,
    settings: ToolSelectionSettings,
) -> LangChainReadOnlyAgent:
    """组装和生产一致的 Agent，只换掉模型和工具适配器。"""
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    return LangChainReadOnlyAgent(
        TunnelMinionChatModel(provider=provider),
        registry,
        runtime,
        Platform.WINDOWS,
        tool_selection=settings,
    )


def case_inputs(
    case: ToolSelectionCase,
) -> tuple[ToolCallContext, tuple[str, ...], ServiceCheckTarget | None]:
    """为一个问题生成调用上下文、允许的工具和可选的所选服务。"""
    node = NodeId.new()
    context = ToolCallContext(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        caller_node_id=node,
        execution_node_id=node,
    )
    target = (
        ServiceCheckTarget(
            service_id=compute_observed_service_id(node, ServiceProtocol.TCP, "127.0.0.1", 8080),
            node_id=node,
            display_name="相册",
            protocol=ServiceProtocol.TCP,
            port=8080,
            application_kind=case.application_kind,
        )
        if case.with_target
        else None
    )
    return context, TOOL_SETS[case.tool_set], target


async def run_offline(dataset: ToolSelectionDataset) -> SelectionReport:
    """用假模型跑真实 Agent，按“该看到的看到、不该看到的没看到、不超上限”打分。"""
    registry = build_registry(dataset.tool_outputs)
    results: list[SelectionCaseResult] = []
    for case in dataset.cases:
        provider = SelectionProbeProvider()
        agent = build_agent(provider, registry, ToolSelectionSettings(max_tools=case.max_tools))
        context, allowed, target = case_inputs(case)
        await agent.run(case.question, context, allowed, target=target)
        first = provider.seen[0]
        after = provider.seen[1] if len(provider.seen) > 1 else first
        diagnostic = [name for name in first if name in allowed]
        missing = tuple(name for name in case.must_see if name not in first)
        unexpected = tuple(name for name in case.must_hide if name in first)
        over_limit = case.max_tools is not None and len(diagnostic) > case.max_tools
        restores = set(allowed) <= set(after) and REQUEST_MORE_TOOLS not in after
        results.append(
            SelectionCaseResult(
                case_id=case.case_id,
                visible_first_round=first,
                visible_after_expand=after,
                missing=missing,
                unexpected=unexpected,
                over_limit=over_limit,
                expansion_restores_all=restores,
                passed=not missing and not unexpected and not over_limit and restores,
            )
        )
    return SelectionReport(
        dataset_id=dataset.dataset_id,
        cases=len(results),
        passed=sum(item.passed for item in results),
        results=tuple(results),
    )


def report_json(report: BaseModel) -> str:
    """稳定排版的报告文本。"""
    return json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"


# 模型声称“没有某某工具 / 查不了 Docker”的说法；本次要消除的正是这类回答。
_MISSING_TOOL_CLAIM = re.compile(
    r"没有[^。\n]{0,12}(?:工具|权限)|(?:无法|不能)(?:查看|访问|获取|检查)[^。\n]{0,12}"
    r"(?:docker|容器)|no [a-z ]{0,24}tool",
    re.IGNORECASE,
)


class RealCaseRun(BaseModel):
    """真实模型跑一个问题的一次结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    variant: str
    round_index: int = Field(ge=1)
    tools_called: tuple[str, ...]
    first_tool: str | None
    first_tool_ok: bool
    expected_covered: bool
    claimed_missing_tool: bool
    asked_for_more: bool
    model_rounds: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    stop_reason: str


class VariantSummary(BaseModel):
    """一组配置（A 现状 / B 挑工具）的汇总指标。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    variant: str
    runs: int
    first_tool_hits: int
    expected_covered: int
    missing_tool_claims: int
    asked_for_more: int
    mean_model_rounds: float
    mean_total_tokens: float


def score_run(
    case: ToolSelectionCase,
    variant: str,
    round_index: int,
    result: AgentTurnResult,
    requested_tools: tuple[str, ...],
) -> RealCaseRun:
    """按实际执行过的诊断工具打分；查阅方法和请求更多工具不算诊断。"""
    called = tuple(item.tool_name for item in result.evidence_answer.evidence)
    first = called[0] if called else None
    return RealCaseRun(
        case_id=case.case_id,
        variant=variant,
        round_index=round_index,
        tools_called=called,
        first_tool=first,
        first_tool_ok=first in case.acceptable_first_tools,
        expected_covered=all(name in called for name in case.expected_tools),
        claimed_missing_tool=bool(_MISSING_TOOL_CLAIM.search(result.answer)),
        asked_for_more=REQUEST_MORE_TOOLS in requested_tools,
        model_rounds=result.model_rounds,
        tool_calls=result.tool_calls,
        total_tokens=result.usage.total_tokens,
        stop_reason=result.stop_reason.value,
    )


def failed_run(
    case: ToolSelectionCase, variant: str, round_index: int, error_code: str
) -> RealCaseRun:
    """模型调用失败的一次：照常计入次数，所有命中项都算没做到。"""
    return RealCaseRun(
        case_id=case.case_id,
        variant=variant,
        round_index=round_index,
        tools_called=(),
        first_tool=None,
        first_tool_ok=False,
        expected_covered=False,
        claimed_missing_tool=False,
        asked_for_more=False,
        model_rounds=0,
        tool_calls=0,
        total_tokens=0,
        stop_reason=f"provider-error:{error_code}",
    )


def summarize(runs: tuple[RealCaseRun, ...]) -> tuple[VariantSummary, ...]:
    """按配置汇总；顺序与第一次出现的顺序一致。"""
    variants = tuple(dict.fromkeys(item.variant for item in runs))
    summaries: list[VariantSummary] = []
    for variant in variants:
        group = [item for item in runs if item.variant == variant]
        summaries.append(
            VariantSummary(
                variant=variant,
                runs=len(group),
                first_tool_hits=sum(item.first_tool_ok for item in group),
                expected_covered=sum(item.expected_covered for item in group),
                missing_tool_claims=sum(item.claimed_missing_tool for item in group),
                asked_for_more=sum(item.asked_for_more for item in group),
                mean_model_rounds=round(fmean(item.model_rounds for item in group), 2),
                mean_total_tokens=round(fmean(item.total_tokens for item in group), 1),
            )
        )
    return tuple(summaries)


def summary_markdown(label: str, summaries: tuple[VariantSummary, ...]) -> str:
    """一页中文摘要，方便贴进 PR 或报告目录。"""
    lines = [
        f"# 挑工具前后对比：{label}",
        "",
        "| 配置 | 次数 | 先调对工具 | 调齐期望工具 | 说“没有工具” "
        "| 请求更多工具 | 平均轮数 | 平均 token |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in summaries:
        lines.append(
            f"| {item.variant} | {item.runs} | {item.first_tool_hits}/{item.runs} "
            f"| {item.expected_covered}/{item.runs} | {item.missing_tool_claims} "
            f"| {item.asked_for_more} | {item.mean_model_rounds} | {item.mean_total_tokens} |"
        )
    return "\n".join(lines) + "\n"
