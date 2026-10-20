"""使用当前模型和本进程临时监听，验收三次有界任务及显式续办。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import psutil

from tunnelminion.agent.conversation import InMemoryConversationService, RunView, StartRunInput
from tunnelminion.agent.langchain_model import TunnelMinionChatModel
from tunnelminion.agent.runtime import (
    AgentRunLimits,
    AgentStopReason,
    LangChainReadOnlyAgent,
    ServiceCheckTarget,
)
from tunnelminion.agent.service_observation import compute_observed_service_id
from tunnelminion.coordinator.contracts import ServiceProtocol
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.configuration import (
    FileModelConfigurationRepository,
    ModelConfigurationService,
)
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelProvider,
    ModelRequest,
    ModelResponse,
)
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.platforms.windows.adapters import NetworkListenersAdapter
from tunnelminion.platforms.windows.definitions import windows_tool_definitions
from tunnelminion.platforms.windows.models import NetworkListener
from tunnelminion.platforms.windows.system import PsutilSystemReader
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime

TOOLS = ("list_network_listeners",)
LIMITS = AgentRunLimits(max_model_rounds=4, max_tool_calls=6, timeout_seconds=180)


class FixtureReader(PsutilSystemReader):
    """只枚举本进程、本次端口的实际监听，不采集其他服务。"""

    def __init__(self, port: int) -> None:
        self.port = port
        self.calls = 0

    def listeners(self) -> tuple[NetworkListener, ...]:
        self.calls += 1
        process = psutil.Process()
        return tuple(
            NetworkListener(
                protocol="tcp",
                address=item.laddr.ip,
                port=item.laddr.port,
                pid=process.pid,
                process_name=process.name(),
            )
            for item in process.net_connections(kind="tcp")
            if item.status == psutil.CONN_LISTEN
            and item.laddr
            and (item.laddr.ip, item.laddr.port) == ("127.0.0.1", self.port)
        )


class RecordingProvider:
    """调用真实 Provider，只记录工具名与历史标记，不保存提示正文或隐藏推理。"""

    def __init__(self, provider: ModelProvider) -> None:
        self.provider = provider
        self.calls: list[dict[str, Any]] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return self.provider.capabilities

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        record: dict[str, Any] = {
            "available_tools": [item.name for item in request.tools],
            "historical_observation_present": any(
                item.role == "tool" and "untrusted-historical-tool-data" in (item.content or "")
                for item in request.messages
            ),
            "skill_method_present": any(
                item.role == "tool" and "investigation-method-not-evidence" in (item.content or "")
                for item in request.messages
            ),
        }
        self.calls.append(record)
        try:
            result = await self.provider.complete(request, cancellation)
        except BaseException as exc:
            record["error_type"] = type(exc).__name__
            raise
        record["selected_tools"] = [item.name for item in result.tool_calls]
        return result


def fixture_registry(reader: FixtureReader) -> ToolRegistry:
    """沿用真实监听适配器，只暴露本次端口且拒绝额外采集参数。"""
    registry = ToolRegistry()
    definition = next(item for item in windows_tool_definitions() if item.name == TOOLS[0])
    registry.register(
        definition.model_copy(
            update={
                "description": f"只读取本次临时服务 127.0.0.1:{reader.port} 的实际监听。",
                "input_schema": {"type": "object", "additionalProperties": False},
            }
        ),
        NetworkListenersAdapter(reader),
    )
    return registry


def public_run(run: RunView) -> dict[str, Any]:
    """报告仅包含本次临时任务的公开结果。"""
    return {
        "run_id": str(run.run_id),
        "thread_id": str(run.thread_id),
        "status": run.status.value,
        "error_code": run.error_code,
        "result": run.result.model_dump(mode="json") if run.result is not None else None,
    }


async def investigate(
    service: InMemoryConversationService, started: RunView, *, interrupt: bool = False
) -> RunView:
    """在真实工具返回后通过公开取消入口停止第二次调查。"""
    async for event in service.stream_events(started.run_id):
        if interrupt and event.tool_status == "success":
            service.cancel_run(started.run_id)
    final = service.get_run(started.run_id)
    print(json.dumps({"run": str(final.run_id), "status": final.status.value}), flush=True)
    return final


async def evaluate(
    root: Path, reader: FixtureReader, provider: RecordingProvider, *, prior_failed: bool
) -> dict[str, Any]:
    node = NodeId.new()
    target = ServiceCheckTarget(
        service_id=compute_observed_service_id(node, ServiceProtocol.TCP, "127.0.0.1", reader.port),
        node_id=node,
        display_name="本机临时验收服务",
        protocol=ServiceProtocol.TCP,
        port=reader.port,
    )
    registry = fixture_registry(reader)
    runtime = ToolRuntime(registry, Platform.WINDOWS, InMemoryAuditSink())
    stores = SQLiteStores.open(root / "tasks.sqlite3")

    def create_agent() -> LangChainReadOnlyAgent:
        return LangChainReadOnlyAgent(
            TunnelMinionChatModel(provider=provider), registry, runtime, Platform.WINDOWS
        )

    service = InMemoryConversationService(node, create_agent, stores.checkpoints)
    runs: list[dict[str, Any]] = []
    checks: dict[str, bool] = {}
    if not prior_failed:
        first = await investigate(
            service,
            await service.start_run(
                service.create_thread().thread_id,
                StartRunInput(
                    question="服务是否已经启动？请核对所选临时服务的监听。",
                    tool_names=TOOLS,
                    limits=LIMITS,
                ),
                target,
            ),
        )
        runs.append(public_run(first))
        checks["normal_question_completed"] = bool(
            first.result and first.result.stop_reason is AgentStopReason.COMPLETED
        )
        checks["normal_question_used_real_tool"] = bool(first.result and first.result.tool_calls)
        checks["normal_question_has_checked_fact"] = bool(
            first.result and first.result.evidence_answer.confirmed_facts
        )
        if any("error_type" in call for call in provider.calls):
            return {"runs": runs, "checks": checks, "stopped": "model_request_failed"}
    second = await investigate(
        service,
        await service.start_run(
            service.create_thread().thread_id,
            StartRunInput(
                question="服务是否已经启动？请先查阅目录中适用的调查技能，再核对所选临时服务的监听与本机连接范围。缺少的证据请保留未知。",
                tool_names=TOOLS,
                limits=LIMITS,
            ),
            target,
        ),
        interrupt=True,
    )
    runs.append(public_run(second))
    checks["status_question_entered_investigation"] = bool(
        second.result and second.result.tool_calls
    )
    checkpoint = stores.checkpoints.get(second.run_id)
    checks["interruption_preserved_actual_tool"] = bool(checkpoint and checkpoint.tool_run_ids)
    checks["second_run_cancelled"] = bool(
        second.result and second.result.stop_reason is AgentStopReason.CANCELLED
    )
    before_restore = (len(provider.calls), reader.calls)
    restored = InMemoryConversationService(node, create_agent, stores.checkpoints)
    checks["restore_did_not_replay"] = before_restore == (len(provider.calls), reader.calls)
    if not checks["second_run_cancelled"]:
        return {"runs": runs, "checks": checks, "stopped": "interruption_not_observed"}
    resume_offset = len(provider.calls)
    third = await investigate(
        restored,
        await restored.resume_run(
            second.run_id,
            question="继续原任务，重新核对当前监听，并区分上次检查和当前新检查各自能证明什么。",
            target=target,
        ),
    )
    runs.append(public_run(third))
    checks["same_thread_and_target_resumed"] = (
        third.thread_id == second.thread_id and restored.get_resume_target(third.run_id) == target
    )
    checks["resume_received_historical_observation"] = any(
        call["historical_observation_present"] for call in provider.calls[resume_offset:]
    )
    checks["resume_completed"] = bool(
        third.result and third.result.stop_reason is AgentStopReason.COMPLETED
    )
    checks["resume_has_fresh_checked_fact"] = bool(
        third.result and third.result.tool_calls and third.result.evidence_answer.confirmed_facts
    )
    checks["history_not_promoted_to_current_fact"] = bool(
        checkpoint
        and third.result
        and all(
            not set(fact.evidence_refs).intersection(str(item) for item in checkpoint.tool_run_ids)
            for fact in third.result.evidence_answer.confirmed_facts
        )
    )
    return {"runs": runs, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--model-data-dir", type=Path)
    parser.add_argument("--prior-failure", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check and (
        sys.platform != "win32" or args.output is None or args.model_data_dir is None
    ):
        parser.error("真实验收仅支持 Windows，必须明确提供 --model-data-dir 与 --output")
    prior = None
    if args.prior_failure is not None:
        prior = json.loads(args.prior_failure.read_text(encoding="utf-8"))
        if not (
            prior.get("executed_investigations") == 1
            and prior.get("maximum_investigations") == 3
            and prior.get("remaining_investigations") == 2
            and len(prior.get("runs", [])) == 1
            and prior["runs"][0]["status"] == "failed"
        ):
            parser.error("前次报告必须明确记录一次失败调查及剩余两次预算")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        reader = FixtureReader(listener.getsockname()[1])
        items = reader.listeners()
        assert len(items) == 1 and items[0].pid == psutil.Process().pid
        registry = fixture_registry(reader)
        assert tuple(item.name for item in registry.model_tools(Platform.WINDOWS)) == TOOLS
        assert (
            registry.model_tools(Platform.WINDOWS)[0].input_schema["additionalProperties"] is False
        )
        if args.self_check:
            print("临时监听与允许工具范围自检通过；未调用模型。")
            return 0
        model_path = args.model_data_dir.resolve() / "model.json"
        original_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        configuration = FileModelConfigurationRepository(model_path)
        config = configuration.load()
        assert config is not None, "当前没有配置模型"
        provider = RecordingProvider(
            ModelConfigurationService(configuration, KeyringSecretStore()).create_provider()
        )
        with tempfile.TemporaryDirectory(prefix="tm-task-live-") as temporary:
            result = asyncio.run(
                evaluate(Path(temporary), reader, provider, prior_failed=prior is not None)
            )
        result["model"] = config.model.rsplit("/", 1)[-1]
        result["source_revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
        result["recorded_at"] = datetime.now(UTC).isoformat()
        result["executed_investigations"] = len(result["runs"])
        result["total_investigations"] = len(result["runs"]) + (1 if prior else 0)
        result["maximum_investigations"] = 3
        result["prior_failure_report"] = (
            args.prior_failure.as_posix() if args.prior_failure is not None else None
        )
        result["success_scope"] = "current_source_checks_only"
        result["provider_calls"] = provider.calls
        result["temporary_state_removed"] = not Path(temporary).exists()
        result["model_configuration_unchanged"] = (
            hashlib.sha256(model_path.read_bytes()).hexdigest() == original_hash
        )
        result["skill_read"] = any(
            "read_investigation_skill" in call.get("selected_tools", []) for call in provider.calls
        ) and any(call["skill_method_present"] for call in provider.calls)
    result["temporary_listener_closed"] = reader.listeners() == ()
    checks = cast(dict[str, bool], result["checks"])
    result["passed"] = (
        len(result["runs"]) == (2 if prior else 3)
        and all(checks.values())
        and result["skill_read"]
        and result["temporary_state_removed"]
        and result["temporary_listener_closed"]
        and result["model_configuration_unchanged"]
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "output": str(args.output)}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
