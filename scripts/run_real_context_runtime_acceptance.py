"""组合真实连续对话、动态工具选择、跨节点诊断与事实优先级验收。"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from tunnelminion.agent.context_contracts import ContextFact, FactSource
from tunnelminion.agent.conversation import RunEvent, RunStatus, StartRunInput
from tunnelminion.agent.history import FactResolver
from tunnelminion.app import build_windows_application

ALLOWED_TOOLS = (
    "get_node_summary",
    "get_wireguard_status",
    "probe_service_reachability",
)


async def _run_conversation(data_dir: Path | None) -> dict[str, Any]:
    """在同一 thread 连续运行两轮真实模型，并只保留公开事件与资源指标。"""
    application = build_windows_application(data_dir)
    conversations = application.conversation_service
    thread = conversations.create_thread()
    questions = (
        "旧记录说 B 模型服务端口是 8080。请检查本机节点和 WireGuard 状态，"
        "不要把这条旧记录当成实时事实。",
        "继续上一轮：现在请从 A 实时探测 10.77.0.1:8082，说明是否可达，并引用这次工具证据。",
    )
    runs: list[dict[str, JsonValue]] = []
    for question in questions:
        started = await conversations.start_run(
            thread.thread_id,
            StartRunInput(question=question, tool_names=ALLOWED_TOOLS),
        )
        events = [event async for event in conversations.stream_events(started.run_id)]
        final = conversations.get_run(started.run_id)
        tool_events = _successful_tool_events(events)
        result = final.result
        runs.append(
            {
                "run_id": str(final.run_id),
                "status": final.status.value,
                "actual_tool_names": [event.tool_name for event in tool_events],
                "tool_run_ids": [event.tool_run_id for event in tool_events],
                "model_rounds": result.model_rounds if result is not None else 0,
                "elapsed_ms": result.elapsed_ms if result is not None else 0,
                "usage": (result.usage.model_dump(mode="json") if result is not None else None),
                "context_snapshot_count": (
                    len(result.context_records) if result is not None else 0
                ),
                "failure_count": len(result.failures) if result is not None else 0,
            }
        )
    detail = conversations.get_thread(thread.thread_id)
    return {
        "thread_id": str(thread.thread_id),
        "message_count": detail.thread.message_count,
        "same_thread_continuation": detail.thread.message_count == 4,
        "allowed_tools": list(ALLOWED_TOOLS),
        "runs": runs,
    }


def _successful_tool_events(events: list[RunEvent]) -> tuple[RunEvent, ...]:
    return tuple(
        event
        for event in events
        if event.tool_name is not None
        and event.tool_run_id is not None
        and event.tool_status == "success"
    )


def _load_diagnostic(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _build_report(
    conversation: dict[str, Any],
    diagnostic: dict[str, Any],
) -> dict[str, Any]:
    """把模型行为和确定性证据组合为不含凭据的最终验收结论。"""
    selected = tuple(
        item
        for item in cast(list[dict[str, Any]], diagnostic["diagnostics"])
        if item["port"] == 8082
    )
    facts = (
        ContextFact(
            key="model.service.port",
            value="8080",
            source=FactSource.HISTORY,
            source_id="thread:stale-record",
        ),
        ContextFact(
            key="model.service.port",
            value="8082",
            source=FactSource.REALTIME_EVIDENCE,
            source_id="tool:probe-service-reachability",
        ),
    )
    resolved, conflicts = FactResolver().resolve(facts)
    runs = cast(list[dict[str, Any]], conversation["runs"])
    actual_tools = {
        tool_name for run in runs for tool_name in cast(list[str], run["actual_tool_names"])
    }
    evidence_ids = (
        cast(list[str], selected[0]["evidence_tool_run_ids"]) if len(selected) == 1 else []
    )
    answer = cast(str, diagnostic["answer"])
    checks: dict[str, bool] = {
        "continued_same_thread": bool(conversation["same_thread_continuation"]),
        "both_runs_completed": all(run["status"] == RunStatus.COMPLETED.value for run in runs),
        "dynamic_tool_selected": (
            bool(actual_tools)
            and actual_tools <= set(ALLOWED_TOOLS)
            and "probe_service_reachability" in actual_tools
        ),
        "remote_diagnostic_completed": (
            diagnostic["model_error_code"] is None
            and diagnostic["remote_error_code"] is None
            and {
                "get_node_summary",
                "list_network_listeners",
                "get_process_summary",
                "list_docker_services",
            }
            <= {
                item["tool_name"]
                for item in cast(list[dict[str, Any]], diagnostic["a_gateway_audit_records"])
            }
        ),
        "realtime_probe_reachable": (
            len(selected) == 1 and selected[0]["reachability"] == "reachable"
        ),
        "realtime_fact_supersedes_history": (
            resolved[0].value == "8082"
            and len(conflicts) == 1
            and conflicts[0].stale_value == "8080"
        ),
        "answer_cites_evidence": bool(evidence_ids)
        and all(evidence_id in answer for evidence_id in evidence_ids),
        "no_runtime_failure": all(run["failure_count"] == 0 for run in runs),
    }
    total_usage = {
        name: sum(
            cast(dict[str, int], run["usage"])[name] for run in runs if run["usage"] is not None
        )
        + cast(dict[str, int], diagnostic["model_usage"])[name]
        for name in ("input_tokens", "output_tokens", "total_tokens")
    }
    return {
        "schema_version": 1,
        "acceptance": "agent-context-runtime-windows-a-macos-b",
        "passed": all(checks.values()),
        "checks": checks,
        "conversation": conversation,
        "remote_diagnostic": {
            "endpoint": diagnostic["endpoint"],
            "target_host": diagnostic["target_host"],
            "remote_node_id": diagnostic["remote_node_id"],
            "selected_port": diagnostic["selected_port"],
            "reachability": selected[0]["reachability"] if len(selected) == 1 else None,
            "evidence_tool_run_ids": evidence_ids,
            "elapsed_ms": diagnostic["elapsed_ms"],
            "model_usage": diagnostic["model_usage"],
        },
        "fact_precedence": {
            "stale_history_value": "8080",
            "selected_realtime_value": resolved[0].value,
            "selected_source": resolved[0].source.value,
            "conflict_count": len(conflicts),
        },
        "combined_model_usage": total_usage,
        "excluded_categories": diagnostic["excluded_categories"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--diagnostic",
        type=Path,
        default=Path("evaluations/platform/ab-context-runtime-diagnostic-2026-07-25.json"),
    )
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    conversation = asyncio.run(_run_conversation(args.data_dir))
    report = _build_report(conversation, _load_diagnostic(args.diagnostic))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 1 if args.check and not report["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
