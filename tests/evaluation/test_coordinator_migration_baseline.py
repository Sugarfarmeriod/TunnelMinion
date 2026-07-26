"""Coordinator 迁移前基线必须与既有 A/B 机器证据一致。"""

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).parents[2]


def load(path: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((ROOT / path).read_text(encoding="utf-8")),
    )


def test_coordinator_migration_baseline_freezes_static_and_dynamic_metrics() -> None:
    baseline = load("evaluations/baselines/coordinator-migration-v1.json")
    gateway = load("evaluations/platform/ab-gateway-acceptance-2026-07-18.json")
    diagnostic = load("evaluations/platform/ab-cross-node-diagnostic-2026-07-18.json")
    context = load("evaluations/platform/ab-context-runtime-acceptance-2026-07-25.json")

    static = baseline["static_gateway"]
    assert static["endpoint"] == gateway["endpoint"]
    assert static["protocol"] == gateway["protocol"]
    assert static["unauthenticated_status"] == gateway["unauthenticated_status"]
    assert static["capability_count"] == len(gateway["capabilities"])
    assert static["elapsed_ms"] == gateway["elapsed_ms"]

    cross_node = baseline["static_cross_node_diagnostic"]
    assert cross_node["completed"] is (diagnostic["remote_error_code"] is None)
    assert cross_node["elapsed_ms"] == diagnostic["elapsed_ms"]
    assert cross_node["total_tokens"] == diagnostic["model_usage"]["total_tokens"]

    dynamic = baseline["dynamic_tool_selection"]
    assert dynamic["passed"] == context["passed"]
    assert dynamic["dynamic_tool_selected"] == context["checks"]["dynamic_tool_selected"]
    assert dynamic["combined_total_tokens"] == context["combined_model_usage"]["total_tokens"]
    assert dynamic["run_elapsed_ms"] == [
        run["elapsed_ms"] for run in context["conversation"]["runs"]
    ]


def test_coordinator_migration_baseline_requires_network_invariance() -> None:
    baseline = load("evaluations/baselines/coordinator-migration-v1.json")
    invariance = baseline["network_invariance"]

    assert invariance["gateway_port"] == 8787
    assert invariance["model_port"] == 8082
    assert invariance["coordinator_may_modify_wireguard_or_firewall"] is False
    assert all(
        invariance[key] is True
        for key in (
            "wireguard_config_metadata_unchanged",
            "wireguard_process_unchanged",
            "wireguard_interface_unchanged",
            "wireguard_routes_unchanged",
            "formal_listeners_and_docker_unchanged_after_safe_sharing",
        )
    )
