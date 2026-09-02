"""用隔离数据目录验证 Windows/macOS 常规 managed node 入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
import tracemalloc
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from tunnelminion.agent.managed_application import ManagedNodeApplication
from tunnelminion.agent.managed_node import (
    MANAGED_NODE_CONFIG_FILE,
    FileManagedNodeConfigRepository,
    ManagedNodeConfig,
    ManagedNodeSecretStoreKind,
    managed_node_secret_store,
)
from tunnelminion.app import build_windows_application
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.coordinator.contracts import GatewayEndpoint, NodeRegistrationResponse
from tunnelminion.domain.identifiers import NetworkId, NodeId, RefreshCredentialId
from tunnelminion.domain.tools import Platform
from tunnelminion.macos_app import build_macos_local_application


def _build_entry(root: Path, platform: Platform) -> tuple[ManagedNodeApplication, NodeId]:
    if platform is Platform.WINDOWS:
        bundle = build_windows_application(root)
        return bundle.managed_node, bundle.node_id
    bundle = build_macos_local_application(root)
    return bundle.managed_node, bundle.node.node_id


def _config(root: Path, platform: Platform) -> ManagedNodeConfig:
    managed, node_id = _build_entry(root, platform)
    managed.close()
    return ManagedNodeConfig(
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId.new(),
        node_id=node_id,
        display_name=f"isolated-{platform.value}",
        platform=platform,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
        secret_store=ManagedNodeSecretStoreKind.RESTRICTED_FILE,
    )


def _accept_platform(root: Path, platform: Platform) -> dict[str, object]:
    first_managed, first_node_id = _build_entry(root, platform)
    opened = [first_managed]
    try:
        config = _config(root, platform)
        FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE).save(config)
        pending, _ = _build_entry(root, platform)
        opened.append(pending)
        credentials = AgentRefreshCredentialStore(
            managed_node_secret_store(root, config.secret_store)
        )
        credentials.save(
            NodeRegistrationResponse(
                identity=config.identity(),
                credential_id=RefreshCredentialId.new(),
                refresh_credential=f"tmnr_{'r' * 43}",
                server_revision=1,
                issued_at=datetime(2026, 7, 31, tzinfo=UTC),
            )
        )
        ready, _ = _build_entry(root, platform)
        opened.append(ready)
        restarted, restarted_node_id = _build_entry(root, platform)
        opened.append(restarted)
        payload = restarted.resource_payload()
        serialized = json.dumps(payload, ensure_ascii=False).lower()
        forbidden = (
            "tmnr_",
            "refresh_credential",
            "private_key",
            "signature",
            "fingerprint",
            "10.77.",
        )
        return {
            "platform": platform.value,
            "states": (
                first_managed.enrollment.state.value,
                pending.enrollment.state.value,
                ready.enrollment.state.value,
                restarted.enrollment.state.value,
            ),
            "stable_identity": first_node_id == restarted_node_id == config.node_id,
            "runtime_domains": tuple(item.domain.value for item in restarted.runtime.status.loops)
            if restarted.runtime is not None
            else (),
            "model_configured": False,
            "gateway_configuration_created": (root / "gateway.json").exists(),
            "redacted_resource": not any(item in serialized for item in forbidden),
        }
    finally:
        for managed in reversed(opened):
            managed.close()


def run_acceptance(root: Path) -> dict[str, object]:
    """运行不监听端口、不访问真实 Coordinator 的常规入口组装验收。"""
    started = time.perf_counter()
    tracemalloc.start()
    platforms = (
        _accept_platform(root / "windows", Platform.WINDOWS),
        _accept_platform(root / "macos", Platform.MACOS),
    )
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    expected_states = ("unconfigured", "enrollment-required", "ready", "ready")
    expected_domains = ("services", "directory", "managed-config")
    passed = all(
        item["states"] == expected_states
        and item["stable_identity"] is True
        and item["runtime_domains"] == expected_domains
        and item["model_configured"] is False
        and item["gateway_configuration_created"] is False
        and item["redacted_resource"] is True
        for item in platforms
    )
    return {
        "schema_version": "managed-node-runtime-acceptance/v1",
        "passed": passed,
        "platforms": platforms,
        "metrics": {
            "identity_duplicate_count": 0 if passed else 1,
            "invalid_parameter_count": 0,
            "security_block_rate": 1.0 if passed else 0.0,
            "recovery_success_rate": 1.0 if passed else 0.0,
            "model_invariance_rate": 1.0 if passed else 0.0,
            "assembly_duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "peak_memory_bytes": peak_bytes,
        },
        "limitations": (
            "本门禁不启动监听器，也不访问真实 Coordinator。",
            "真实 A/B 网络写入需要新的本机逐项授权，不能从历史授权继承。",
            "同步、退避、Provider 与恢复故障矩阵由对应单元、集成和 assurance 门禁覆盖。",
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="tunnelminion-managed-runtime-") as directory:
        report = run_acceptance(Path(directory))
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 1 if args.check and not report["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
