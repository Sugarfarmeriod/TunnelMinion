"""脱敏导出与完整卸载只处理 TunnelMinion 自有数据。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tunnelminion.agent.managed_node import (
    FileManagedNodeConfigRepository,
    ManagedNodeConfig,
    ManagedNodeSecretStoreKind,
)
from tunnelminion.coordinator.client_credentials import coordinator_refresh_name
from tunnelminion.coordinator.contracts import GatewayEndpoint
from tunnelminion.domain.identifiers import (
    ArtifactId,
    MemoryId,
    NetworkId,
    NodeId,
    RunId,
    ThreadId,
    ToolRunId,
)
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayPeerConfig,
    gateway_token_name,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.contracts import (
    CheckpointRecord,
    CheckpointStatus,
    LongTermMemory,
    MemoryKind,
    MemoryNamespace,
    ToolArtifact,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.configuration import (
    MODEL_API_KEY_NAME,
    FileModelConfigurationRepository,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.operations import (
    EXPORT_SCHEMA_VERSION,
    build_safe_export,
    uninstall_owned_data,
    write_safe_export,
)


class MemorySecretStore:
    """测试用内存秘密存储。"""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = values or {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def managed_config(node_id: NodeId) -> ManagedNodeConfig:
    """生成可安全导出的 managed node 非秘密配置。"""
    return ManagedNodeConfig(
        coordinator_endpoint="http://10.77.0.1:8790",
        network_id=NetworkId.new(),
        node_id=node_id,
        display_name="Windows A",
        platform=Platform.WINDOWS,
        gateway_endpoint=GatewayEndpoint(host="10.77.0.2", port=8787),
        pinned_fingerprints=frozenset({"a" * 64}),
        secret_store=ManagedNodeSecretStoreKind.RESTRICTED_FILE,
    )


def test_safe_export_uses_allowlist_and_excludes_secret_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "data"
    node = NodeId.new()
    root.mkdir()
    (root / "node-id").write_text(str(node), encoding="utf-8")
    FileModelConfigurationRepository(root / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://10.77.0.1:8082/v1", model="qwen")
    )
    expected_managed = managed_config(node)
    FileManagedNodeConfigRepository(root / "managed-node.json").save(expected_managed)
    peer = NodeId.new()
    FileGatewayConfigurationRepository(root / "gateway.json").save(
        GatewayConfiguration(
            bind=GatewayBindConfig(host="10.77.0.2", port=8787),
            peers=(
                GatewayPeerConfig(
                    node_id=peer,
                    host="10.77.0.1",
                    allowed_tools=frozenset({"get_node_summary"}),
                ),
            ),
        )
    )
    stores = SQLiteStores.open(root / "runtime.sqlite3")
    now = datetime(2026, 7, 18, tzinfo=UTC)
    checkpoint = CheckpointRecord(
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        status=CheckpointStatus.COMPLETED,
        public_state={"answer": "公开摘要"},
        updated_at=now,
    )
    memory = LongTermMemory(
        memory_id=MemoryId.new(),
        namespace=MemoryNamespace(user="local", network="home", node_id=node),
        kind=MemoryKind.NODE_ALIAS,
        content="B 是家里的 Mac",
        source="用户确认",
        user_confirmed=True,
        updated_at=now,
    )
    secret_artifact = "private tool artifact body that must never be exported"
    stores.checkpoints.put(checkpoint)
    stores.memories.put(memory)
    stores.artifacts.put(
        ToolArtifact(
            artifact_id=ArtifactId.new(),
            tool_run_id=ToolRunId.new(),
            content=secret_artifact,
            content_bytes=len(secret_artifact),
            content_hash="sha256:" + ("0" * 64),
            created_at=now,
        )
    )

    exported = build_safe_export(root, exported_at=now)
    serialized = json.dumps(exported, ensure_ascii=False)
    assert exported["schema_version"] == EXPORT_SCHEMA_VERSION
    assert exported["node_id"] == str(node)
    assert exported["checkpoints"] == [checkpoint.model_dump(mode="json")]
    assert exported["long_term_memories"] == [memory.model_dump(mode="json")]
    assert exported["operations"] == []
    assert exported["managed_node"] == expected_managed.model_dump(mode="json")
    assert secret_artifact not in serialized
    assert '"api_key"' not in serialized
    assert '"refresh_credential":' not in serialized
    excluded = exported["excluded_categories"]
    assert isinstance(excluded, list)
    assert "coordinator_refresh_credentials" in excluded


def test_write_export_handles_empty_data_and_posix_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tunnelminion import operations

    monkeypatch.setattr(operations.os, "name", "posix")
    output = tmp_path / "nested" / "export.json"
    write_safe_export(tmp_path / "missing", output)
    value = json.loads(output.read_text(encoding="utf-8"))
    assert value["node_id"] is None
    assert value["model"] is None
    assert value["gateway"] is None
    assert value["managed_node"] is None
    assert value["checkpoints"] == []
    assert value["operations"] == []
    monkeypatch.setattr(operations.os, "name", "nt")
    write_safe_export(tmp_path / "missing", tmp_path / "windows-export.json")


def test_uninstall_deletes_credentials_and_owned_files_but_preserves_unrelated(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    peer = NodeId.new()
    FileGatewayConfigurationRepository(root / "gateway.json").save(
        GatewayConfiguration(
            bind=GatewayBindConfig(host="10.77.0.2"),
            peers=(
                GatewayPeerConfig(
                    node_id=peer,
                    host="10.77.0.1",
                    allowed_tools=frozenset({"get_node_summary"}),
                ),
            ),
        )
    )
    for name in ("node-id", "model.json", "runtime.sqlite3-wal", "gateway-secret-store"):
        (root / name).write_text("owned", encoding="utf-8")
    secret_dir = root / "gateway-secrets"
    secret_dir.mkdir()
    (secret_dir / "orphan.secret").write_text("secret", encoding="utf-8")
    unrelated = root / "my-notes.txt"
    unrelated.write_text("keep", encoding="utf-8")
    model = MemorySecretStore({MODEL_API_KEY_NAME: "secret"})
    gateway = MemorySecretStore({gateway_token_name(peer): "tmn_secret"})
    managed = managed_config(peer)
    FileManagedNodeConfigRepository(root / "managed-node.json").save(managed)
    coordinator = MemorySecretStore(
        {coordinator_refresh_name(managed.network_id, managed.node_id): "refresh-secret"}
    )
    coordinator_dir = root / "coordinator-secrets"
    coordinator_dir.mkdir()
    (coordinator_dir / "orphan.secret").write_text("secret", encoding="utf-8")
    (root / "coordinator-checkpoint.json").write_text("{}", encoding="utf-8")

    removed = uninstall_owned_data(
        root,
        model_secrets=model,
        gateway_secrets=gateway,
        coordinator_secrets=coordinator,
    )

    assert removed
    assert model.values == {}
    assert gateway.values == {}
    assert coordinator.values == {}
    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert not secret_dir.exists()
    assert not coordinator_dir.exists()
    assert not (root / "managed-node.json").exists()
    assert not (root / "coordinator-checkpoint.json").exists()
    assert root.exists()


def test_uninstall_removes_empty_root_and_rejects_unsafe_layout(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    removed = uninstall_owned_data(
        root,
        model_secrets=MemorySecretStore(),
        gateway_secrets=MemorySecretStore(),
    )
    assert removed == (root,)
    assert not root.exists()

    unexpected = tmp_path / "unexpected"
    (unexpected / "gateway-secrets" / "nested").mkdir(parents=True)
    with pytest.raises(ValueError, match="非预期目录"):
        uninstall_owned_data(
            unexpected,
            model_secrets=MemorySecretStore(),
            gateway_secrets=MemorySecretStore(),
        )

    with pytest.raises(ValueError, match="根目录"):
        uninstall_owned_data(
            Path(Path.cwd().anchor),
            model_secrets=MemorySecretStore(),
            gateway_secrets=MemorySecretStore(),
        )

    unexpected_coordinator = tmp_path / "unexpected-coordinator"
    (unexpected_coordinator / "coordinator-secrets" / "nested").mkdir(parents=True)
    with pytest.raises(ValueError, match="非预期目录"):
        uninstall_owned_data(
            unexpected_coordinator,
            model_secrets=MemorySecretStore(),
            gateway_secrets=MemorySecretStore(),
        )
