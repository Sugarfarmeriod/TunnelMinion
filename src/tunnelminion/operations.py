"""本地数据的脱敏导出与 TunnelMinion 自有数据清理。"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from tunnelminion.agent.managed_node import (
    MANAGED_NODE_CONFIG_FILE,
    FileManagedNodeConfigRepository,
    managed_node_secret_store,
)
from tunnelminion.coordinator.client_credentials import AgentRefreshCredentialStore
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    gateway_secret_store,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.configuration import (
    MODEL_API_KEY_NAME,
    FileModelConfigurationRepository,
)
from tunnelminion.model.secrets import KeyringSecretStore, SecretStore

EXPORT_SCHEMA_VERSION = "tunnelminion-export/v1"
_OWNED_FILES = (
    "node-id",
    "model.json",
    "runtime.sqlite3",
    "runtime.sqlite3-wal",
    "runtime.sqlite3-shm",
    "gateway.json",
    "gateway-secret-store",
    MANAGED_NODE_CONFIG_FILE,
    "coordinator-checkpoint.json",
    "network-sync.sqlite3",
    "network-sync.sqlite3-wal",
    "network-sync.sqlite3-shm",
    "managed-network.sqlite3",
    "managed-network.sqlite3-wal",
    "managed-network.sqlite3-shm",
    "governance.sqlite3",
    "governance.sqlite3-wal",
    "governance.sqlite3-shm",
    "network-operations.sqlite3",
    "network-operations.sqlite3-wal",
    "network-operations.sqlite3-shm",
)


def build_safe_export(
    data_dir: Path,
    *,
    exported_at: datetime | None = None,
) -> dict[str, JsonValue]:
    """按允许列表导出公开状态，永不读取密钥或工具 artifact 正文。"""
    node_path = data_dir / "node-id"
    model = FileModelConfigurationRepository(data_dir / "model.json").load()
    gateway = FileGatewayConfigurationRepository(data_dir / "gateway.json").load()
    managed_node = FileManagedNodeConfigRepository(data_dir / MANAGED_NODE_CONFIG_FILE).load()
    checkpoints: list[JsonValue] = []
    memories: list[JsonValue] = []
    operations: list[JsonValue] = []
    database_path = data_dir / "runtime.sqlite3"
    if database_path.exists():
        stores = SQLiteStores.open(database_path)
        checkpoints = [item.model_dump(mode="json") for item in stores.checkpoints.list_all()]
        memories = [item.model_dump(mode="json") for item in stores.memories.list_all()]
        operations = [item.model_dump(mode="json") for item in stores.operations.list_summaries()]

    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_at": (exported_at or datetime.now(UTC)).isoformat(),
        "node_id": node_path.read_text(encoding="utf-8").strip() if node_path.exists() else None,
        "model": model.model_dump(mode="json") if model is not None else None,
        "gateway": gateway.model_dump(mode="json") if gateway is not None else None,
        "managed_node": (
            managed_node.model_dump(mode="json") if managed_node is not None else None
        ),
        "checkpoints": checkpoints,
        "long_term_memories": memories,
        "operations": operations,
        "excluded_categories": [
            "model_api_keys",
            "gateway_tokens",
            "wireguard_secrets",
            "tool_artifact_contents",
            "temporary_access_credentials",
            "coordinator_enrollment_tokens",
            "coordinator_refresh_credentials",
            "coordinator_access_assertions",
            "coordinator_checkpoints",
            "managed_config_envelopes",
            "authorization_headers",
            "remote_untrusted_bodies",
        ],
    }


def write_safe_export(data_dir: Path, output: Path) -> None:
    """以原子替换方式写入 UTF-8 JSON，并在 POSIX 上收紧文件权限。"""
    value = build_safe_export(data_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(f"{output.suffix}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(temporary, 0o600)
    temporary.replace(output)


def uninstall_owned_data(
    data_dir: Path,
    *,
    model_secrets: SecretStore | None = None,
    gateway_secrets: SecretStore | None = None,
    coordinator_secrets: SecretStore | None = None,
) -> tuple[Path, ...]:
    """删除应用凭据与已知自有文件，但保留 WireGuard 和无关用户文件。"""
    root = data_dir.resolve()
    if root == Path(root.anchor):
        raise ValueError("拒绝把文件系统根目录作为 TunnelMinion 数据目录")

    model_store = model_secrets or KeyringSecretStore()
    model_store.delete(MODEL_API_KEY_NAME)
    managed_repository = FileManagedNodeConfigRepository(root / MANAGED_NODE_CONFIG_FILE)
    managed_config = managed_repository.load()
    if managed_config is not None:
        coordinator_store = coordinator_secrets or managed_node_secret_store(
            root, managed_config.secret_store
        )
        AgentRefreshCredentialStore(coordinator_store).delete(
            managed_config.network_id,
            managed_config.node_id,
        )
    gateway_service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        gateway_secrets or gateway_secret_store(root),
    )
    gateway_service.delete()

    removed: list[Path] = []
    for name in _OWNED_FILES:
        path = root / name
        if path.exists():
            path.unlink()
            removed.append(path)

    secret_dir = root / "gateway-secrets"
    if secret_dir.exists():
        for path in secret_dir.iterdir():
            if not path.is_file():
                raise ValueError("gateway-secrets 中存在非预期目录，已停止清理")
            path.unlink()
            removed.append(path)
        secret_dir.rmdir()
        removed.append(secret_dir)

    coordinator_secret_dir = root / "coordinator-secrets"
    if coordinator_secret_dir.exists():
        for path in coordinator_secret_dir.iterdir():
            if not path.is_file():
                raise ValueError("coordinator-secrets 中存在非预期目录，已停止清理")
            path.unlink()
            removed.append(path)
        coordinator_secret_dir.rmdir()
        removed.append(coordinator_secret_dir)

    if root.exists() and not any(root.iterdir()):
        root.rmdir()
        removed.append(root)
    return tuple(removed)
