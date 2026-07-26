"""Agent 本机 refresh 凭据的 keyring 兼容存储边界。"""

from __future__ import annotations

from tunnelminion.coordinator.contracts import NodeRegistrationResponse
from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.model.secrets import SecretStore


def coordinator_refresh_name(network_id: NetworkId, node_id: NodeId) -> str:
    """生成不含秘密的 keyring 条目名。"""
    return f"coordinator-refresh:{network_id}:{node_id}"


class AgentRefreshCredentialStore:
    """确保完整 refresh 凭据只交给操作系统秘密存储。"""

    def __init__(self, secrets: SecretStore) -> None:
        self._secrets = secrets

    def save(self, response: NodeRegistrationResponse) -> None:
        self._secrets.set(
            coordinator_refresh_name(
                response.identity.network_id,
                response.identity.node_id,
            ),
            response.refresh_credential,
        )

    def load(self, network_id: NetworkId, node_id: NodeId) -> str | None:
        return self._secrets.get(coordinator_refresh_name(network_id, node_id))

    def delete(self, network_id: NetworkId, node_id: NodeId) -> None:
        self._secrets.delete(coordinator_refresh_name(network_id, node_id))
