"""显式 A/B peer 配置与独立应用凭据生命周期测试。"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
    gateway_token_name,
    generate_gateway_token,
)
from tunnelminion.gateway.security import GatewayBindConfig, GatewayLimits
from tunnelminion.model.secrets import KeyringSecretStore, RestrictedFileSecretStore


class MemorySecrets:
    """测试用本机密钥环，不把值写入文件。"""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def peer(node_id: NodeId | None = None, *, host: str = "10.77.0.2") -> GatewayPeerConfig:
    """创建显式 peer 非秘密配置。"""
    return GatewayPeerConfig(
        node_id=node_id or NodeId.new(),
        host=host,
        port=8787,
        allowed_tools=frozenset({"get_node_summary", "list_network_listeners"}),
    )


def test_file_repository_round_trip_never_contains_token(tmp_path: Path) -> None:
    """配置文件只保存地址和允许列表，凭据格式不会落盘。"""
    path = tmp_path / "nested" / "gateway.json"
    repository = FileGatewayConfigurationRepository(path)
    assert repository.load() is None
    value = GatewayConfiguration(bind=GatewayBindConfig(host="10.77.0.1"), peers=(peer(),))
    repository.save(value)
    assert repository.load() == value
    content = path.read_text(encoding="utf-8")
    assert "tmn_" not in content
    assert "private" not in content.lower()
    repository.delete()
    repository.delete()
    assert repository.load() is None


def test_configure_provision_replace_revoke_and_delete(tmp_path: Path) -> None:
    """peer 可显式增加、更新、撤销和整体清理，token 只存在密钥环。"""
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    secrets = MemorySecrets()
    service = GatewayConfigurationService(repository, secrets)
    assert service.view().configured is False
    with pytest.raises(RuntimeError, match="尚未配置"):
        service.provision_peer(GatewayPeerInput(peer=peer(), token=generate_gateway_token()))

    configured = service.configure_local(GatewayBindConfig(host="10.77.0.1"))
    assert configured.configured is True
    assert configured.peers == ()
    first = peer()
    token = generate_gateway_token()
    assert token.startswith("tmn_")
    view = service.provision_peer(GatewayPeerInput(peer=first, token=token))
    assert view.peers[0].credential_configured is True
    assert secrets.values[gateway_token_name(first.node_id)] == token
    assert token not in (tmp_path / "gateway.json").read_text(encoding="utf-8")

    replacement = first.model_copy(update={"port": 9000})
    service.provision_peer(GatewayPeerInput(peer=replacement, token=generate_gateway_token()))
    second = peer()
    service.provision_peer(GatewayPeerInput(peer=second, token=generate_gateway_token()))
    assert [item.node_id for item in service.view().peers] == [first.node_id, second.node_id]
    assert service.view().peers[0].port == 9000

    limits = GatewayLimits(requests_per_minute=12)
    changed = service.configure_local(GatewayBindConfig(host="10.77.0.1"), limits)
    assert changed.limits == limits
    preserved = service.configure_local(GatewayBindConfig(host="10.77.0.1"))
    assert preserved.limits == limits
    policy = service.build_security_policy()
    assert policy.authenticate(f"Bearer {secrets.values[gateway_token_name(first.node_id)]}")

    with pytest.raises(KeyError, match="gateway_peer_not_found"):
        service.revoke_peer(NodeId.new())
    service.revoke_peer(first.node_id)
    assert gateway_token_name(first.node_id) not in secrets.values
    service.delete()
    assert repository.load() is None
    assert secrets.values == {}
    service.delete()


def test_configuration_rejects_wireguard_keys_and_missing_credentials(tmp_path: Path) -> None:
    """WireGuard 样式密钥不能复用，缺少应用 token 时网关拒绝启动。"""
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    secrets = MemorySecrets()
    service = GatewayConfigurationService(repository, secrets)
    service.configure_local(GatewayBindConfig(host="10.77.0.1"))
    value = peer()
    with pytest.raises(ValueError, match="tmn_"):
        service.provision_peer(
            GatewayPeerInput(
                peer=value,
                token="abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG=",
            )
        )
    with pytest.raises(ValidationError, match="WireGuard"):
        GatewayBindConfig(host="0.0.0.0")
    with pytest.raises(ValidationError, match="WireGuard"):
        _ = peer(host="8.8.8.8").endpoint()

    token = generate_gateway_token()
    service.provision_peer(GatewayPeerInput(peer=value, token=token))
    secrets.delete(gateway_token_name(value.node_id))
    assert service.view().peers[0].credential_configured is False
    with pytest.raises(RuntimeError, match="缺少网关凭据"):
        service.build_security_policy()

    empty_repository = FileGatewayConfigurationRepository(tmp_path / "empty.json")
    empty_service = GatewayConfigurationService(empty_repository, MemorySecrets())
    with pytest.raises(RuntimeError, match="尚未配置"):
        empty_service.revoke_peer(NodeId.new())
    with pytest.raises(RuntimeError, match="尚未配置"):
        empty_service.build_security_policy()

    no_peer = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "no-peer.json"), MemorySecrets()
    )
    no_peer.configure_local(GatewayBindConfig(host="10.77.0.1"))
    with pytest.raises(ValueError, match="至少需要一个"):
        no_peer.build_security_policy()


def test_gateway_secret_store_selection_is_explicit_and_persistent(tmp_path: Path) -> None:
    """默认保持 Keyring，显式无头选择才启用账户受限文件。"""
    assert isinstance(gateway_secret_store(tmp_path), KeyringSecretStore)
    selected = configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE)
    assert isinstance(selected, RestrictedFileSecretStore)
    assert isinstance(gateway_secret_store(tmp_path), RestrictedFileSecretStore)
