"""我的电脑命令的加入、秘密落盘和离线移除提示。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from tests.trust.test_identity import MemorySecrets
from tests.trust.test_own_devices import Mesh, computer

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import JoinCode, JoinCodeKind, SignaturePurpose
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewaySecretStoreKind,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import SecretStore
from tunnelminion.trust.cli import owner_command
from tunnelminion.trust.contracts import IdentityError, TrustStore
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.join import join_owner
from tunnelminion.trust.keys import DEVICE_KEY_NAME, OWNER_KEY_NAME


@pytest.mark.parametrize(
    ("platform", "store_kind", "existing"),
    [
        ("win32", None, False),
        ("darwin", GatewaySecretStoreKind.KEYRING, True),
        ("linux", GatewaySecretStoreKind.RESTRICTED_FILE, False),
    ],
)
def test_join_owner_saves_only_device_key_after_verified_handshake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    store_kind: GatewaySecretStoreKind | None,
    existing: bool,
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    root = tmp_path / "new"
    secrets = MemorySecrets()

    def secret_backend(_root: Path) -> MemorySecrets:
        return secrets

    monkeypatch.setattr("tunnelminion.trust.join.gateway_secret_store", secret_backend)
    monkeypatch.setattr("tunnelminion.trust.join.gateway_keyring_store", secret_backend)
    monkeypatch.setattr("tunnelminion.trust.join.RestrictedFileSecretStore", secret_backend)
    monkeypatch.setattr("tunnelminion.trust.join.sys", SimpleNamespace(platform=platform))

    def detect(_host: str, _port: int) -> str:
        return "10.20.0.2"

    monkeypatch.setattr("tunnelminion.trust.join.detect_local_host", detect)
    mesh = Mesh("10.20.0.2", apps)

    def transport(*args: object, **kwargs: object) -> Mesh:
        assert kwargs.get("local_address") == "10.20.0.2"
        return mesh

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    if existing:
        root.mkdir()
        (root / "node-id").write_text(str(NodeId.new()), encoding="utf-8")
        FileGatewayConfigurationRepository(root / "gateway.json").save(
            GatewayConfiguration(bind=GatewayBindConfig(host="10.20.0.2"))
        )
    # 加入方用真实时间签应答，邀请方也按真实时间检查应答是否新鲜。
    a.service.clock = lambda: datetime.now(UTC)
    code = a.service.invite()
    if existing:
        # 已有网关配置时，指定不同的端口会被拒绝，什么都不写。
        with pytest.raises(IdentityError, match="已有网关配置"):
            asyncio.run(join_owner(code, root, port_override=8788))
        assert not SQLiteTrustStore.is_initialized(root / "runtime.sqlite3")
    port = 8787 if existing else 8788
    asyncio.run(join_owner(code, root, port_override=port, secret_store_kind=store_kind))
    assert SQLiteTrustStore.is_initialized(root / "runtime.sqlite3")
    assert set(secrets.values) == {DEVICE_KEY_NAME}
    config = FileGatewayConfigurationRepository(root / "gateway.json").load()
    assert config is not None and config.bind.host == "10.20.0.2"
    # 指定了端口就用指定的，同一台电脑上可以再开一个数据目录。
    assert config.bind.port == port
    assert (
        SQLiteStores.open(root / "runtime.sqlite3").trust.load(SignaturePurpose.DEVICE_CERTIFICATE)
        is not None
    )
    with pytest.raises(IdentityError, match="已经初始化"):
        asyncio.run(join_owner(code, root))


@pytest.mark.parametrize(
    "fault",
    [
        "expired",
        "naive",
        "kind",
        "self",
        "route",
        "status",
        "rate",
        "large",
        "malformed",
        "connection",
        "owner",
        "existing_key",
    ],
)
def test_join_owner_rejects_failures_without_saving_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    a = computer(tmp_path / "a", 1, {})
    root = tmp_path / "new"
    secrets = MemorySecrets()

    def secret_backend(_root: Path) -> MemorySecrets:
        return secrets

    monkeypatch.setattr("tunnelminion.trust.join.gateway_secret_store", secret_backend)
    code = a.service.invite().model_copy(
        update={"expires_at": datetime.now(UTC) + timedelta(hours=24)}
    )
    if fault == "expired":
        code = code.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    elif fault == "naive":
        code = code.model_copy(update={"expires_at": datetime.now()})
    elif fault == "kind":
        code = code.model_copy(update={"kind": JoinCodeKind.FRIEND})
    elif fault == "self":
        root.mkdir()
        (root / "node-id").write_text(str(a.service.node_id), encoding="utf-8")
    elif fault == "existing_key":
        secrets.values[DEVICE_KEY_NAME] = a.key.seed_text()
    elif fault == "owner":
        code = code.model_copy(update={"owner_fingerprint": "sha256:" + "f" * 64})

    def detect(_host: str, _port: int) -> str:
        if fault == "route":
            raise OSError
        return "10.20.0.2"

    monkeypatch.setattr("tunnelminion.trust.join.detect_local_host", detect)

    def handler(request: httpx.Request) -> httpx.Response:
        if fault == "connection":
            raise httpx.ConnectError(code.token, request=request)
        if fault in ("status", "rate"):
            return httpx.Response(429 if fault == "rate" else 401)
        if fault in ("large", "malformed"):
            return httpx.Response(200, content="x" * 512_001 if fault == "large" else "invalid")
        from tunnelminion.trust.contracts import OwnerJoinRequest

        accepted = a.service.accept_join(
            code.token, OwnerJoinRequest.model_validate_json(request.content), "10.20.0.2"
        )
        return httpx.Response(200, content=accepted.model_dump_json())

    with pytest.raises(ValueError) as caught:
        asyncio.run(join_owner(code, root, transport=httpx.MockTransport(handler)))
    assert code.token not in str(caught.value)
    assert OWNER_KEY_NAME not in secrets.values
    if fault != "existing_key":
        assert secrets.values == {}
    assert not SQLiteTrustStore.is_initialized(root / "runtime.sqlite3")


def test_owner_commands_invite_restrict_remove_and_show_removed_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)

    def secrets(root: Path) -> MemorySecrets:
        return a.secrets if root == a.root else b.secrets

    def devices(node_id: NodeId, _store: TrustStore, _secrets: SecretStore) -> OwnDevicesService:
        return a.service if node_id == a.service.node_id else b.service

    monkeypatch.setattr("tunnelminion.trust.cli.gateway_secret_store", secrets)
    monkeypatch.setattr("tunnelminion.trust.cli.OwnDevicesService", devices)
    suffix = ["--data-dir", str(a.root)]
    assert owner_command(["owner", "invite", *suffix]) == 0
    code = JoinCode.decode(capsys.readouterr().out.strip(), JoinCodeKind.OWNER)
    assert code.inviter_node_id == a.service.node_id
    assert (
        owner_command(
            [
                "owner",
                "device-permissions",
                str(b.service.node_id),
                "--no-proxy-repair-approval",
                "--no-delegation",
                "--no-model-borrowing",
                "--daily-quota",
                "100",
                *suffix,
            ]
        )
        == 0
    )
    assert owner_command(["owner", "device-permissions", str(b.service.node_id), *suffix]) == 0
    permissions = a.service.store.device_permissions(b.service.node_id)
    assert not permissions.allow_proxy_repair_approval and permissions.daily_quota == 100
    a.mesh.offline.add(b.host)
    assert owner_command(["owner", "remove", str(b.service.node_id), *suffix]) == 0
    assert "这次没推到" in capsys.readouterr().out
    target = a.service.roster().device(a.service.node_id)
    assert target is not None
    asyncio.run(b.service.sync(target))
    assert owner_command(["owner", "status", "--data-dir", str(b.root)]) == 0
    assert "已被移出我的电脑" in capsys.readouterr().out
    assert owner_command(["owner", "invite", "--data-dir", str(b.root)]) == 2
    assert owner_command(["owner", "invite", "--data-dir", str(tmp_path / "empty")]) == 2


def test_owner_join_cli_passes_options_and_hides_bad_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a = computer(tmp_path / "a", 1, {})
    code = a.service.invite()

    async def joined(
        received: JoinCode,
        root: Path,
        *,
        host_override: str | None,
        port_override: int | None,
        secret_store_kind: GatewaySecretStoreKind | None,
        reset: bool,
    ) -> None:
        assert received == code and root == tmp_path and reset is False
        assert host_override == "10.20.0.2" and port_override == 8788
        assert secret_store_kind is GatewaySecretStoreKind.RESTRICTED_FILE

    monkeypatch.setattr("tunnelminion.trust.cli.join_owner", joined)
    assert (
        owner_command(
            [
                "owner",
                "join",
                code.encode(),
                "--data-dir",
                str(tmp_path),
                "--bind-host",
                "10.20.0.2",
                "--bind-port",
                "8788",
                "--secret-store",
                "restricted-file",
            ]
        )
        == 0
    )

    async def default_joined(
        received: JoinCode,
        root: Path,
        *,
        host_override: str | None,
        port_override: int | None,
        secret_store_kind: GatewaySecretStoreKind | None,
        reset: bool,
    ) -> None:
        assert received == code and root == tmp_path and reset is False
        assert host_override is None and port_override is None and secret_store_kind is None

    monkeypatch.setattr("tunnelminion.trust.cli.join_owner", default_joined)
    assert owner_command(["owner", "join", code.encode(), "--data-dir", str(tmp_path)]) == 0
    assert owner_command(["owner", "join", "invalid", "--data-dir", str(tmp_path)]) == 2
    assert code.token not in capsys.readouterr().out
