"""邀请码命令与两个平台网关的首次配对。"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from tests.gateway.test_invites import ACCEPTANCE, JOINER, PERMISSIONS, InviteClient
from tests.gateway.test_model_lending import StubProvider, call

from tunnelminion import cli
from tunnelminion.agent.invites import InviteService
from tunnelminion.app import build_windows_gateway_application
from tunnelminion.domain.invites import (
    INVITE_LIFETIME,
    InviteAccepted,
    InviteCode,
    InvitePermissions,
)
from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA, BorrowedModelResult
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
)
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.macos_app import build_macos_gateway_application
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.secrets import KeyringSecretStore, RestrictedFileSecretStore


@pytest.mark.parametrize("platform", ["win32", "darwin"])
@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("borrowing", [False, True])
def test_invite_cli_prints_exact_text_and_registers_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    platform: str,
    configured: bool,
    borrowing: bool,
) -> None:
    monkeypatch.setattr(cli.sys, "platform", platform)
    monkeypatch.setattr("tunnelminion.app.default_data_dir", lambda: tmp_path)
    if configured:
        configuration = GatewayConfigurationService(
            FileGatewayConfigurationRepository(tmp_path / "gateway.json"),
            configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE),
        )
        configuration.configure_local(GatewayBindConfig(host="10.77.0.1", port=9999))
    arguments = ["invite"]
    if configured:
        arguments += ["--data-dir", str(tmp_path)]
    else:
        arguments += ["--bind-host", "10.77.0.1", "--secret-store", "restricted-file"]
        if borrowing:
            arguments += ["--bind-port", "9000"]
    if borrowing:
        arguments += ["--allow-delegation", "--allow-model-borrowing", "--daily-quota", "12345"]
    before = datetime.now(UTC)
    assert cli.main(arguments) == 0
    after = datetime.now(UTC)
    captured = capsys.readouterr()
    text = captured.out.splitlines()[1]
    code = InviteCode.decode(text)
    expected = (
        f"邀请码（24 小时内有效，只能用一次）：\n{text}\n\n"
        f"在要加入的电脑上运行：\ntunnelminion join {text}\n\n"
        "提醒：网关要保持运行，对方才能加入。\n"
    )
    if borrowing:
        expected += "对方借用模型时，他发出的问题会经过本机的模型；每天额度 12345 个 token。\n"
    assert captured.out == expected and not captured.err
    assert code.platform is (Platform.MACOS if platform == "darwin" else Platform.WINDOWS)
    assert code.host == "10.77.0.1"
    assert code.port == (9999 if configured else 9000 if borrowing else 8787)
    assert code.permissions == InvitePermissions(
        allow_delegation=borrowing,
        allow_model_borrowing=borrowing,
        daily_quota=12345 if borrowing else DEFAULT_DAILY_TOKEN_QUOTA,
    )
    assert before + INVITE_LIFETIME <= code.expires_at <= after + INVITE_LIFETIME
    assert (tmp_path / "node-id").read_text(encoding="utf-8") == str(code.node_id)
    assert isinstance(gateway_secret_store(tmp_path), RestrictedFileSecretStore)
    assert (
        SQLiteStores.open(tmp_path / "runtime.sqlite3").invites.accept(
            hashlib.sha256(code.token.encode()).digest(), JOINER, after
        )
        == code.permissions
    )


def test_invite_cli_default_secret_store_is_keyring(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["invite", "--data-dir", str(tmp_path), "--bind-host", "10.77.0.1"]) == 0
    assert (
        InviteCode.decode(capsys.readouterr().out.splitlines()[1]).permissions
        == InvitePermissions()
    )
    assert isinstance(gateway_secret_store(tmp_path), KeyringSecretStore)


@pytest.mark.parametrize("bind_port", [[], ["--bind-port", "9000"]])
def test_invite_cli_requires_bind_host_for_unconfigured_gateway(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bind_port: list[str]
) -> None:
    root = tmp_path / "unconfigured"
    assert cli.main(["invite", "--data-dir", str(root), *bind_port]) == 2
    captured = capsys.readouterr()
    assert captured.out == "本机网关还没有配置，请加上 --bind-host <本机组网地址>\n"
    assert not captured.err and not root.exists()


@pytest.mark.parametrize(
    "options",
    [
        ["--daily-quota", "0"],
        ["--bind-host", "0.0.0.0"],
        ["--bind-host", "10.77.0.1", "--bind-port", "80"],
    ],
)
def test_invite_cli_validates_permissions_and_bind_address(
    tmp_path: Path, options: list[str]
) -> None:
    with pytest.raises(ValidationError):
        cli.main(["invite", "--data-dir", str(tmp_path), *options])
    assert not (tmp_path / "runtime.sqlite3").exists()


@pytest.mark.parametrize("platform", [Platform.WINDOWS, Platform.MACOS])
def test_empty_gateway_accepts_invite_and_serves_new_peer_without_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: Platform
) -> None:
    configuration = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"),
        configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE),
    )
    configuration.configure_local(GatewayBindConfig(host="10.77.0.1"))
    provider = StubProvider()

    def create_provider(_self: ModelConfigurationService) -> StubProvider:
        return provider

    monkeypatch.setattr(ModelConfigurationService, "create_provider", create_provider)
    bundle = (
        build_windows_gateway_application(tmp_path)
        if platform is Platform.WINDOWS
        else build_macos_gateway_application(tmp_path)
    )
    assert bundle.delegation_service is not None and bundle.model_lending_service is not None
    client = cast(InviteClient, TestClient(bundle.app, client=(ACCEPTANCE.host, 1234)))
    issuer = InviteService(
        bundle.node_id,
        platform,
        configuration,
        SQLiteStores.open(tmp_path / "runtime.sqlite3").invites,
    )
    code = issuer.create(PERMISSIONS)
    headers = {"Authorization": f"Bearer {code.token}"}
    assert client.get("/v1/capabilities", headers=headers).status_code == 401
    accepted = client.post(
        "/v1/invites:accept", json=ACCEPTANCE.model_dump(mode="json"), headers=headers
    )
    assert accepted.status_code == 200
    assert InviteAccepted.model_validate(accepted.json()).permissions == PERMISSIONS
    assert client.get("/v1/capabilities", headers=headers).status_code == 200
    borrowed = client.post(
        "/v1/model:complete",
        json=call().model_copy(update={"caller_node_id": JOINER}).model_dump(mode="json"),
        headers=headers,
    )
    assert borrowed.status_code == 200
    assert BorrowedModelResult.model_validate(borrowed.json()).provider_node_id == bundle.node_id
    missing = client.get("/v1/delegations/invalid", headers=headers)
    assert missing.status_code == 404
    assert (
        GatewayErrorResponse.model_validate(missing.json()).error.code
        is GatewayErrorCode.DELEGATION_NOT_FOUND
    )
