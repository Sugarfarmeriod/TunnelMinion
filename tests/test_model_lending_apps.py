"""模型提供方的应用组装与只读用量命令。"""

from __future__ import annotations

import asyncio
import io
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from tests.gateway.test_model_lending import AUTH, PEER, TOKEN, StubProvider, call

from tunnelminion import cli
from tunnelminion.app import build_windows_gateway_application
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.model_borrowing import DEFAULT_DAILY_TOKEN_QUOTA, ModelUsageRecord
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.macos_app import build_macos_gateway_application
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.configuration import ModelConfigurationService


@pytest.mark.parametrize("platform", [Platform.WINDOWS, Platform.MACOS])
@pytest.mark.parametrize("allow", [False, True])
def test_gateways_build_model_lending_only_for_allowed_peers_and_use_the_node_provider_and_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: Platform,
    allow: bool,
) -> None:
    configuration = GatewayConfigurationService(
        FileGatewayConfigurationRepository(tmp_path / "gateway.json"),
        configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE),
    )
    configuration.configure_local(GatewayBindConfig(host="10.77.0.5"))
    configuration.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=PEER,
                platform=Platform.MACOS,
                host="10.77.0.1",
                allowed_tools=frozenset({"get_node_summary"}),
                allow_model_borrowing=allow,
            ),
            token=TOKEN,
        )
    )
    provider = StubProvider()
    factory_calls: list[ModelConfigurationService] = []

    def create_provider(self: ModelConfigurationService) -> StubProvider:
        factory_calls.append(self)
        return provider

    monkeypatch.setattr(ModelConfigurationService, "create_provider", create_provider)
    bundle = (
        build_windows_gateway_application(tmp_path)
        if platform is Platform.WINDOWS
        else build_macos_gateway_application(tmp_path)
    )
    assert (bundle.model_lending_service is not None) is allow
    assert bundle.delegation_service is None and not factory_calls

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bundle.app), base_url="http://gateway"
        ) as client:
            response = await client.post(
                "/v1/model:complete", json=call().model_dump(mode="json"), headers=AUTH
            )
        assert response.status_code == (200 if allow else 503)
        if allow:
            assert str(bundle.node_id) in response.text

    asyncio.run(scenario())
    records = SQLiteStores.open(tmp_path / "runtime.sqlite3").model_usage.list(date.today())
    assert len(factory_calls) == (1 if allow else 0)
    assert records == (
        (ModelUsageRecord(peer_node_id=PEER, day=date.today(), calls=1, tokens=17),)
        if allow
        else ()
    )


@pytest.mark.parametrize("custom", [False, True])
def test_gateway_configure_cli_persists_borrowing_permission_and_token_quota(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    custom: bool,
) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(TOKEN))
    arguments = [
        "gateway-configure",
        "--data-dir",
        str(tmp_path),
        "--bind-host",
        "10.77.0.5",
        "--peer-node-id",
        str(PEER),
        "--peer-platform",
        "macos",
        "--peer-host",
        "10.77.0.1",
        "--secret-store",
        "restricted-file",
    ]
    if custom:
        arguments += ["--allow-model-borrowing", "--daily-quota", "12345"]
    assert cli.main(arguments) == 0
    configuration = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
    assert configuration is not None
    peer = configuration.peers[0]
    assert peer.allow_model_borrowing is custom
    assert peer.daily_quota == (12345 if custom else DEFAULT_DAILY_TOKEN_QUOTA)
    output = capsys.readouterr().out
    assert TOKEN not in output


@pytest.mark.parametrize("explicit", [False, True])
def test_model_usage_cli_reads_only_today_as_json_lines_without_modifying_the_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    explicit: bool,
) -> None:
    monkeypatch.setattr("tunnelminion.app.default_data_dir", lambda: tmp_path)
    path = tmp_path / "runtime.sqlite3"
    store = SQLiteStores.open(path).model_usage
    today = date.today()
    other = NodeId("node_" + "f" * 32)
    store.add(PEER, today - timedelta(days=1), 99, 999)
    store.add(other, today, 2, 200)
    store.add(PEER, today, 1, 100)
    before = path.read_bytes(), path.stat().st_mtime_ns
    arguments = ["model-usage", "--data-dir", str(tmp_path)] if explicit else ["model-usage"]
    assert cli.main(arguments) == 0
    assert tuple(
        ModelUsageRecord.model_validate_json(line) for line in capsys.readouterr().out.splitlines()
    ) == (
        ModelUsageRecord(peer_node_id=PEER, day=today, calls=1, tokens=100),
        ModelUsageRecord(peer_node_id=other, day=today, calls=2, tokens=200),
    )
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_model_usage_cli_does_not_create_a_data_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "missing"
    assert cli.main(["model-usage", "--data-dir", str(root)]) == 0
    assert not root.exists() and not capsys.readouterr().out


def test_model_usage_cli_accepts_a_database_without_a_model_usage_table(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "runtime.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE service_marks (mark_key TEXT PRIMARY KEY)")
    connection.close()
    before = path.read_bytes(), path.stat().st_mtime_ns
    assert cli.main(["model-usage", "--data-dir", str(tmp_path)]) == 0
    assert not capsys.readouterr().out
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize("state", ["missing", "platform", "credential", "ready"])
def test_existing_model_peer_contract_requires_an_explicit_peer_platform_and_credential(
    tmp_path: Path,
    state: str,
) -> None:
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    secrets = configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE)
    service = GatewayConfigurationService(repository, secrets)
    configured_peer = GatewayPeerConfig(
        node_id=PEER,
        platform=None if state == "platform" else Platform.MACOS,
        host="10.77.0.1",
        allowed_tools=frozenset({"get_node_summary"}),
    )
    repository.save(
        GatewayConfiguration(
            bind=GatewayBindConfig(host="10.77.0.5"),
            peers=() if state == "missing" else (configured_peer,),
        )
    )
    if state in {"missing", "platform"}:
        with pytest.raises(KeyError, match="gateway_model_peer_not_found"):
            service.resolve_model_peer(PEER)
    elif state == "credential":
        with pytest.raises(RuntimeError, match="缺少网关凭据"):
            service.resolve_model_peer(PEER)
    else:
        service.provision_peer(GatewayPeerInput(peer=configured_peer, token=TOKEN))
        resolved = service.resolve_model_peer(PEER)
        assert resolved.node_id == PEER and resolved.platform is Platform.MACOS
        assert resolved.endpoint == "http://10.77.0.1:8787"
        assert resolved.token == TOKEN and resolved.allowed_tools == ()
