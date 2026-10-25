"""加入方的本地配置顺序、模型选择和命令输出。"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

import httpx
import pytest
from tests.model.test_configuration import MemorySecrets

from tunnelminion import cli
from tunnelminion.agent import join as joining
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.invites import (
    InviteAcceptance,
    InviteAccepted,
    InviteCode,
    InvitePermissions,
)
from tunnelminion.domain.model_borrowing import BorrowedModelCall, BorrowedModelResult
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.client import FixedGatewayClient, InviteHandshakeError
from tunnelminion.gateway.configuration import (
    DEFAULT_GATEWAY_TOOLS,
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
    gateway_token_name,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.model.contracts import ProviderError, ProviderErrorCode, ToolCall
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.tools.audit import AuditSink

NOW = datetime(2026, 10, 25, tzinfo=UTC)
LOCAL = NodeId("node_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
CODE = InviteCode(
    node_id=NodeId("node_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    platform=Platform.MACOS,
    host="10.77.0.1",
    port=8787,
    token="tmn_" + "a" * 40,
    permissions=InvitePermissions(),
    expires_at=datetime(2100, 1, 1, tzinfo=UTC),
)
ACCEPTED = InviteAccepted(
    inviter_node_id=CODE.node_id,
    permissions=InvitePermissions(
        allow_delegation=True, allow_model_borrowing=True, daily_quota=1234
    ),
)
CONTACT = "正在联系 node_bbbbbbb（10.77.0.1:8787）……\n"
PAIRED = "已加入。对方：node_bbbbbbb，平台：macOS\n"
PERMISSIONS = "- 可以把问题交给对方的 Agent 处理\n- 可以借用对方的模型，每天 1234 个 token\n"
BORROWING = "正在切换到对方的模型并做一次自检，可能要几十秒……\n"
BORROWED = "已改用对方的模型。你在这台电脑上提的问题会发给对方的模型处理。\n"


@pytest.fixture
def handshakes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[InviteAcceptance]:
    seen: list[InviteAcceptance] = []
    secrets = MemorySecrets()
    monkeypatch.setattr(joining, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(joining.sys, "platform", "win32")
    monkeypatch.setattr(joining, "KeyringSecretStore", lambda: secrets)
    monkeypatch.setattr("tunnelminion.gateway.configuration.KeyringSecretStore", lambda: secrets)

    def detect(host: str, port: int) -> str:
        assert (host, port) == (CODE.host, CODE.port)
        return "10.77.0.2"

    async def accept(code: InviteCode, acceptance: InviteAcceptance) -> InviteAccepted:
        assert code.node_id == CODE.node_id
        config = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
        assert config is not None and all(peer.node_id != code.node_id for peer in config.peers)
        seen.append(acceptance)
        return ACCEPTED

    monkeypatch.setattr(joining, "detect_local_host", detect)
    monkeypatch.setattr(joining, "accept_invite", accept)
    return seen


@pytest.fixture
def model_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[BorrowedModelCall]:
    seen: list[BorrowedModelCall] = []

    def client(
        endpoint: str,
        token: str,
        local_node_id: NodeId,
        remote_node_id: NodeId,
        audit_sink: AuditSink,
    ) -> FixedGatewayClient:
        assert endpoint == "http://10.77.0.1:8787" and token == CODE.token
        assert remote_node_id == CODE.node_id
        assert local_node_id == NodeId((tmp_path / "node-id").read_text(encoding="utf-8"))

        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == "http://10.77.0.1:8787/v1/model:complete"
            call = BorrowedModelCall.model_validate_json(request.content)
            assert call.caller_node_id == local_node_id
            seen.append(call)
            result = BorrowedModelResult(
                provider_node_id=remote_node_id,
                tool_calls=(
                    ToolCall(
                        call_id="self-check", name=call.tools[0].name, arguments={"status": "ok"}
                    ),
                )
                if call.tools
                else (),
                structured_output={"status": "ok"} if call.response_schema else None,
            )
            return httpx.Response(200, content=result.model_dump_json())

        return FixedGatewayClient(
            endpoint,
            token,
            local_node_id,
            remote_node_id,
            audit_sink,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(joining, "FixedGatewayClient", client)
    return seen


def configure_bind(root: Path) -> GatewayConfiguration:
    (root / "node-id").write_text(str(LOCAL), encoding="utf-8")
    config = GatewayConfiguration(bind=GatewayBindConfig(host="10.77.0.8", port=9001))
    FileGatewayConfigurationRepository(root / "gateway.json").save(config)
    return config


@pytest.mark.parametrize(
    ("host", "family"), [("10.77.0.1", socket.AF_INET), ("fd00::1", socket.AF_INET6)]
)
def test_detect_local_host_uses_udp_route_and_closes_socket(
    monkeypatch: pytest.MonkeyPatch, host: str, family: socket.AddressFamily
) -> None:
    actions: list[object] = []

    class RouteSocket:
        def __enter__(self) -> RouteSocket:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            actions.append("closed")

        def connect(self, address: tuple[str, int]) -> None:
            actions.append(address)

        def getsockname(self) -> tuple[str, int]:
            return "10.77.0.2", 54321

    def create(selected_family: socket.AddressFamily, kind: socket.SocketKind) -> RouteSocket:
        assert selected_family == family and kind == socket.SOCK_DGRAM
        return RouteSocket()

    monkeypatch.setattr(joining.socket, "socket", create)
    assert joining.detect_local_host(host, 8787) == "10.77.0.2"
    assert actions == [(host, 8787), "closed"]


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_fresh_join_saves_bind_peer_token_and_validated_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    model_calls: list[BorrowedModelCall],
    platform: str,
) -> None:
    monkeypatch.setattr(joining.sys, "platform", platform)
    assert (
        asyncio.run(
            joining.join(
                CODE,
                data_dir=tmp_path,
                bind_port=8999,
                secret_store_kind=GatewaySecretStoreKind.RESTRICTED_FILE,
                now=NOW,
            )
        )
        == ACCEPTED
    )
    config = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
    assert config is not None and config.bind == GatewayBindConfig(host="10.77.0.2", port=8999)
    peer = config.peers[0]
    assert (peer.node_id, peer.platform, peer.host, peer.port) == (
        CODE.node_id,
        CODE.platform,
        CODE.host,
        CODE.port,
    )
    assert peer.allowed_tools == frozenset(DEFAULT_GATEWAY_TOOLS)
    assert (
        not peer.allowed_operations and not peer.allow_delegation and not peer.allow_model_borrowing
    )
    assert gateway_secret_store(tmp_path).get(gateway_token_name(CODE.node_id)) == CODE.token
    assert CODE.token not in (tmp_path / "gateway.json").read_text(encoding="utf-8")
    assert handshakes == [
        InviteAcceptance(
            node_id=NodeId((tmp_path / "node-id").read_text(encoding="utf-8")),
            platform=Platform.MACOS if platform == "darwin" else Platform.WINDOWS,
            host="10.77.0.2",
            port=8999,
        )
    ]
    borrowed = FileModelConfigurationRepository(tmp_path / "model.json").load_borrowed()
    assert borrowed is not None and borrowed.peer_node_id == CODE.node_id
    assert len(model_calls) == 2
    output = capsys.readouterr()
    assert output.out == CONTACT + PAIRED + PERMISSIONS + BORROWING + BORROWED
    assert output.err == ""


@pytest.mark.parametrize("host_override", [None, "10.77.0.9"])
def test_configured_join_keeps_bind_and_can_override_reported_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handshakes: list[InviteAcceptance],
    host_override: str | None,
) -> None:
    original = configure_bind(tmp_path)

    def no_detection(_host: str, _port: int) -> str:
        raise AssertionError("已有监听配置时不自动探测")

    monkeypatch.setattr(joining, "detect_local_host", no_detection)
    asyncio.run(
        joining.join(CODE, host_override=host_override, bind_port=9999, use_borrowed_model=False)
    )
    config = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
    assert config is not None and config.bind == original.bind
    assert handshakes[0].host == (host_override or original.bind.host)
    assert handshakes[0].port == original.bind.port and handshakes[0].node_id == LOCAL
    assert not (tmp_path / "model.json").exists()


def test_join_keeps_other_peers_and_saved_secret_backend(
    tmp_path: Path, handshakes: list[InviteAcceptance]
) -> None:
    original = configure_bind(tmp_path)
    repository = FileGatewayConfigurationRepository(tmp_path / "gateway.json")
    service = GatewayConfigurationService(
        repository, configure_gateway_secret_store(tmp_path, GatewaySecretStoreKind.RESTRICTED_FILE)
    )
    other = GatewayPeerConfig(
        node_id=NodeId("node_cccccccccccccccccccccccccccccccc"),
        platform=Platform.WINDOWS,
        host="10.77.0.3",
        allowed_tools=frozenset({"get_node_summary"}),
    )
    other_token = "tmn_" + "c" * 40
    service.provision_peer(GatewayPeerInput(peer=other, token=other_token))
    assert cli.main(["join", CODE.encode(), "--keep-model"]) == 0
    config = repository.load()
    assert config is not None and config.bind == original.bind
    assert config.peers[0] == other and config.peers[1].node_id == CODE.node_id
    assert gateway_secret_store(tmp_path).get(gateway_token_name(other.node_id)) == other_token
    assert gateway_secret_store(tmp_path).get(gateway_token_name(CODE.node_id)) == CODE.token
    assert (tmp_path / "gateway-secret-store").read_text(encoding="utf-8") == "restricted-file"
    assert len(handshakes) == 1


@pytest.mark.parametrize("use_borrowed_model", [None, False, True])
def test_join_preserves_existing_model_unless_explicitly_replaced(
    tmp_path: Path,
    handshakes: list[InviteAcceptance],
    model_calls: list[BorrowedModelCall],
    use_borrowed_model: bool | None,
) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    original = OpenAICompatibleConfig(endpoint="http://127.0.0.1:11434/v1", model="existing")
    repository.save(original)
    asyncio.run(joining.join(CODE, use_borrowed_model=use_borrowed_model))
    assert len(handshakes) == 1
    if use_borrowed_model is True:
        assert repository.load() is None and repository.load_borrowed() is not None
        assert len(model_calls) == 2
    else:
        assert repository.load() == original and repository.load_borrowed() is None
        assert model_calls == []


@pytest.mark.parametrize(
    "error", [ProviderError(ProviderErrorCode.TIMEOUT, "自检超时"), RuntimeError("private")]
)
def test_borrow_failure_keeps_pairing_and_reports_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    error: Exception,
) -> None:
    async def fail(_self: object, _peer: NodeId) -> None:
        raise error

    monkeypatch.setattr(joining.ModelConfigurationService, "borrow", fail)
    assert cli.main(["join", CODE.encode()]) == 0
    config = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
    assert config is not None and config.peers[0].node_id == CODE.node_id
    assert gateway_secret_store(tmp_path).get(gateway_token_name(CODE.node_id)) == CODE.token
    assert not (tmp_path / "model.json").exists() and len(handshakes) == 1
    reason = "自检超时" if isinstance(error, ProviderError) else "模型自检失败"
    output = capsys.readouterr()
    assert output.out == (
        CONTACT
        + PAIRED
        + PERMISSIONS
        + BORROWING
        + f"没能改用对方的模型：{reason}。配对已经完成，可以稍后运行 "
        + f"tunnelminion model-borrow --from {CODE.node_id}。\n"
    )
    assert output.err == ""


@pytest.mark.parametrize("configured", [False, True])
def test_failed_handshake_writes_no_identity_peer_model_or_store_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handshakes: list[InviteAcceptance],
    configured: bool,
) -> None:
    if configured:
        configure_bind(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    async def fail(_code: InviteCode, _acceptance: InviteAcceptance) -> InviteAccepted:
        raise InviteHandshakeError("invalid")

    monkeypatch.setattr(joining, "accept_invite", fail)
    with pytest.raises(InviteHandshakeError):
        asyncio.run(joining.join(CODE, secret_store_kind=GatewaySecretStoreKind.RESTRICTED_FILE))
    after = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    if configured:
        assert after == before
    else:
        assert set(after) == {"gateway.json"}
        config = FileGatewayConfigurationRepository(tmp_path / "gateway.json").load()
        assert config is not None and config.peers == ()
    assert handshakes == []


@pytest.mark.parametrize("offset", [timedelta(), timedelta(seconds=-1)])
def test_expired_code_does_not_write_or_contact_inviter(
    tmp_path: Path, handshakes: list[InviteAcceptance], offset: timedelta
) -> None:
    with pytest.raises(joining.JoinError, match="邀请码已过期，请让对方重新生成"):
        asyncio.run(joining.join(CODE.model_copy(update={"expires_at": NOW + offset}), now=NOW))
    assert handshakes == [] and list(tmp_path.iterdir()) == []


def test_own_code_does_not_contact_inviter(
    tmp_path: Path, handshakes: list[InviteAcceptance]
) -> None:
    (tmp_path / "node-id").write_text(str(CODE.node_id), encoding="utf-8")
    with pytest.raises(joining.JoinError, match="不能加入自己生成的邀请码"):
        asyncio.run(joining.join(CODE, now=NOW))
    assert handshakes == [] and not (tmp_path / "gateway.json").exists()


@pytest.mark.parametrize("kind", ["invalid", "expired", "own"])
def test_cli_rejects_local_errors_with_exact_text(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    kind: str,
) -> None:
    code = CODE.encode()
    expected = "这不是有效的邀请码"
    if kind == "invalid":
        code = "not-an-invite"
    elif kind == "expired":
        code = CODE.model_copy(update={"expires_at": datetime(2000, 1, 1, tzinfo=UTC)}).encode()
        expected = "邀请码已过期，请让对方重新生成"
    else:
        (tmp_path / "node-id").write_text(str(CODE.node_id), encoding="utf-8")
        expected = "不能加入自己生成的邀请码"
    assert cli.main(["join", code]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == expected + "\n"
    assert handshakes == []


@pytest.mark.parametrize(
    "error",
    [
        InviteHandshakeError("invalid"),
        InviteHandshakeError("unreachable"),
        InviteHandshakeError("rate_limited"),
        InviteHandshakeError("bad_response"),
        OSError("no-route"),
    ],
)
def test_cli_maps_handshake_and_route_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    error: InviteHandshakeError | OSError,
) -> None:
    async def fail(_code: InviteCode, _acceptance: InviteAcceptance) -> InviteAccepted:
        raise error

    def no_route(_host: str, _port: int) -> str:
        raise error

    if isinstance(error, OSError):
        monkeypatch.setattr(joining, "detect_local_host", no_route)
    else:
        monkeypatch.setattr(joining, "accept_invite", fail)
    assert cli.main(["join", CODE.encode()]) == 1
    expected = {
        "invalid": "邀请码无效、已过期或已被使用",
        "unreachable": "连不上对方电脑（10.77.0.1:8787）。请确认组网已连通、对方的网关正在运行",
        "rate_limited": "对方电脑暂时拒绝了请求，请稍后再试",
        "bad_response": "这不是有效的邀请码",
    }[error.reason if isinstance(error, InviteHandshakeError) else "unreachable"]
    output = capsys.readouterr()
    assert output.out == ("" if isinstance(error, OSError) else CONTACT)
    assert output.err == expected + "\n" and handshakes == []


@pytest.mark.parametrize("platform", [Platform.MACOS, Platform.WINDOWS])
@pytest.mark.parametrize("borrow", [False, True])
def test_cli_flags_and_success_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    model_calls: list[BorrowedModelCall],
    platform: Platform,
    borrow: bool,
) -> None:
    code = CODE.model_copy(update={"platform": platform})
    FileModelConfigurationRepository(tmp_path / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://127.0.0.1:11434/v1", model="existing")
    )
    assert (
        cli.main(
            [
                "join",
                code.encode(),
                "--data-dir",
                str(tmp_path),
                "--host",
                "10.77.0.9",
                "--bind-port",
                "9999",
                "--secret-store",
                "restricted-file",
                "--use-borrowed-model" if borrow else "--keep-model",
            ]
        )
        == 0
    )
    label = "macOS" if platform is Platform.MACOS else "Windows"
    output = capsys.readouterr()
    assert output.out == (
        CONTACT
        + f"已加入。对方：node_bbbbbbb，平台：{label}\n"
        + PERMISSIONS
        + (BORROWING + BORROWED if borrow else "")
    )
    assert output.err == ""
    assert handshakes[0].host == "10.77.0.9" and handshakes[0].port == 9999
    assert len(model_calls) == (2 if borrow else 0)


@pytest.mark.parametrize("delegation", [False, True])
def test_no_model_permission_prevents_even_explicit_borrow(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    model_calls: list[BorrowedModelCall],
    delegation: bool,
) -> None:
    async def accept(_code: InviteCode, acceptance: InviteAcceptance) -> InviteAccepted:
        handshakes.append(acceptance)
        return InviteAccepted(
            inviter_node_id=CODE.node_id,
            permissions=InvitePermissions(allow_delegation=delegation),
        )

    monkeypatch.setattr(joining, "accept_invite", accept)
    assert cli.main(["join", CODE.encode(), "--use-borrowed-model"]) == 0
    assert model_calls == [] and len(handshakes) == 1
    assert capsys.readouterr().out == (
        CONTACT + PAIRED + ("- 可以把问题交给对方的 Agent 处理\n" if delegation else "")
    )


@pytest.mark.parametrize(
    "code",
    [
        CODE.model_copy(update={"expires_at": datetime(2100, 1, 1)}),
        CODE.model_copy(update={"token": "x" * 40}),
        CODE.model_copy(update={"host": "8.8.8.8"}),
    ],
)
def test_cli_rejects_unusable_code_fields_before_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    handshakes: list[InviteAcceptance],
    code: InviteCode,
) -> None:
    assert cli.main(["join", code.encode()]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == "这不是有效的邀请码\n"
    assert handshakes == [] and list(tmp_path.iterdir()) == []


def test_cli_model_flags_are_mutually_exclusive(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["join", CODE.encode(), "--keep-model", "--use-borrowed-model"])
    assert caught.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["join", "gateway-configure"])
def test_cli_entry_points_load_without_circular_imports(command: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from tunnelminion.cli import main\nraise SystemExit(main())",
            command,
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--secret-store" in result.stdout
