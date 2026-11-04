"""我的电脑只靠身份通行证、没有任何旧式配对时也能拿到网关的全部能力。"""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.operation.factories import plan
from tests.operation.test_requester import (
    FakeCallbackRuntime,
    FakeDiagnosticAgent,
    _candidate,  # pyright: ignore[reportPrivateUsage]
)
from tests.operation.test_workflow import MemorySecretStore
from tests.tools.test_registry import definition
from tests.trust.test_own_devices import Computer, computer

from tunnelminion.domain.tools import Platform, RiskLevel
from tunnelminion.domain.trust import PassScope
from tunnelminion.gateway import api as gateway_api
from tunnelminion.gateway.api import create_gateway_router
from tunnelminion.gateway.audit import InMemoryGatewaySecurityAuditSink
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import (
    DEFAULT_GATEWAY_TOOLS,
    DEFAULT_OWNER_OPERATIONS,
    GatewayOperationPeer,
    GatewayPeerView,
)
from tunnelminion.gateway.contracts import RequesterVerificationCallback
from tunnelminion.gateway.operations import CallbackRequesterVerifier, TargetOperationGatewayService
from tunnelminion.gateway.security import (
    GatewayAuthenticationKind,
    GatewayPeerPolicy,
    identity_permissions,
)
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation import definitions
from tunnelminion.operation.contracts import OperationRecord, OperationStatus
from tunnelminion.operation.definitions import SAFE_HTTP_SHARING_OPERATION
from tunnelminion.operation.fakes import (
    FakeRequesterVerifier,
    FakeServiceEvidenceProvider,
    FakeSharingAdapter,
)
from tunnelminion.operation.http_sharing import HTTPSharingConfig, validate_http_sharing_plan
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.operation.requester import RequesterExecutionInput, RequesterOperationInput
from tunnelminion.operation.requester_service import RequesterOperationService
from tunnelminion.operation.workflow import OperationWorkflow, operation_token_name
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.fakes import FakeToolAdapter
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import ToolRuntime
from tunnelminion.trust.passes import issue_pass

# 这些字段描述"是谁、在哪、额度多少"，不是能力开关；其余字段一律视为能力，必须对我的电脑打开。
_POLICY_IDENTITY_FIELDS = frozenset(
    {"node_id", "token_digest", "source_host", "authentication_kind", "daily_quota"}
)
_VIEW_IDENTITY_FIELDS = frozenset(
    {"node_id", "relationship", "platform", "display_name", "host", "port", "daily_quota"}
)


def _registered_operations() -> frozenset[str]:
    """操作定义模块里登记的全部受控操作名。"""
    return frozenset(
        value
        for name, value in vars(definitions).items()
        if name.endswith("_OPERATION") and isinstance(value, str)
    )


def _no_legacy_pairing(*machines: Computer) -> None:
    """每台电脑都把其他电脑认作我的电脑，且彼此之间没有任何旧式配对。"""
    for machine in machines:
        for other in machines:
            if other is not machine:
                assert machine.config.relationship(other.service.node_id) == "mine"
                assert machine.policy.static_source_hosts(other.service.node_id) == ()


@pytest.mark.parametrize("direction", ["master_to_member", "member_to_master"])
def test_own_device_gets_every_gateway_capability_from_pass_alone(
    tmp_path: Path, direction: str
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    _no_legacy_pairing(a, b)
    requester, target = (a, b) if direction == "master_to_member" else (b, a)
    assert set(DEFAULT_OWNER_OPERATIONS) == _registered_operations()

    # 目标端：每种通行证认证出来的我的电脑，所有能力开关都已打开。
    for scope in (PassScope.TOOL_GATEWAY, PassScope.OPERATION_GATEWAY):
        credential = issue_pass(requester.service, target.service.node_id, scope)
        peer = target.policy.authenticate(
            f"Bearer {credential}", audience=scope.value, source_host=requester.host
        )
        assert peer is not None
        assert peer.authentication_kind is GatewayAuthenticationKind.OWNER_DEVICE
        for item in fields(GatewayPeerPolicy):
            if item.name not in _POLICY_IDENTITY_FIELDS:
                assert getattr(peer, item.name), f"我的电脑在目标端拿不到 {item.name}"
        assert peer.allowed_tools == frozenset(DEFAULT_GATEWAY_TOOLS)
        assert peer.allowed_operations == frozenset(DEFAULT_OWNER_OPERATIONS)
        # 同样的权限换成朋友身份，受控操作和只读工具仍被身份上限清空。
        friend = identity_permissions(
            replace(peer, authentication_kind=GatewayAuthenticationKind.FRIEND_DEVICE)
        )
        assert friend.allowed_operations == frozenset()
        assert friend.allowed_tools == frozenset()

    # 请求端：本机配置视图里的我的电脑同样全部打开，且每类调用都能解析出对端。
    view = next(
        peer for peer in requester.config.view().peers if peer.node_id == target.service.node_id
    )
    assert view.relationship == "mine"
    for name in GatewayPeerView.model_fields:
        if name not in _VIEW_IDENTITY_FIELDS:
            assert getattr(view, name), f"我的电脑在请求端拿不到 {name}"
    node_id = target.service.node_id
    requester.config.resolve_tool_peer(node_id, DEFAULT_GATEWAY_TOOLS)
    requester.config.resolve_service_peer(node_id)
    requester.config.resolve_delegation_peer(node_id)
    requester.config.resolve_model_peer(node_id)
    for operation in DEFAULT_OWNER_OPERATIONS:
        requester.config.resolve_operation_peer(node_id, operation)
        assert requester.config.eligible_operation_peers(operation) == (view,)


def _target_app(
    target: Computer, root: Path
) -> tuple[
    FastAPI,
    AuthorizationService[OperationRecord],
    OperationWorkflow,
    FakeSharingAdapter,
    MemorySecretStore,
]:
    stores = SQLiteStores.open(root / "target-operations.sqlite3")
    registry = ToolRegistry()
    registry.register(definition("get_node_summary"), FakeToolAdapter())
    registry.register(
        definition(SAFE_HTTP_SHARING_OPERATION, RiskLevel.REQUIRES_APPROVAL), FakeToolAdapter()
    )
    authorization = AuthorizationService(
        stores.operations,
        stores.preauthorizations,
        OperationPolicy(registry, stores.preauthorizations),
    )
    adapter = FakeSharingAdapter()
    secrets = MemorySecretStore()
    service = plan().service.model_copy(update={"port": 8080})
    workflow = OperationWorkflow(
        stores.operations,
        secrets,
        FakeServiceEvidenceProvider(service),
        adapter,
        FakeRequesterVerifier(target.service.node_id),
    )
    app = FastAPI()
    app.include_router(
        create_gateway_router(
            target.service.node_id,
            Platform.MACOS,
            registry,
            ToolRuntime(registry, Platform.MACOS, InMemoryAuditSink()),
            target.policy,
            InMemoryGatewaySecurityAuditSink(),
            TargetOperationGatewayService(stores.operations, authorization, workflow),
            owner_devices=target.service,
        )
    )
    return app, authorization, workflow, adapter, secrets


@pytest.mark.anyio
async def test_own_devices_share_http_service_end_to_end_with_passes_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: dict[str, FastAPI] = {}
    requester = computer(tmp_path / "requester", 1, apps)
    target = computer(tmp_path / "target", 2, apps, requester)
    _no_legacy_pairing(requester, target)
    app, authorization, workflow, adapter, secrets = _target_app(target, tmp_path)
    apps[target.host] = app
    callback_runtime = FakeCallbackRuntime()

    def callback_verifier(callback: RequesterVerificationCallback) -> CallbackRequesterVerifier:
        # 目标端回调请求端时只能经过内存网格，来源地址就是目标电脑名单上的地址。
        assert callback.endpoint.startswith(f"http://{requester.host}:")
        assert callback_runtime.app is not None
        return CallbackRequesterVerifier(
            callback,
            transport=httpx.ASGITransport(app=callback_runtime.app, client=(target.host, 1234)),
        )

    monkeypatch.setattr(gateway_api, "CallbackRequesterVerifier", callback_verifier)

    def client(peer: GatewayOperationPeer) -> FixedGatewayClient:
        return FixedGatewayClient(
            peer.endpoint,
            peer.token,
            requester.service.node_id,
            peer.node_id,
            InMemoryAuditSink(),
            transport=requester.mesh,
        )

    service = RequesterOperationService(
        node_id=requester.service.node_id,
        store=SQLiteStores.open(tmp_path / "requester-operations.sqlite3").requester_operations,
        configuration=requester.config,
        diagnostic_agent_factory=lambda _peer: FakeDiagnosticAgent(_candidate),
        gateway_client_factory=client,
        callback_runtime=callback_runtime,
        clock=lambda: datetime.now(UTC),
        verification_transport=httpx.MockTransport(lambda _request: httpx.Response(204)),
        access_transport=httpx.MockTransport(lambda _request: httpx.Response(200, text="ok")),
    )
    assert [peer.node_id for peer in service.eligible_peers()] == [target.service.node_id]

    # 申请：目标端只记录为待批准，没有建任何资源。
    created = await service.create_operation(
        RequesterOperationInput(
            target_node_id=target.service.node_id,
            service_port=8080,
            bind_port=18_881,
            duration_seconds=300,
            confirmed=True,
        )
    )
    operation_id = created.plan.operation_id
    assert created.error_code is None
    assert created.remote_summary is not None
    assert created.remote_summary.status is OperationStatus.AWAITING_AUTHORIZATION
    blocked = await service.execute_operation(operation_id, RequesterExecutionInput(confirmed=True))
    assert blocked.error_code == "operation_not_authorized"
    assert adapter.create_calls == 0

    # 目标端本机批准后，请求端确认执行，目标端回调请求端独立验证。
    now = datetime.now(UTC)
    authorization.approve_once(
        operation_id,
        operator="target-local-user",
        decided_at=now,
        expires_at=now + timedelta(minutes=1),
        local_control=True,
    )
    executed = await service.execute_operation(
        operation_id, RequesterExecutionInput(confirmed=True)
    )
    assert executed.error_code is None
    assert executed.remote_summary is not None
    assert executed.remote_summary.status is OperationStatus.SUCCEEDED
    assert executed.remote_summary.verification_results == ("passed",)
    assert adapter.create_calls == 1
    assert service.access_expires_at(operation_id) is not None

    # 访问：经请求端转发到目标端临时入口。
    accessed = await service.access_operation(operation_id, method="GET", path="/")
    assert (accessed.status_code, accessed.content) == (200, b"ok")

    # 目标端苹果网关按配置视图生成的来源地址白名单，认得出这台我的电脑。
    sharing_peers = {
        str(peer.node_id): frozenset({peer.host})
        for peer in target.config.view().peers
        if SAFE_HTTP_SHARING_OPERATION in peer.allowed_operations
    }
    assert sharing_peers == {str(requester.service.node_id): frozenset({requester.host})}
    validate_http_sharing_plan(
        executed.plan,
        HTTPSharingConfig(
            wireguard_addresses=frozenset({target.host}),
            allowed_peer_addresses=sharing_peers,
        ),
    )

    # 到期回收：资源和临时凭据都清掉，请求端看到同一个操作已过期且不能再访问。
    lease = executed.remote_summary.absolute_expires_at
    assert lease is not None
    expired = await workflow.expire_due(at=lease)
    assert [item.plan.operation_id for item in expired] == [operation_id]
    assert adapter.active_resources == {}
    assert operation_token_name(operation_id) not in secrets.values
    refreshed = await service.refresh_operation(operation_id)
    assert refreshed.remote_summary is not None
    assert refreshed.remote_summary.status is OperationStatus.EXPIRED
    assert service.access_expires_at(operation_id) is None
