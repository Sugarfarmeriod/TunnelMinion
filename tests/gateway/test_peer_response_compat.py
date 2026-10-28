"""对方电脑升级后在响应里多带字段，旧版本仍能读；认识的字段和权限照常严格校验。"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from tunnelminion.domain.delegation import (
    DelegationEvidence,
    DelegationProposedRepair,
    DelegationRecord,
    DelegationResult,
    DelegationStatus,
)
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import (
    DelegationId,
    NodeId,
    OperationId,
    RunId,
    ThreadId,
    ToolRunId,
)
from tunnelminion.domain.invites import InviteAccepted, InvitePermissions
from tunnelminion.domain.model_borrowing import BorrowedModelResult
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.trust import DeviceCertificate, SignaturePurpose, key_fingerprint
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.contracts import (
    GATEWAY_PROTOCOL,
    GatewayCapabilities,
    GatewayError,
    GatewayErrorCode,
    GatewayErrorResponse,
    GatewayServices,
    PeerRepairView,
    PeerServiceEntry,
    RemoteOperationResult,
    RemoteToolResult,
    RemoteVerificationResult,
    ServicePort,
    parse_peer_response,
)
from tunnelminion.model.contracts import ModelUsage, ToolCall
from tunnelminion.operation.contracts import (
    OperationError,
    OperationErrorCode,
    OperationLevel,
    OperationStatus,
    OperationSummary,
    VerificationRecord,
    VerificationResult,
)
from tunnelminion.tools.audit import InMemoryAuditSink
from tunnelminion.tools.contracts import ToolExecutionStatus
from tunnelminion.trust.contracts import FriendPairing, OwnerJoinResponse, TrustSyncMessage
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.signatures import seal

NOW = datetime(2026, 10, 1, tzinfo=UTC)
LOCAL = NodeId("node_" + "a" * 32)
REMOTE = NodeId("node_" + "b" * 32)
# 这些字段的值本身就是任意 JSON（工具参数、结构化输出等），里面的键属于数据，不是模型字段。
FREE_FORM = {"input_schema", "output_schema", "details", "arguments", "structured_output", "output"}


def tool() -> ToolDefinition:
    return ToolDefinition(
        name="get_node_summary",
        version=ProtocolVersion(major=1, minor=0),
        description="节点摘要",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=next(iter(RiskLevel)),
        platforms=frozenset({Platform.WINDOWS}),
        permissions=("read",),
        timeout_seconds=5,
        max_result_bytes=1000,
        data_sensitivity=next(iter(DataSensitivity)),
    )


def summary() -> OperationSummary:
    return OperationSummary(
        operation_id=OperationId.new(),
        thread_id=ThreadId.new(),
        run_id=RunId.new(),
        tool_run_ids=(ToolRunId.new(),),
        request_node_id=LOCAL,
        target_node_id=REMOTE,
        tool_name="restart_container",
        level=next(iter(OperationLevel)),
        status=next(iter(OperationStatus)),
        authorization_kind=None,
        authorization_basis=None,
        bind_host="127.0.0.1",
        bind_port=8080,
        absolute_expires_at=None,
        resource_ids=(),
        verification_results=(next(iter(VerificationResult)),),
        cleanup_result=None,
        error=OperationError(
            code=next(iter(OperationErrorCode)), message="失败", correlation_id="c-1"
        ),
        updated_at=NOW,
    )


RESPONSES: list[BaseModel] = [
    GatewayErrorResponse(
        error=GatewayError(code=GatewayErrorCode.TRUST_SYNC_REQUIRED, message="先同步名单")
    ),
    GatewayCapabilities(
        protocol=GATEWAY_PROTOCOL,
        node_id=REMOTE,
        platform=Platform.WINDOWS,
        tools=(tool(),),
        operations=("restart_container",),
    ),
    GatewayServices(
        node_id=REMOTE,
        display_name="对方电脑",
        observed_at=NOW,
        services=(
            PeerServiceEntry(
                key="docker:web",
                name="web",
                kind="docker",
                ports=(ServicePort(port=8080, protocol="tcp", has_web_page=True),),
            ),
        ),
        pending_repair_ids=(OperationId.new(),),
    ),
    PeerRepairView(
        repair_id=OperationId.new(),
        node_id=REMOTE,
        service_name="web",
        kind="restart",
        status="pending",
        action_summary="重启",
        reason="挂了",
        impact_summary="短暂中断",
        verification_summary="检查端口",
        failure_summary="无",
        created_at=NOW,
        updated_at=NOW,
    ),
    RemoteToolResult(
        protocol=GATEWAY_PROTOCOL,
        execution_node_id=REMOTE,
        run_id=RunId.new(),
        tool_run_id=ToolRunId.new(),
        status=ToolExecutionStatus.SUCCESS,
        output={"items": [{"name": "web"}]},
        error=ToolError(code=ErrorCode.INTERNAL, message="部分失败", details={"hint": 1}),
    ),
    RemoteOperationResult(protocol=GATEWAY_PROTOCOL, execution_node_id=REMOTE, summary=summary()),
    RemoteVerificationResult(
        verification=VerificationRecord(
            operation_id=OperationId.new(),
            verifier_node_id=LOCAL,
            result=next(iter(VerificationResult)),
            status_code=200,
            evidence_summary="端口可达",
            verified_at=NOW,
        )
    ),
    InviteAccepted(
        inviter_node_id=REMOTE, inviter_display_name="对方", permissions=InvitePermissions()
    ),
    BorrowedModelResult(
        provider_node_id=REMOTE,
        content="结论",
        tool_calls=(ToolCall(call_id="c1", name="get_node_summary", arguments={"a": 1}),),
        structured_output={"k": "v"},
        usage=ModelUsage(input_tokens=1, output_tokens=2, total_tokens=3),
    ),
    DelegationRecord(
        delegation_id=DelegationId.new(),
        caller_node_id=LOCAL,
        executing_node_id=REMOTE,
        question="服务怎么了",
        status=next(iter(DelegationStatus)),
        created_at=NOW,
        result=DelegationResult(
            summary="正常",
            confirmed_facts=("端口在听",),
            evidence=(DelegationEvidence(tool_name="get_node_summary", status="success"),),
            proposed_repairs=(
                DelegationProposedRepair(
                    repair_id=OperationId.new(),
                    service_name="web",
                    action="重启",
                    status="pending",
                    how_to_approve="在设置页批准",
                    expires_at=NOW,
                ),
            ),
            stop_reason="done",
            model_rounds=1,
            tool_calls=1,
            elapsed_ms=10,
        ),
    ),
]


def with_future_fields(value: Any, *, skip: frozenset[str] = frozenset()) -> Any:
    """在每一层对象里都塞一个旧版本不认识的字段。"""
    if isinstance(value, list):
        return [with_future_fields(item, skip=skip) for item in value]  # pyright: ignore[reportUnknownVariableType]
    if isinstance(value, dict):
        return {
            **{
                key: item if key in FREE_FORM | skip else with_future_fields(item, skip=skip)
                for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
            },
            "future_field": {"nested": [1, 2]},
        }
    return value


@pytest.mark.parametrize("response", RESPONSES, ids=lambda item: type(item).__name__)
def test_every_peer_response_ignores_unknown_fields(response: BaseModel) -> None:
    model = type(response)
    skip: frozenset[str] = frozenset({"permissions"} if model is InviteAccepted else ())
    newer = json.dumps(with_future_fields(json.loads(response.model_dump_json()), skip=skip))
    if model is not PeerRepairView:
        # 模型本身仍是严格模式：请求体和本机存储照旧拒收不认识的字段。
        with pytest.raises(ValidationError):
            model.model_validate_json(newer)
    assert parse_peer_response(model, newer) == response
    assert parse_peer_response(model, newer.encode()) == response


def test_known_fields_and_permissions_stay_strict() -> None:
    services = json.loads(RESPONSES[2].model_dump_json())
    services["services"][0]["ports"][0]["port"] = 70000
    with pytest.raises(ValidationError):
        parse_peer_response(GatewayServices, json.dumps(services))
    services = json.loads(RESPONSES[2].model_dump_json())
    services["services"][0]["kind"] = "kubernetes"
    with pytest.raises(ValidationError):
        parse_peer_response(GatewayServices, json.dumps(services))
    # 看不懂的权限宁可整份拒收，也不悄悄丢掉。
    accepted = json.loads(RESPONSES[7].model_dump_json())
    accepted["permissions"]["allow_future_power"] = True
    with pytest.raises(ValidationError):
        parse_peer_response(InviteAccepted, json.dumps(accepted))
    with pytest.raises(ValidationError):
        parse_peer_response(GatewayServices, b"{not json")


def test_unusual_annotations_are_left_to_the_model() -> None:
    class Pair(BaseModel):
        model_config = {"extra": "forbid"}

        name: str

    class Holder(BaseModel):
        model_config = {"extra": "forbid"}

        fixed: tuple[Pair, int]
        either: Pair | ToolCall | None = None

    # 定长元组和多种模型的联合类型不去猜，原样交给模型校验。
    with pytest.raises(ValidationError):
        parse_peer_response(Holder, json.dumps({"fixed": [{"name": "a", "x": 1}, 1]}))
    with pytest.raises(ValidationError):
        parse_peer_response(
            Holder, json.dumps({"fixed": [{"name": "a"}, 1], "either": {"name": "a", "x": 1}})
        )
    assert parse_peer_response(Holder, json.dumps({"fixed": [{"name": "a"}, 1], "y": 2})) == Holder(
        fixed=(Pair(name="a"), 1)
    )


@pytest.mark.parametrize("model", [TrustSyncMessage, FriendPairing, OwnerJoinResponse])
def test_trust_responses_already_ignore_unknown_fields(model: type[BaseModel]) -> None:
    key = PrivateKey.generate()
    certificate = seal(
        SignaturePurpose.DEVICE_CERTIFICATE,
        DeviceCertificate(
            owner_fingerprint=key_fingerprint(key.public_key),
            node_id=REMOTE,
            device_public_key=key.public_key,
            issued_at=NOW,
        ),
        key,
    )
    envelope = {**json.loads(certificate.model_dump_json()), "future_field": 1}
    value = {
        "roster": envelope,
        "trust_list": envelope,
        "certificate": envelope,
        "owner_public_key": key.public_key,
        "recovery_fingerprint": key_fingerprint(key.public_key),
        "display_name": "朋友",
        "rotations": [{"rotation": envelope, "roster": envelope, "future_field": 1}],
        "future_field": {"x": 1},
    }
    parsed = model.model_validate_json(json.dumps(value))
    assert "future_field" not in parsed.model_dump_json()


def test_client_reads_newer_service_list() -> None:
    expected = RESPONSES[2]
    newer = json.dumps(with_future_fields(json.loads(expected.model_dump_json())))

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=newer, headers={"Content-Type": "application/json"})

    client = FixedGatewayClient(
        "http://127.0.0.1:8787",
        "tmn_" + "t" * 40,
        LOCAL,
        REMOTE,
        InMemoryAuditSink(),
        transport=httpx.MockTransport(handler),
    )
    assert asyncio.run(client.get_services()) == expected
