"""受管网络结构、预算、序列化和秘密边界测试。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError
from tests.network.factories import (
    NETWORK_ID,
    NODE_A,
    NODE_B,
    NOW,
    candidate,
    desired,
    identity,
    lease,
    observation,
    ownership,
    peer,
)

import tunnelminion.network.contracts as contracts
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.network.contracts import (
    AcknowledgementStage,
    AddressLease,
    ApprovedRouteOverlap,
    DesiredNetworkConfig,
    LeaseStatus,
    ManagedResourceOwnership,
    NetworkAcknowledgement,
    NetworkAction,
    NetworkError,
    NetworkErrorCode,
    NetworkPlan,
    NetworkPlanStep,
    OwnershipState,
    PlanStepKind,
    ProviderReceipt,
    ReceiptStatus,
    SignedDesiredConfig,
    StepReceipt,
    VerificationResult,
    canonical_sha256,
    compute_plan_hash,
)


def test_public_network_contracts_round_trip_without_secret_fields() -> None:
    values = (candidate(), lease(), identity(), desired(), observation())

    for value in values:
        assert value.__class__.model_validate_json(value.model_dump_json()) == value

    schemas = " ".join(str(value.__class__.model_json_schema()).lower() for value in values)
    assert "private_key" not in schemas
    assert "preshared" not in schemas
    assert "authorization" not in schemas

    with pytest.raises(ValidationError, match="extra_forbidden"):
        DesiredNetworkConfig.model_validate({**desired().model_dump(), "private_key": "forbidden"})


def test_endpoint_lease_and_identity_validate_scope_and_time() -> None:
    with pytest.raises(ValidationError, match="does not appear"):
        candidate(host="not-an-ip")
    with pytest.raises(ValidationError, match="过期时间"):
        candidate(expires_at=NOW)
    with pytest.raises(ValidationError, match="属于地址池"):
        lease(address="10.204.0.1/32")
    with pytest.raises(ValidationError, match="host 前缀"):
        lease(address="10.203.0.1/24")

    foreign = lease(node_id=NODE_B)
    with pytest.raises(ValidationError, match="相同 network/node"):
        identity(lease=foreign)


def test_desired_config_rejects_routes_revisions_peers_and_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="host route"):
        peer(allowed_host_routes=("0.0.0.0/0",))
    with pytest.raises(ValidationError, match="不得重复"):
        peer(allowed_host_routes=("10.203.0.2/32", "10.203.0.2/32"))
    with pytest.raises(ValidationError, match="host 前缀"):
        desired(address="10.203.0.1/24")
    with pytest.raises(ValidationError):
        desired(listen_port=65536)
    with pytest.raises(ValidationError, match="父 revision"):
        desired(parent_revision=1)
    with pytest.raises(ValidationError, match="主版本不兼容"):
        desired(protocol_version=ProtocolVersion(major=2, minor=0))
    with pytest.raises(ValidationError, match="peer 节点"):
        desired(peers=(peer(node_id=NODE_A),))
    with pytest.raises(ValidationError, match="peer 节点"):
        desired(peers=(peer(), peer()))
    with pytest.raises(ValidationError, match="非默认 IPv4 宽路由"):
        ApprovedRouteOverlap(
            route="0.0.0.0/0",
            observation_fingerprint="sha256:" + "a" * 64,
        )
    with pytest.raises(ValidationError, match="规范形式"):
        ApprovedRouteOverlap(
            route="10.128.0.0/255.128.0.0",
            observation_fingerprint="sha256:" + "a" * 64,
        )
    with pytest.raises(ValidationError, match="直接相关"):
        desired(
            allowed_route_overlaps=(
                ApprovedRouteOverlap(
                    route="192.168.0.0/16",
                    observation_fingerprint="sha256:" + "a" * 64,
                ),
            )
        )
    overlap = ApprovedRouteOverlap(
        route="10.128.0.0/9",
        observation_fingerprint="sha256:" + "a" * 64,
    )
    with pytest.raises(ValidationError, match="不得重复"):
        desired(allowed_route_overlaps=(overlap, overlap))
    assert desired(allowed_route_overlaps=(overlap,)).allowed_route_overlaps == (overlap,)
    assert desired(listen_port=18889).listen_port == 18889

    monkeypatch.setattr(contracts, "MAX_CONFIG_BYTES", 1)
    with pytest.raises(ValidationError, match="字节预算"):
        desired()


def test_observation_and_ownership_require_valid_system_identity() -> None:
    with pytest.raises(ValidationError, match="稳定接口 ID"):
        observation(ownership_state=OwnershipState.MANAGED_OWNED, stable_interface_id=None)
    with pytest.raises(ValidationError, match="IPv4 or IPv6"):
        observation(addresses=("invalid",))
    with pytest.raises(ValidationError, match="does not appear"):
        observation(host_routes=("invalid",))

    managed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    value = ownership(managed)
    assert ManagedResourceOwnership.model_validate_json(value.model_dump_json()) == value


def _plan(action: NetworkAction = NetworkAction.CREATE) -> NetworkPlan:
    observed = observation(
        ownership_state=OwnershipState.MANAGED_OWNED
        if action is not NetworkAction.CREATE
        else OwnershipState.ABSENT
    )
    owned = ownership(observed) if action is not NetworkAction.CREATE else None
    steps = (
        NetworkPlanStep(
            index=0,
            kind=PlanStepKind.WRITE_CONFIG,
            target="tmn-test-a",
            expected_effect="write revision",
            rollback_kind=PlanStepKind.DELETE_CONFIG,
        ),
    )
    plan_hash = compute_plan_hash(
        action=action,
        desired=desired(),
        observed_fingerprint=observed.system_fingerprint,
        ownership=owned,
        steps=steps,
    )
    return NetworkPlan(
        action=action,
        desired=desired(),
        observed_fingerprint=observed.system_fingerprint,
        ownership=owned,
        steps=steps,
        plan_hash=plan_hash,
    )


def test_plan_requires_continuous_steps_ownership_and_valid_hash() -> None:
    valid = _plan()
    assert valid.plan_hash == canonical_sha256(
        {
            "action": valid.action,
            "desired": valid.desired.model_dump(mode="json"),
            "observed_fingerprint": valid.observed_fingerprint,
            "ownership": None,
            "steps": [step.model_dump(mode="json") for step in valid.steps],
        }
    )
    with pytest.raises(ValidationError, match="索引必须连续"):
        NetworkPlan.model_validate(
            {
                **valid.model_dump(),
                "steps": (valid.steps[0].model_copy(update={"index": 1}),),
            }
        )
    with pytest.raises(ValidationError, match="非创建计划"):
        NetworkPlan.model_validate({**valid.model_dump(), "action": NetworkAction.UPDATE})
    with pytest.raises(ValidationError, match="计划哈希"):
        NetworkPlan.model_validate({**valid.model_dump(), "plan_hash": f"sha256:{'0' * 64}"})


def _step(index: int = 0) -> StepReceipt:
    return StepReceipt(
        index=index,
        kind=PlanStepKind.WRITE_CONFIG,
        succeeded=True,
        system_receipt_hash=canonical_sha256({"index": index}),
    )


def test_receipt_verification_signature_and_acknowledgement_contracts() -> None:
    plan = _plan()
    key = f"netop_{'a' * 64}"
    valid = ProviderReceipt(
        idempotency_key=key,
        plan_hash=plan.plan_hash,
        revision=1,
        provider=plan.desired.provider,
        observation_fingerprint=observation().system_fingerprint,
        status=ReceiptStatus.APPLIED,
        steps=(_step(),),
    )
    assert ProviderReceipt.model_validate_json(valid.model_dump_json()) == valid
    with pytest.raises(ValidationError, match="从零连续"):
        ProviderReceipt.model_validate({**valid.model_dump(), "steps": (_step(1),)})
    with pytest.raises(ValidationError, match="失败回执"):
        ProviderReceipt.model_validate({**valid.model_dump(), "status": ReceiptStatus.FAILED})
    error = NetworkError(
        code=NetworkErrorCode.APPLY_FAILED,
        message="failed",
        correlation_id="corr",
    )
    observed = observation()
    with pytest.raises(ValidationError, match="非失败回执"):
        ProviderReceipt.model_validate({**valid.model_dump(), "error": error})
    with pytest.raises(ValidationError, match="观察指纹"):
        ProviderReceipt.model_validate(
            {
                **valid.model_dump(),
                "observation_after": observed,
                "observation_fingerprint": f"sha256:{'f' * 64}",
            }
        )
    failed = VerificationResult(
        idempotency_key=key,
        plan_hash=plan.plan_hash,
        revision=1,
        provider=plan.desired.provider,
        observation_fingerprint=observed.system_fingerprint,
        succeeded=False,
        checked_dimensions=("interface",),
        observation=observed,
        error=error.model_copy(update={"code": NetworkErrorCode.VERIFY_FAILED}),
    )
    assert not failed.succeeded
    with pytest.raises(ValidationError, match="不一致"):
        VerificationResult.model_validate({**failed.model_dump(), "succeeded": True})
    with pytest.raises(ValidationError, match="观察指纹"):
        VerificationResult.model_validate(
            {
                **failed.model_dump(),
                "observation_fingerprint": f"sha256:{'f' * 64}",
            }
        )

    signed = SignedDesiredConfig(
        config=desired(),
        key_id="coordinator-key",
        key_fingerprint=canonical_sha256({"key": "coordinator"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        signature="s" * 80,
    )
    assert signed.config.target_node_id == NODE_A
    with pytest.raises(ValidationError, match="过期时间"):
        SignedDesiredConfig.model_validate({**signed.model_dump(), "expires_at": NOW})

    ack = NetworkAcknowledgement(
        network_id=NETWORK_ID,
        node_id=NODE_A,
        revision=1,
        stage=AcknowledgementStage.PENDING,
        acknowledged_at=NOW,
    )
    assert ack.plan_hash is None


def test_identifier_and_public_key_validation_are_strict() -> None:
    with pytest.raises(ValidationError):
        identity(public_key="short")
    with pytest.raises(ValidationError):
        AddressLease(
            network_id=NETWORK_ID,
            node_id=NodeId.new(),
            address="10.203.0.2/32",
            pool="10.203.0.0/24",
            revision=0,
            status=LeaseStatus.ACTIVE,
        )
