"""直连联合验证、防抖切换和 endpoint 选择测试。"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest
from tests.network.factories import NOW, candidate

from tunnelminion.network.contracts import CandidateSource, EndpointCandidate, ProviderKind
from tunnelminion.network.path_controller import (
    CandidateProbePolicy,
    DirectPathController,
    DirectPathErrorCode,
    DirectPathEvidence,
    DirectPathVerifier,
    GatewayPathEndpoint,
    NetworkPathType,
    PathControllerPolicy,
    PathSelection,
    select_gateway_endpoint,
)


class FakeProbe:
    def __init__(
        self,
        *,
        endpoint_results: list[bool] | None = None,
        target_result: bool = True,
    ) -> None:
        self.endpoint_results = endpoint_results or []
        self.target_result = target_result
        self.endpoints: list[EndpointCandidate] = []
        self.targets: list[tuple[str, int]] = []

    async def endpoint(
        self,
        candidate: EndpointCandidate,
        timeout_seconds: float,
    ) -> bool:
        assert 0 < timeout_seconds <= 5
        self.endpoints.append(candidate)
        return self.endpoint_results.pop(0) if self.endpoint_results else False

    async def target(self, host: str, port: int, timeout_seconds: float) -> bool:
        assert 0 < timeout_seconds <= 10
        self.targets.append((host, port))
        return self.target_result


def policy(**updates: object) -> CandidateProbePolicy:
    values: dict[str, object] = {"approved_networks": ("203.0.113.0/24",)}
    values.update(updates)
    return CandidateProbePolicy.model_validate(values)


async def verify(
    probe: FakeProbe,
    *,
    candidates: tuple[EndpointCandidate, ...] | None = None,
    handshake: datetime | None = NOW,
    routes: tuple[str, ...] = ("10.203.0.2/32",),
    now: datetime = NOW,
    candidate_policy: CandidateProbePolicy | None = None,
) -> DirectPathEvidence:
    return await DirectPathVerifier(candidate_policy or policy(), probe).verify(
        provider=ProviderKind.WINDOWS,
        revision=2,
        candidates=(candidate(),) if candidates is None else candidates,
        last_handshake_at=handshake,
        observed_host_routes=routes,
        expected_host_route="10.203.0.2/32",
        target_host="10.203.0.2",
        target_port=8787,
        now=now,
    )


def evidence(
    *,
    revision: int = 1,
    verified: bool,
    at: datetime = NOW,
    error: DirectPathErrorCode | None = None,
) -> DirectPathEvidence:
    return DirectPathEvidence(
        provider=ProviderKind.WINDOWS,
        revision=revision,
        candidate_count=1,
        selected_candidate_hash=f"sha256:{'a' * 64}",
        endpoint_probe_at=at,
        endpoint_probe_succeeded=True,
        last_handshake_at=at,
        handshake_fresh=verified,
        host_route_present=verified,
        target_probe_at=at,
        target_probe_succeeded=verified,
        verified=verified,
        stable_error_code=error,
        observed_at=at,
    )


def initial(path_type: NetworkPathType = NetworkPathType.STATIC) -> PathSelection:
    return PathSelection(
        path_type=path_type,
        provider=ProviderKind.WINDOWS,
        revision=1,
        last_known_good_revision=(1 if path_type is NetworkPathType.DIRECT else None),
        candidate_count=0,
        consecutive_failures=0,
        consecutive_successes=0,
        selected_at=NOW,
        last_evidence_at=NOW,
    )


def test_candidate_policy_and_evidence_reject_invalid_states() -> None:
    with pytest.raises(ValueError, match="默认路由"):
        policy(approved_networks=("0.0.0.0/0",))
    with pytest.raises(ValueError, match="四项证据"):
        DirectPathEvidence(
            provider=ProviderKind.WINDOWS,
            revision=1,
            candidate_count=0,
            endpoint_probe_succeeded=False,
            handshake_fresh=False,
            host_route_present=False,
            target_probe_succeeded=False,
            verified=True,
            observed_at=NOW,
        )
    with pytest.raises(ValueError, match="错误码"):
        evidence(verified=False)


def test_verifier_ranks_filters_bounds_and_verifies_joint_evidence() -> None:
    explicit = candidate(host="203.0.113.11", source=CandidateSource.ADMIN_EXPLICIT)
    stun = candidate(host="203.0.113.12", source=CandidateSource.STUN_SAME_SOCKET)
    observed = candidate(host="203.0.113.13", source=CandidateSource.NODE_OBSERVED)
    expired = candidate(
        host="203.0.113.14",
        observed_at=NOW - timedelta(minutes=2),
        expires_at=NOW - timedelta(minutes=1),
    )
    outside = candidate(host="198.51.100.2")
    probe = FakeProbe(endpoint_results=[False, True])
    result = asyncio.run(
        verify(
            probe,
            candidates=(observed, outside, expired, stun, explicit),
            candidate_policy=policy(max_candidates=2),
        )
    )
    assert result.verified
    assert result.candidate_count == 2
    assert [item.source for item in probe.endpoints] == [
        CandidateSource.ADMIN_EXPLICIT,
        CandidateSource.STUN_SAME_SOCKET,
    ]
    assert probe.targets == [("10.203.0.2", 8787)]
    assert result.selected_candidate_hash is not None


@pytest.mark.parametrize(
    ("candidates", "endpoint_results", "handshake", "routes", "target", "expected"),
    [
        ((), [], NOW, ("10.203.0.2/32",), True, DirectPathErrorCode.NO_APPROVED_CANDIDATE),
        (
            (candidate(),),
            [False],
            NOW,
            ("10.203.0.2/32",),
            True,
            DirectPathErrorCode.ENDPOINT_UNREACHABLE,
        ),
        (
            (candidate(),),
            [True],
            NOW - timedelta(minutes=10),
            ("10.203.0.2/32",),
            True,
            DirectPathErrorCode.HANDSHAKE_STALE,
        ),
        (
            (candidate(),),
            [True],
            NOW,
            (),
            True,
            DirectPathErrorCode.HOST_ROUTE_MISSING,
        ),
        (
            (candidate(),),
            [True],
            NOW,
            ("10.203.0.2/32",),
            False,
            DirectPathErrorCode.TARGET_UNREACHABLE,
        ),
    ],
)
def test_verifier_failure_matrix(
    candidates: tuple[EndpointCandidate, ...],
    endpoint_results: list[bool],
    handshake: datetime | None,
    routes: tuple[str, ...],
    target: bool,
    expected: DirectPathErrorCode,
) -> None:
    result = asyncio.run(
        verify(
            FakeProbe(endpoint_results=endpoint_results, target_result=target),
            candidates=candidates,
            handshake=handshake,
            routes=routes,
        )
    )
    assert not result.verified
    assert result.stable_error_code is expected


def test_verifier_rejects_naive_clock_and_future_or_naive_handshake() -> None:
    with pytest.raises(ValueError, match="时区"):
        asyncio.run(
            verify(
                FakeProbe(endpoint_results=[True]),
                now=NOW.replace(tzinfo=None),
            )
        )
    for handshake in (NOW.replace(tzinfo=None), NOW + timedelta(seconds=1)):
        result = asyncio.run(verify(FakeProbe(endpoint_results=[True]), handshake=handshake))
        assert result.stable_error_code is DirectPathErrorCode.HANDSHAKE_STALE


def test_controller_hysteresis_single_loss_sustained_failure_and_recovery() -> None:
    controller = DirectPathController(
        PathControllerPolicy(
            consecutive_failure_threshold=3,
            consecutive_success_threshold=2,
            minimum_dwell_seconds=0,
        ),
        initial=initial(),
    )
    assert controller.selection.path_type is NetworkPathType.STATIC
    first = asyncio.run(controller.reconcile(evidence(verified=True)))
    assert first.path_type is NetworkPathType.STATIC
    direct = asyncio.run(
        controller.reconcile(evidence(verified=True, at=NOW + timedelta(seconds=1)))
    )
    assert direct.path_type is NetworkPathType.DIRECT
    one_loss = asyncio.run(
        controller.reconcile(
            evidence(
                verified=False,
                at=NOW + timedelta(seconds=2),
                error=DirectPathErrorCode.TARGET_UNREACHABLE,
            )
        )
    )
    assert one_loss.path_type is NetworkPathType.DIRECT
    asyncio.run(
        controller.reconcile(
            evidence(
                verified=False,
                at=NOW + timedelta(seconds=3),
                error=DirectPathErrorCode.TARGET_UNREACHABLE,
            )
        )
    )
    fallback = asyncio.run(
        controller.reconcile(
            evidence(
                verified=False,
                at=NOW + timedelta(seconds=4),
                error=DirectPathErrorCode.TARGET_UNREACHABLE,
            )
        )
    )
    assert fallback.path_type is NetworkPathType.STATIC
    assert fallback.consecutive_failures == 3


def test_controller_dwell_revision_rollback_and_input_guards() -> None:
    calls: list[tuple[int, int]] = []

    async def rollback(failed_revision: int, good_revision: int) -> None:
        calls.append((failed_revision, good_revision))

    controller = DirectPathController(
        PathControllerPolicy(
            consecutive_failure_threshold=2,
            consecutive_success_threshold=2,
            minimum_dwell_seconds=10,
        ),
        initial=initial(NetworkPathType.DIRECT),
        rollback_revision=rollback,
    )
    failed = evidence(
        revision=2,
        verified=False,
        at=NOW + timedelta(seconds=11),
        error=DirectPathErrorCode.HOST_ROUTE_MISSING,
    )
    assert asyncio.run(controller.reconcile(failed)).path_type is NetworkPathType.DIRECT
    rolled = asyncio.run(
        controller.reconcile(failed.model_copy(update={"observed_at": NOW + timedelta(seconds=12)}))
    )
    assert rolled.path_type is NetworkPathType.STATIC
    assert rolled.stable_error_code is DirectPathErrorCode.REVISION_ROLLED_BACK
    assert calls == [(2, 1)]
    newer = DirectPathController(
        PathControllerPolicy(),
        initial=initial().model_copy(update={"revision": 2}),
    )
    with pytest.raises(ValueError, match="倒退"):
        asyncio.run(
            newer.reconcile(
                evidence(
                    revision=1,
                    verified=False,
                    error=DirectPathErrorCode.HOST_ROUTE_MISSING,
                )
            )
        )
    with pytest.raises(ValueError, match="static"):
        asyncio.run(
            controller.reconcile(
                failed,
                fallback=NetworkPathType.RELAYED,
            )
        )


def test_gateway_endpoint_selection_priority_freshness_and_validation() -> None:
    static = GatewayPathEndpoint(
        host="10.77.0.1",
        port=8787,
        path_type=NetworkPathType.STATIC,
        revision=0,
    )
    relay = GatewayPathEndpoint(
        host="10.77.0.3",
        port=8787,
        path_type=NetworkPathType.RELAYED,
        revision=1,
    )
    direct = GatewayPathEndpoint(
        host="10.203.0.2",
        port=8787,
        path_type=NetworkPathType.DIRECT,
        revision=2,
        verified_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    offline = GatewayPathEndpoint(
        host="10.77.0.4",
        port=8787,
        path_type=NetworkPathType.OFFLINE,
        revision=3,
    )
    assert select_gateway_endpoint((static, relay, direct, offline), now=NOW) == direct
    assert (
        select_gateway_endpoint(
            (static, relay, direct.model_copy(update={"expires_at": NOW})),
            now=NOW,
        )
        == relay
    )
    assert select_gateway_endpoint((static,), now=NOW) == static
    assert select_gateway_endpoint((offline,), now=NOW) is None
    with pytest.raises(ValueError, match="新鲜度"):
        GatewayPathEndpoint(
            host="10.203.0.2",
            port=8787,
            path_type=NetworkPathType.DIRECT,
            revision=1,
        )
    with pytest.raises(ValueError, match="通配"):
        GatewayPathEndpoint(
            host="0.0.0.0",
            port=8787,
            path_type=NetworkPathType.STATIC,
            revision=0,
        )
    with pytest.raises(ValueError, match="时区"):
        select_gateway_endpoint((static,), now=NOW.replace(tzinfo=None))
