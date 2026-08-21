"""跨平台只读 PathProbe 契约、预算、取消与失败矩阵测试。"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import datetime, timedelta
from typing import Any, NotRequired, TypedDict, TypeVar

import pytest
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, NOW

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import CandidateSource, EndpointCandidate, ProviderKind
from tunnelminion.network.path_controller import DirectPathErrorCode
from tunnelminion.network.path_probe import (
    ObservedEndpoint,
    PathProbeFacts,
    PathProbePolicy,
    PlatformPathProbe,
    tcp_target_probe,
)

T = TypeVar("T")


class ProbeArgs(TypedDict):
    network_id: NetworkId
    node_id: NodeId
    plan_hash: str
    authorization_revision: int
    revision: int
    candidates: tuple[EndpointCandidate, ...]
    expected_host_route: str
    target_host: str
    target_port: int
    now: datetime
    cancel_event: NotRequired[asyncio.Event]


def run(awaitable: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(awaitable)


def candidate(
    host: str,
    *,
    port: int = 51820,
    source: CandidateSource = CandidateSource.ADMIN_EXPLICIT,
    observed_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> EndpointCandidate:
    return EndpointCandidate(
        host=host,
        port=port,
        source=source,
        observed_at=observed_at,
        expires_at=expires_at,
    )


def facts(
    *,
    endpoints: tuple[tuple[str, int], ...] = (("10.0.0.10", 51820),),
    handshake: datetime | None = NOW,
    routes: tuple[str, ...] = ("10.0.0.2/32",),
    error: DirectPathErrorCode | None = None,
    source: str = "fixture:readonly",
) -> PathProbeFacts:
    return PathProbeFacts(
        source=source,
        observed_endpoints=tuple(
            ObservedEndpoint(host=host, port=port) for host, port in endpoints
        ),
        last_handshake_at=handshake,
        handshake_probe_at=NOW,
        host_routes=routes,
        host_route_probe_at=NOW,
        observed_at=NOW,
        error_code=error,
    )


def policy(**updates: object) -> PathProbePolicy:
    values: dict[str, object] = {
        "approved_networks": ("10.0.0.0/24", "fd00::/64"),
        "approved_ports": (51820,),
    }
    values.update(updates)
    return PathProbePolicy.model_validate(values)


class FactsReader:
    def __init__(self, value: PathProbeFacts, *, delay: float = 0) -> None:
        self.value = value
        self.delay = delay
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.started = asyncio.Event()

    async def __call__(self) -> PathProbeFacts:
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            return self.value
        finally:
            self.active -= 1


class TargetReader:
    def __init__(self, value: bool = True, *, delay: float = 0) -> None:
        self.value = value
        self.delay = delay
        self.calls: list[tuple[str, int, float]] = []
        self.started = asyncio.Event()

    async def __call__(self, host: str, port: int, timeout_seconds: float) -> bool:
        self.calls.append((host, port, timeout_seconds))
        self.started.set()
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.value


def make_probe(
    reader: FactsReader,
    target: TargetReader | None = None,
    **updates: object,
) -> PlatformPathProbe:
    return PlatformPathProbe(
        provider=ProviderKind.WINDOWS,
        policy=policy(**updates),
        facts_reader=reader,
        target_probe=target or TargetReader(),
    )


def probe_args(
    *,
    revision: int = 1,
    candidates: tuple[EndpointCandidate, ...] = (candidate("10.0.0.10"),),
    now: datetime = NOW,
    expected_host_route: str = "10.0.0.2/32",
    target_host: str = "10.0.0.2",
    target_port: int = 51820,
    cancel_event: asyncio.Event | None = None,
) -> ProbeArgs:
    values: ProbeArgs = {
        "network_id": NETWORK_ID,
        "node_id": NODE_A,
        "plan_hash": f"sha256:{'b' * 64}",
        "authorization_revision": revision,
        "revision": revision,
        "candidates": candidates,
        "expected_host_route": expected_host_route,
        "target_host": target_host,
        "target_port": target_port,
        "now": now,
    }
    if cancel_event is not None:
        values["cancel_event"] = cancel_event
    return values


def test_policy_fixes_budget_ports_and_refresh_interval() -> None:
    value = policy()
    assert value.max_candidates == 4
    assert value.per_candidate_timeout_seconds == 1
    assert value.target_timeout_seconds == 2
    assert value.min_refresh_interval_seconds == 30
    with pytest.raises(ValidationError):
        policy(max_candidates=5)
    with pytest.raises(ValidationError):
        policy(per_candidate_timeout_seconds=1.1)
    with pytest.raises(ValidationError):
        policy(target_timeout_seconds=2.1)
    with pytest.raises(ValidationError):
        policy(min_refresh_interval_seconds=29.9)
    with pytest.raises(ValidationError):
        policy(min_refresh_interval_seconds=30.1)
    with pytest.raises(ValidationError):
        policy(approved_ports=(51820, 51820))
    with pytest.raises(ValidationError):
        PathProbePolicy(approved_networks=("10.0.0.0/24",), approved_ports=(0,))


def test_facts_reject_secret_like_or_unbounded_values() -> None:
    with pytest.raises(ValidationError, match="时区"):
        PathProbeFacts(
            source="fixture",
            handshake_probe_at=NOW.replace(tzinfo=None),
            host_route_probe_at=NOW,
            observed_at=NOW,
        )
    with pytest.raises(ValidationError, match="host route"):
        facts(routes=("10.0.0.0/24",))
    with pytest.raises(ValidationError, match="规范"):
        facts(routes=("10.0.0.2/255.255.255.255",))
    with pytest.raises(ValidationError):
        ObservedEndpoint(host="not-an-ip", port=51820)
    with pytest.raises(ValidationError):
        PathProbeFacts(
            source="fixture",
            last_handshake_at=NOW.replace(tzinfo=None),
            handshake_probe_at=NOW,
            host_route_probe_at=NOW,
            observed_at=NOW,
        )


def test_probe_filters_sources_network_ports_expiry_and_budget() -> None:
    values = tuple(candidate(f"10.0.0.{index}") for index in range(10, 15))
    reader = FactsReader(facts(endpoints=(("10.0.0.13", 51820),)))
    target = TargetReader()
    result = run(
        make_probe(reader, target).probe(
            **probe_args(
                candidates=(
                    values[0],
                    candidate("10.0.0.11", source=CandidateSource.NODE_OBSERVED),
                    candidate("10.0.0.12", port=51821),
                    candidate("10.0.0.13"),
                    candidate("10.0.0.14"),
                    candidate("192.0.2.1"),
                    candidate("fd00::10"),
                    candidate(
                        "10.0.0.15",
                        observed_at=NOW - timedelta(minutes=2),
                        expires_at=NOW - timedelta(minutes=1),
                    ),
                )
            )
        )
    )
    assert result.candidate_count == 4
    assert result.selected_candidate_source is CandidateSource.ADMIN_EXPLICIT
    assert result.endpoint_probe_succeeded
    assert result.selected_candidate_hash is not None
    assert result.source == "fixture:readonly"
    assert result.endpoint_probe_at is not None
    assert result.handshake_probe_at is not None
    assert result.host_route_probe_at is not None
    assert result.target_probe_at is not None
    assert result.target_probe_succeeded
    assert target.calls == [("10.0.0.2", 51820, 2.0)]


def test_probe_refresh_is_cached_and_concurrent_requests_are_serialized() -> None:
    reader = FactsReader(facts(), delay=0.01)
    target = TargetReader(delay=0.01)
    probe = make_probe(reader, target)
    first = run(probe.probe(**probe_args()))
    cached = run(probe.probe(**probe_args(now=NOW + timedelta(seconds=1))))
    assert cached == first
    assert reader.calls == 1
    assert len(target.calls) == 1

    async def gather_results() -> list[object]:
        return list(
            await asyncio.gather(
                probe.probe(**probe_args(revision=2, now=NOW + timedelta(seconds=31))),
                probe.probe(**probe_args(revision=3, now=NOW + timedelta(seconds=31))),
            )
        )

    results = run(gather_results())
    assert len(results) == 2
    assert reader.max_active == 1


@pytest.mark.parametrize(
    ("reader_facts", "target_value", "expected"),
    [
        (facts(endpoints=()), True, DirectPathErrorCode.ENDPOINT_UNREACHABLE),
        (facts(handshake=NOW - timedelta(minutes=10)), True, DirectPathErrorCode.HANDSHAKE_STALE),
        (facts(routes=()), True, DirectPathErrorCode.HOST_ROUTE_MISSING),
        (facts(), False, DirectPathErrorCode.TARGET_UNREACHABLE),
        (facts(endpoints=()), True, DirectPathErrorCode.NO_APPROVED_CANDIDATE),
    ],
)
def test_probe_failure_matrix(
    reader_facts: PathProbeFacts,
    target_value: bool,
    expected: DirectPathErrorCode,
) -> None:
    candidates = (
        () if expected is DirectPathErrorCode.NO_APPROVED_CANDIDATE else (candidate("10.0.0.10"),)
    )
    result = run(
        make_probe(FactsReader(reader_facts), TargetReader(target_value)).probe(
            **probe_args(candidates=candidates)
        )
    )
    assert not result.verified
    assert result.stable_error_code is expected
    if expected in {
        DirectPathErrorCode.ENDPOINT_UNREACHABLE,
        DirectPathErrorCode.NO_APPROVED_CANDIDATE,
        DirectPathErrorCode.TARGET_UNREACHABLE,
    }:
        assert not result.target_probe_succeeded


@pytest.mark.parametrize(
    "error",
    [DirectPathErrorCode.PERMISSION_DENIED, DirectPathErrorCode.UNSUPPORTED],
)
def test_probe_permission_and_unsupported_are_stable_degradations(
    error: DirectPathErrorCode,
) -> None:
    reader = FactsReader(facts(error=error))
    target = TargetReader()
    result = run(make_probe(reader, target).probe(**probe_args()))
    assert result.stable_error_code is error
    assert not result.verified
    assert not target.calls


@pytest.mark.parametrize(
    ("exception_type", "expected"),
    [
        (NotImplementedError, DirectPathErrorCode.UNSUPPORTED),
        (ConnectionError, DirectPathErrorCode.PROVIDER_UNAVAILABLE),
        (OSError, DirectPathErrorCode.PATH_UNAVAILABLE),
    ],
)
def test_probe_reader_exception_matrix_is_stable(
    exception_type: type[Exception],
    expected: DirectPathErrorCode,
) -> None:
    async def failing() -> PathProbeFacts:
        raise exception_type("fake read failure")

    result = run(
        PlatformPathProbe(
            provider=ProviderKind.WINDOWS,
            policy=policy(),
            facts_reader=failing,
        ).probe(**probe_args())
    )
    assert result.stable_error_code is expected


def test_probe_handles_reader_timeout_and_permission_errors() -> None:
    timeout_reader = FactsReader(facts(), delay=0.05)
    cancel = asyncio.Event()
    timed = run(
        make_probe(timeout_reader, per_candidate_timeout_seconds=0.01).probe(
            **probe_args(cancel_event=cancel)
        )
    )
    assert timed.stable_error_code is DirectPathErrorCode.TIMEOUT

    async def denied() -> PathProbeFacts:
        raise PermissionError("denied")

    denied_probe = PlatformPathProbe(
        provider=ProviderKind.MACOS,
        policy=policy(),
        facts_reader=denied,
    )
    result = run(denied_probe.probe(**probe_args()))
    assert result.stable_error_code is DirectPathErrorCode.PERMISSION_DENIED


def test_probe_target_timeout_with_untriggered_cancel_event() -> None:
    target = TargetReader(delay=0.05)
    cancel = asyncio.Event()
    probe = make_probe(FactsReader(facts()), target, target_timeout_seconds=0.01)
    result = run(probe.probe(**probe_args(cancel_event=cancel)))
    assert result.stable_error_code is DirectPathErrorCode.TARGET_UNREACHABLE
    assert not result.target_probe_succeeded


def test_probe_target_timeout_and_compatibility_methods() -> None:
    reader = FactsReader(facts())
    target = TargetReader(delay=0.05)
    probe = make_probe(reader, target, target_timeout_seconds=0.01)
    timed = run(probe.probe(**probe_args()))
    assert timed.stable_error_code is DirectPathErrorCode.TARGET_UNREACHABLE
    assert not timed.target_probe_succeeded

    assert run(probe.endpoint(candidate("10.0.0.10"), 1))
    with pytest.raises(TimeoutError):
        run(probe.target("10.0.0.2", 51820, 0.01))
    with pytest.raises(ValueError, match="私有"):
        run(probe.target("8.8.8.8", 51820, 1))


def test_probe_cancellation_stops_facts_and_target() -> None:
    reader = FactsReader(facts(), delay=10)
    cancel = asyncio.Event()
    probe = make_probe(reader)

    async def exercise() -> None:
        task = asyncio.create_task(probe.probe(**probe_args(cancel_event=cancel)))  # type: ignore[arg-type]
        await reader.started.wait()
        cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert [item for item in asyncio.all_tasks() if item is not asyncio.current_task()] == []

    run(exercise())
    assert reader.active == 0

    target = TargetReader(delay=10)
    reader = FactsReader(facts())
    cancel = asyncio.Event()
    probe = make_probe(reader, target)

    async def cancel_target() -> None:
        task = asyncio.create_task(probe.probe(**probe_args(cancel_event=cancel)))  # type: ignore[arg-type]
        await target.started.wait()
        cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert [item for item in asyncio.all_tasks() if item is not asyncio.current_task()] == []

    run(cancel_target())


def test_probe_rejects_public_target_and_non_host_route() -> None:
    probe = make_probe(FactsReader(facts()))
    with pytest.raises(ValueError, match="host route"):
        run(probe.probe(**probe_args(expected_host_route="10.0.0.0/24")))
    with pytest.raises(ValueError, match="批准"):
        run(probe.probe(**probe_args(expected_host_route="192.168.1.1/32")))
    with pytest.raises(ValueError, match="私有"):
        run(probe.probe(**probe_args(target_host="8.8.8.8")))
    with pytest.raises(ValidationError):
        EndpointCandidate(
            host="evil.example",
            port=51820,
            source=CandidateSource.ADMIN_EXPLICIT,
            observed_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )


def test_probe_rejects_private_but_unapproved_target_before_connection() -> None:
    target = TargetReader()
    probe = make_probe(FactsReader(facts()), target)
    with pytest.raises(ValueError, match="批准"):
        run(probe.probe(**probe_args(target_host="192.168.1.77", target_port=22)))
    assert target.calls == []


def test_probe_rejects_naive_clock_cancelled_before_start_and_bad_target_bounds() -> None:
    probe = make_probe(FactsReader(facts()))
    with pytest.raises(ValueError, match="时钟"):
        run(probe.probe(**probe_args(now=NOW.replace(tzinfo=None))))
    cancel = asyncio.Event()
    cancel.set()
    with pytest.raises(asyncio.CancelledError):
        run(probe.probe(**probe_args(cancel_event=cancel)))
    for host in ("0.0.0.0", "224.0.0.1"):
        with pytest.raises(ValueError):
            run(probe.target(host, 51820, 1))
    with pytest.raises(ValueError, match="端口"):
        run(probe.target("10.0.0.2", 0, 1))


def test_probe_marks_missing_handshake_as_stale() -> None:
    result = run(make_probe(FactsReader(facts(handshake=None))).probe(**probe_args()))
    assert result.stable_error_code is DirectPathErrorCode.HANDSHAKE_STALE


def test_tcp_target_probe_is_read_only_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    class Writer:
        closed = False

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    writer = Writer()

    async def opened(host: str, port: int) -> tuple[object, Writer]:
        assert (host, port) == ("127.0.0.1", 1)
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", opened)
    assert run(tcp_target_probe("127.0.0.1", 1, 1))
    assert writer.closed

    async def failed(host: str, port: int) -> tuple[object, Writer]:
        del host, port
        raise OSError("unreachable")

    monkeypatch.setattr(asyncio, "open_connection", failed)
    assert not run(tcp_target_probe("127.0.0.1", 1, 1))
