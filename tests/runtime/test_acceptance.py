"""独立 A/B peer 结果、包摘要和零秘密响应边界测试。"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import cast

import httpx
import pytest

from tunnelminion.runtime.acceptance import (
    DEFAULT_MAX_RESPONSE_BYTES,
    PackageEntrypointSummary,
    PeerAcceptanceProbe,
    PeerAcceptanceResult,
    PeerAcceptanceState,
    _consume_response,  # pyright: ignore[reportPrivateUsage]
    is_production_candidate_accepted,
    package_entrypoint_summary,
)


def _manifest() -> dict[str, object]:
    return {
        "candidate": {
            "id": "tunnelminion-test-win32-amd64",
            "application_version": "0.1.0",
            "platform": "win32",
            "architecture": "amd64",
        },
        "entrypoint": "tunnelminion.exe",
        "entrypoint_args": ["runtime-child"],
        "files": [
            {
                "path": "tunnelminion.exe",
                "sha256": "a" * 64,
                "size": 12,
            }
        ],
    }


def _package() -> PackageEntrypointSummary:
    return package_entrypoint_summary(_manifest(), manifest_bytes=b"manifest")


def _probe(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> PeerAcceptanceProbe:
    return PeerAcceptanceProbe(
        max_response_bytes=max_response_bytes,
        transport=httpx.MockTransport(handler),
    )


def test_package_summary_binds_manifest_and_entrypoint_without_paths() -> None:
    summary = _package()

    assert summary.package_id == "tunnelminion-test-win32-amd64"
    assert summary.manifest_sha256 == hashlib.sha256(b"manifest").hexdigest()
    assert summary.entrypoint_sha256 == "a" * 64
    serialized = summary.model_dump_json()
    assert "tunnelminion.exe" not in serialized
    assert "runtime-child" not in serialized

    canonical = package_entrypoint_summary(_manifest())
    assert canonical.manifest_sha256 != summary.manifest_sha256
    assert PackageEntrypointSummary.from_manifest(_manifest()) == canonical


@pytest.mark.parametrize("case", range(10))
def test_package_summary_rejects_invalid_manifest_fields(
    case: int,
) -> None:
    value = _manifest()
    if case == 0:
        value["candidate"] = "bad"
    elif case == 1:
        cast(dict[str, object], value["candidate"])["id"] = ""
    elif case == 2:
        value["entrypoint"] = "../outside"
    elif case == 3:
        value["files"] = "bad"
    elif case == 4:
        cast(list[object], value["files"])[0] = "bad"
    elif case == 5:
        cast(dict[str, object], cast(list[object], value["files"])[0])["sha256"] = "bad"
    elif case == 6:
        value["entrypoint"] = "missing"
    elif case == 7:
        value["entrypoint_args"] = "bad"
    elif case == 8:
        value["entrypoint_args"] = list(range(9))
    else:
        cast(list[object], value["entrypoint_args"])[0] = 3
    with pytest.raises(ValueError):
        package_entrypoint_summary(value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        "ftp://peer.example",
        "http://user:password@peer.example",
        "http://peer.example/base",
        "http://peer.example?token=secret",
        "http://peer.example#fragment",
        "http://peer.example:not-a-port",
        "http://peer.example:0",
    ],
)
def test_invalid_peer_endpoint_is_unverified_without_request(endpoint: str) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        del request
        called = True
        return httpx.Response(401)

    result = _probe(handler).probe(endpoint, _package())

    assert result.status is PeerAcceptanceState.UNVERIFIED
    assert result.error_code == "peer_endpoint_invalid"
    assert not result.accepted
    assert not called


def test_missing_package_evidence_is_unverified_and_does_not_request_peer() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        del request
        called = True
        return httpx.Response(401)

    result = _probe(handler).probe("http://peer.example:8787", None)

    assert result.status is PeerAcceptanceState.UNVERIFIED
    assert result.error_code == "package_entrypoint_unverified"
    assert result.package is None
    assert not called


def test_unauthorized_401_is_the_only_accepted_peer_evidence() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert "authorization" not in request.headers
        assert request.headers["accept"] == "application/json"
        return httpx.Response(401, request=request, text="unauthorized")

    result = _probe(handler).probe("http://peer.example:8787/", _package())

    assert result.status is PeerAcceptanceState.REACHABLE
    assert result.accepted
    assert result.http_status == 401
    assert result.response_size_bytes == len(b"unauthorized")
    assert seen == ["http://peer.example:8787/v1/capabilities"]
    assert result.endpoint_sha256 is not None
    assert is_production_candidate_accepted(True, result)
    assert not is_production_candidate_accepted(False, result)


def test_peer_latency_uses_injected_monotonic_clock() -> None:
    now = 0.0

    def monotonic() -> float:
        nonlocal now
        value = now
        now += 0.012
        return value

    probe = PeerAcceptanceProbe(
        monotonic=monotonic,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(401, request=request, text="ok")
        ),
    )
    result = probe.probe("http://peer.example:8787", _package())

    assert result.latency_ms == 12


def test_peer_reachable_cannot_override_local_ownership_conflict() -> None:
    result = _probe(
        lambda request: httpx.Response(401, request=request, text="unauthorized")
    ).probe("http://peer.example:8787", _package())

    assert result.status is PeerAcceptanceState.REACHABLE
    assert result.accepted
    assert not is_production_candidate_accepted(False, result)


@pytest.mark.parametrize(
    ("response", "error_code"),
    [
        (httpx.Response(200, text="not accepted"), "peer_http_unexpected_status"),
        (httpx.Response(401, text="Authorization: Bearer tmn_fake"), "peer_response_body_rejected"),
    ],
)
def test_wrong_status_or_sensitive_body_cannot_be_accepted(
    response: httpx.Response,
    error_code: str,
) -> None:
    result = _probe(lambda request: response).probe("http://peer.example:8787", _package())

    assert result.status is PeerAcceptanceState.UNREACHABLE
    assert not result.accepted
    assert result.error_code == error_code
    assert result.http_status in {200, 401}
    assert "tmn_fake" not in result.model_dump_json()
    assert "Authorization" not in result.model_dump_json()


def test_oversized_body_is_counted_only_to_the_bounded_limit() -> None:
    result = _probe(
        lambda request: httpx.Response(401, request=request, content=b"x" * 9),
        max_response_bytes=8,
    ).probe("http://peer.example:8787", _package())

    assert result.status is PeerAcceptanceState.UNREACHABLE
    assert result.error_code == "peer_response_too_large"
    assert result.response_size_bytes == 9
    assert "xxxxxxxx" not in result.model_dump_json()


@pytest.mark.parametrize(
    "error",
    [
        httpx.TimeoutException("timeout"),
        httpx.HTTPError("http"),
        OSError("socket"),
        RuntimeError("fixture"),
        ValueError("untrusted response iterator"),
    ],
)
def test_peer_transport_failures_are_stable_and_redacted(error: BaseException) -> None:
    result = _probe(
        lambda request: (_ for _ in ()).throw(error),
    ).probe("http://peer.example:8787", _package())

    assert result.status is PeerAcceptanceState.UNREACHABLE
    assert result.error_code in {"peer_timeout", "peer_unreachable", "peer_probe_failed"}
    assert "socket" not in result.model_dump_json()
    assert "fixture" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("timeout", "limit"),
    [
        (0.0, DEFAULT_MAX_RESPONSE_BYTES),
        (31.0, DEFAULT_MAX_RESPONSE_BYTES),
        (3.0, 0),
        (3.0, 1024 * 1024 + 1),
    ],
)
def test_peer_probe_rejects_unbounded_parameters(timeout: float, limit: int) -> None:
    with pytest.raises(ValueError):
        PeerAcceptanceProbe(timeout_seconds=timeout, max_response_bytes=limit)


def test_response_consumer_handles_chunk_boundary_markers_without_storing_body() -> None:
    size, error = _consume_response(
        (chunk for chunk in (b"prefix Bear", b"er tmn_fake suffix")),
        1024,
    )
    assert size == len(b"prefix Bearer tmn_fake suffix")
    assert error == "peer_response_body_rejected"

    size, error = _consume_response((b"safe",), 1024)
    assert size == 4
    assert error is None


def test_result_model_rejects_non_401_or_authorized_acceptance() -> None:
    package = _package()
    with pytest.raises(ValueError):
        PeerAcceptanceResult(
            status=PeerAcceptanceState.REACHABLE,
            accepted=True,
            package=package,
            http_status=200,
            latency_ms=0,
        )
    with pytest.raises(ValueError, match="peer_reachable"):
        PeerAcceptanceResult(
            status=PeerAcceptanceState.REACHABLE,
            accepted=False,
            package=package,
            http_status=200,
            latency_ms=0,
        )
    with pytest.raises(ValueError):
        PeerAcceptanceResult(
            status=PeerAcceptanceState.UNREACHABLE,
            accepted=False,
            package=package,
            http_status=401,
            latency_ms=0,
            authorization_header_sent=True,
        )


def test_package_summary_rejects_relative_path_variants() -> None:
    for entrypoint in ("/absolute", "\\absolute", "C:/absolute", "dir/../entry"):
        value = _manifest()
        value["entrypoint"] = entrypoint
        with pytest.raises(ValueError):
            package_entrypoint_summary(value)


def test_package_summary_rejects_bad_file_shape_and_bad_argument_type() -> None:
    value = _manifest()
    cast(list[object], value["files"])[0] = {"path": "tunnelminion.exe", "sha256": "a" * 63}
    with pytest.raises(ValueError):
        package_entrypoint_summary(value)

    value = _manifest()
    cast(list[object], value["entrypoint_args"])[0] = "x" * 161
    with pytest.raises(ValueError):
        package_entrypoint_summary(value)
