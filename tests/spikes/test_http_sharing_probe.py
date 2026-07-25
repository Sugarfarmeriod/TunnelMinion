# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from spikes.sharing.http_proxy_probe import (
    MAX_PROBE_RESPONSE_BYTES,
    PROBE_OWNER_PREFIX,
    PROBE_TOKEN,
    ProbeConfig,
    ProbeLease,
    build_proxy_app,
    build_upstream_fixture,
    compare_proxy_options,
    recover_stale_probe_lease,
    validate_bind_host,
    write_probe_lease,
)


def _config(**updates: object) -> ProbeConfig:
    values: dict[str, object] = {
        "bind_host": "10.77.0.2",
        "bind_port": 18881,
        "allowed_bind_hosts": frozenset({"10.77.0.2"}),
        "upstream_url": "http://fixture",
        "token": PROBE_TOKEN,
        "timeout_seconds": 1,
        "max_response_bytes": MAX_PROBE_RESPONSE_BYTES,
    }
    values.update(updates)
    return ProbeConfig.model_validate(values)


def test_proxy_rejects_invalid_or_unlisted_bind_addresses() -> None:
    for host in ("0.0.0.0", "127.0.0.1", "8.8.8.8"):
        try:
            validate_bind_host(host, frozenset({host}))
        except ValueError:
            pass
        else:
            raise AssertionError(f"{host} 应被拒绝")

    try:
        validate_bind_host("10.77.0.3", frozenset({"10.77.0.2"}))
    except ValueError:
        pass
    else:
        raise AssertionError("未列入允许集合的地址应被拒绝")


def test_proxy_requires_token_and_forwards_bounded_request() -> None:
    upstream = build_upstream_fixture()
    transport = httpx.ASGITransport(app=upstream)
    client = TestClient(build_proxy_app(_config(), transport=transport))

    denied = client.get("/fixture/denied")
    allowed = client.post(
        "/fixture/allowed",
        headers={"X-TunnelMinion-Share-Token": PROBE_TOKEN},
        content=b"probe",
    )

    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "invalid_share_token"
    assert allowed.status_code == 200
    assert allowed.json() == {"path": "allowed", "method": "POST", "body": "probe"}


def test_proxy_rejects_oversized_upstream_response() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 32)

    client = TestClient(
        build_proxy_app(
            _config(max_response_bytes=16),
            transport=httpx.MockTransport(handler),
        )
    )

    response = client.get(
        "/large",
        headers={"X-TunnelMinion-Share-Token": PROBE_TOKEN},
    )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_response_too_large"


def test_recovery_only_removes_owned_stale_probe_lease(tmp_path: Path) -> None:
    lease_path = tmp_path / "lease.json"
    owned = ProbeLease(
        owner_id=f"{PROBE_OWNER_PREFIX}test",
        bind_host="10.77.0.2",
        bind_port=18881,
        process_id=100,
    )
    write_probe_lease(lease_path, owned)

    active = recover_stale_probe_lease(lease_path, active_process_ids=frozenset({100}))
    stale = recover_stale_probe_lease(lease_path, active_process_ids=frozenset())

    assert not active.recovered
    assert active.reason == "process_active"
    assert stale.recovered
    assert not lease_path.exists()

    write_probe_lease(
        lease_path,
        owned.model_copy(update={"owner_id": "foreign_resource"}),
    )
    foreign = recover_stale_probe_lease(lease_path, active_process_ids=frozenset())

    assert not foreign.recovered
    assert foreign.reason == "foreign_owner"
    assert lease_path.exists()


def test_embedded_proxy_is_available_without_external_binary() -> None:
    embedded, external = compare_proxy_options()

    assert embedded.available
    assert embedded.packaged_with_project
    assert embedded.explicit_lifecycle
    assert not embedded.extra_system_config
    assert external.name == "managed-external-proxy"
