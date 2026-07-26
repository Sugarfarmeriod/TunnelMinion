"""Coordinator 双应用工厂与监听配置边界测试。"""

from pathlib import Path
from typing import Any, Protocol, cast

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from tests.coordinator.test_directory import capability_snapshot, service_snapshot
from tests.coordinator.test_registry import (
    NETWORK,
    OTHER_NETWORK,
    MemorySecrets,
    MutableClock,
    authentication,
    enrollment,
    heartbeat_for,
    identity,
    registration,
)

from tunnelminion.coordinator.app import (
    CoordinatorAdminBindConfig,
    CoordinatorAgentBindConfig,
    CoordinatorApplicationConfig,
    build_coordinator_applications,
)
from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AuthenticatedCapabilitySnapshot,
    AuthenticatedDirectoryQuery,
    AuthenticatedServiceSnapshot,
    DirectoryQuery,
    EnrollmentTokenRequest,
)
from tunnelminion.coordinator.directory import CoordinatorDirectoryService
from tunnelminion.coordinator.identity import AssertionService, SigningKeyService
from tunnelminion.coordinator.registry import CoordinatorRegistryService, SQLiteCoordinatorStore


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...

    def post(self, url: str, *, json: Any | None = None) -> httpx.Response: ...

    def put(self, url: str, *, json: Any | None = None) -> httpx.Response: ...


def test_coordinator_builds_separate_agent_and_loopback_admin_apps(tmp_path: Path) -> None:
    config = CoordinatorApplicationConfig(
        data_path=tmp_path / "coordinator.sqlite3",
        agent_bind=CoordinatorAgentBindConfig(host="10.77.0.1", port=8790),
    )
    applications = build_coordinator_applications(config)
    agent = cast(ApiClient, TestClient(applications.agent_app))
    admin = cast(ApiClient, TestClient(applications.admin_app))

    assert applications.config.admin_bind == CoordinatorAdminBindConfig()
    assert CoordinatorAdminBindConfig(host="::1").host == "::1"
    assert agent.get("/api/v1/agent/health").json() == {
        "status": "available",
        "boundary": "agent",
    }
    assert agent.get("/api/v1/admin/health").status_code == 404
    assert admin.get("/api/v1/admin/health").json() == {
        "status": "available",
        "boundary": "admin",
    }
    assert admin.get("/api/v1/agent/health").status_code == 404
    assert agent.get("/openapi.json").status_code == 404
    assert admin.get("/api/docs").status_code == 200


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "8.8.8.8"])
def test_agent_api_requires_explicit_private_non_loopback_address(host: str) -> None:
    with pytest.raises(ValidationError, match="WireGuard"):
        CoordinatorAgentBindConfig(host=host, port=8790)


def test_admin_api_rejects_non_loopback_and_config_rejects_unknown_fields(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError, match="环回"):
        CoordinatorAdminBindConfig(host="10.77.0.1")
    with pytest.raises(ValidationError):
        CoordinatorApplicationConfig.model_validate(
            {
                "data_path": tmp_path / "coordinator.sqlite3",
                "agent_bind": {"host": "10.77.0.1", "port": 8790},
                "token": "should-not-be-here",
            }
        )


def test_coordinator_agent_identity_and_admin_node_apis(tmp_path: Path) -> None:
    clock = MutableClock()
    store = SQLiteCoordinatorStore(tmp_path / "coordinator.sqlite3")
    registry = CoordinatorRegistryService(store, clock=clock.utcnow)
    registry.create_network(NETWORK)
    token, _ = enrollment(registry)
    registered = registry.register(registration(token))
    auth = authentication(registered)
    secrets = MemorySecrets()
    keys = SigningKeyService(store, secrets, clock=clock.utcnow)
    keys.rotate()
    assertions = AssertionService(registry, keys, clock=clock.utcnow)
    directory = CoordinatorDirectoryService(store, registry, clock=clock.utcnow)
    config = CoordinatorApplicationConfig(
        data_path=store.path,
        agent_bind=CoordinatorAgentBindConfig(host="10.77.0.1", port=8790),
    )
    applications = build_coordinator_applications(
        config,
        registry=registry,
        assertions=assertions,
        directory=directory,
    )
    agent = cast(ApiClient, TestClient(applications.agent_app))
    admin = cast(ApiClient, TestClient(applications.admin_app))

    forbidden_enrollment = admin.post(
        "/api/v1/admin/enrollments",
        json=EnrollmentTokenRequest(network_id=OTHER_NETWORK).model_dump(mode="json"),
    )
    assert forbidden_enrollment.status_code == 403
    created_enrollment = admin.post(
        "/api/v1/admin/enrollments",
        json=EnrollmentTokenRequest(network_id=NETWORK).model_dump(mode="json"),
    )
    assert created_enrollment.status_code == 200
    second_registration = registration(
        created_enrollment.json()["token"],
        identity(node_id=type(auth.node_id).new(), display_name="second"),
        device="c" * 64,
        key="d" * 64,
    )
    registered_second = agent.post(
        "/api/v1/agent/registrations",
        json=second_registration.model_dump(mode="json"),
    )
    assert registered_second.status_code == 200
    invalid_registration = agent.post(
        "/api/v1/agent/registrations",
        json=second_registration.model_copy(
            update={"enrollment_token": f"tmne_{'x' * 43}"}
        ).model_dump(mode="json"),
    )
    assert invalid_registration.status_code == 409
    second_auth = authentication(type(registered).model_validate(registered_second.json()))
    rotated_self = agent.post(
        "/api/v1/agent/refresh/rotate",
        json=second_auth.model_dump(mode="json"),
    )
    assert rotated_self.status_code == 200
    assert (
        agent.post(
            "/api/v1/agent/refresh/rotate",
            json=second_auth.model_dump(mode="json"),
        ).status_code
        == 401
    )

    heartbeat = agent.post(
        "/api/v1/agent/heartbeat",
        json={
            "authentication": auth.model_dump(mode="json"),
            "heartbeat": heartbeat_for(auth).model_dump(mode="json"),
        },
    )
    assert heartbeat.status_code == 200
    assertion = agent.post(
        "/api/v1/agent/assertions",
        json=AccessAssertionRequest(
            authentication=auth,
            audience="tool-gateway",
        ).model_dump(mode="json"),
    )
    assert assertion.status_code == 200
    assert assertion.json()["assertion"] not in str(registry.audit_records(NETWORK))
    assert agent.get("/api/v1/agent/verification-keys").status_code == 200
    capability_payload = AuthenticatedCapabilitySnapshot(
        authentication=auth,
        snapshot=capability_snapshot(auth),
    )
    assert (
        agent.put(
            "/api/v1/agent/snapshots/capabilities",
            json=capability_payload.model_dump(mode="json"),
        ).status_code
        == 200
    )
    assert (
        agent.put(
            "/api/v1/agent/snapshots/services",
            json=AuthenticatedServiceSnapshot(
                authentication=auth,
                snapshot=service_snapshot(auth),
            ).model_dump(mode="json"),
        ).status_code
        == 200
    )
    directory_response = agent.post(
        "/api/v1/agent/directory/query",
        json=AuthenticatedDirectoryQuery(
            authentication=auth,
            query=DirectoryQuery(network_id=NETWORK),
        ).model_dump(mode="json"),
    )
    assert directory_response.status_code == 200
    assert any(node["capability_count"] == 1 for node in directory_response.json()["nodes"])
    out_of_order = agent.put(
        "/api/v1/agent/snapshots/capabilities",
        json=AuthenticatedCapabilitySnapshot(
            authentication=auth,
            snapshot=capability_snapshot(auth, key_character="c"),
        ).model_dump(mode="json"),
    )
    assert out_of_order.status_code == 400
    service_out_of_order = agent.put(
        "/api/v1/agent/snapshots/services",
        json=AuthenticatedServiceSnapshot(
            authentication=auth,
            snapshot=service_snapshot(auth, key_character="c"),
        ).model_dump(mode="json"),
    )
    assert service_out_of_order.status_code == 400
    forbidden_directory = agent.post(
        "/api/v1/agent/directory/query",
        json=AuthenticatedDirectoryQuery(
            authentication=auth,
            query=DirectoryQuery(
                network_id=type(NETWORK)("network_ffffffffffffffffffffffffffffffff")
            ),
        ).model_dump(mode="json"),
    )
    assert forbidden_directory.status_code == 403

    prefix = f"/api/v1/admin/networks/{NETWORK}/nodes/{auth.node_id}"
    assert admin.get(f"/api/v1/admin/networks/{NETWORK}/nodes").status_code == 200
    rotated = admin.post(f"{prefix}/rotate-refresh")
    assert rotated.status_code == 200
    revoked = admin.post(f"{prefix}/revoke", json={"reason": "lost"})
    assert revoked.json() == {"status": "revoked"}
    assert admin.post(f"{prefix}/rotate-refresh").status_code == 403
    assert admin.post(f"{prefix}/revoke", json={"reason": "again"}).status_code == 403
    denied = agent.post(
        "/api/v1/agent/heartbeat",
        json={
            "authentication": auth.model_dump(mode="json"),
            "heartbeat": heartbeat_for(auth).model_dump(mode="json"),
        },
    )
    assert denied.status_code == 401
    assert auth.refresh_credential not in denied.text
    restored = admin.post(f"{prefix}/restore")
    assert restored.status_code == 200
    assert restored.json()["refresh_credential"] != auth.refresh_credential
    assert admin.post(f"{prefix}/restore").status_code == 403
    offline_assertion = agent.post(
        "/api/v1/agent/assertions",
        json=AccessAssertionRequest(
            authentication=authentication(type(registered).model_validate(restored.json())),
            audience="tool-gateway",
        ).model_dump(mode="json"),
    )
    assert offline_assertion.status_code == 403
