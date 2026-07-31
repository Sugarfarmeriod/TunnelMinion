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
from tests.network.factories import desired

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
    CoordinatorErrorCode,
    DirectoryQuery,
    EnrollmentTokenRequest,
)
from tunnelminion.coordinator.directory import CoordinatorDirectoryService
from tunnelminion.coordinator.identity import AssertionService, SigningKeyService
from tunnelminion.coordinator.network_control import (
    AddressPoolRequest,
    ManagedNetworkControlService,
    ManagedNetworkRequest,
    RelayRoleRequest,
)
from tunnelminion.coordinator.registry import (
    CoordinatorRegistryService,
    RegistryError,
    SQLiteCoordinatorStore,
)
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.network.contracts import AcknowledgementStage, NetworkAcknowledgement, RelayRole
from tunnelminion.network.governance import NetworkPathStatus


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
    page = admin.get("/")
    assert page.status_code == 200
    assert "创建并复制一次性 token" in page.text
    assert "refresh_credential" not in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]


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


def test_managed_network_admin_routes_map_service_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteCoordinatorStore(tmp_path / "coordinator.sqlite3")
    keys = SigningKeyService(store, MemorySecrets())
    keys.rotate()
    control = ManagedNetworkControlService(store, keys)
    config = CoordinatorApplicationConfig(
        data_path=store.path,
        agent_bind=CoordinatorAgentBindConfig(host="10.77.0.1", port=8790),
    )
    admin = cast(
        ApiClient,
        TestClient(
            build_coordinator_applications(
                config,
                network_control=control,
            ).admin_app
        ),
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise RegistryError(CoordinatorErrorCode.FORBIDDEN, "测试拒绝")

    monkeypatch.setattr(control, "create_network", reject)
    assert (
        admin.post(
            "/api/v1/admin/networks",
            json=ManagedNetworkRequest(network_id=NETWORK).model_dump(mode="json"),
        ).status_code
        == 403
    )
    monkeypatch.setattr(control, "list_address_pools", reject)
    assert admin.get(f"/api/v1/admin/networks/{NETWORK}/address-pools").status_code == 403
    monkeypatch.setattr(control, "set_relay_role", reject)
    assert (
        admin.put(
            f"/api/v1/admin/networks/{NETWORK}/nodes/{NodeId.new()}/relay-role",
            json=RelayRoleRequest(role=RelayRole.NONE).model_dump(mode="json"),
        ).status_code
        == 403
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
    network_control = ManagedNetworkControlService(store, keys, clock=clock.utcnow)
    config = CoordinatorApplicationConfig(
        data_path=store.path,
        agent_bind=CoordinatorAgentBindConfig(host="10.77.0.1", port=8790),
    )
    applications = build_coordinator_applications(
        config,
        registry=registry,
        assertions=assertions,
        directory=directory,
        network_control=network_control,
    )
    agent = cast(ApiClient, TestClient(applications.agent_app))
    admin = cast(ApiClient, TestClient(applications.admin_app))

    managed = admin.post(
        "/api/v1/admin/networks",
        json=ManagedNetworkRequest(network_id=NETWORK).model_dump(mode="json"),
    )
    assert managed.json() == {"network_id": str(NETWORK)}
    pool_path = f"/api/v1/admin/networks/{NETWORK}/address-pools"
    pool_request = AddressPoolRequest(
        pool="10.204.0.0/29",
        reserved_addresses=("10.204.0.1",),
    )
    assert admin.post(pool_path, json=pool_request.model_dump(mode="json")).status_code == 200
    assert admin.get(pool_path).json()[0]["pool"] == "10.204.0.0/29"
    relay_path = f"/api/v1/admin/networks/{NETWORK}/nodes/{auth.node_id}/relay-role"
    relay = admin.put(
        relay_path,
        json=RelayRoleRequest(
            role=RelayRole.CAPABLE,
            capability_verified=True,
        ).model_dump(mode="json"),
    )
    assert relay.json()["role"] == RelayRole.CAPABLE.value
    assert agent.get(pool_path).status_code == 404
    assert (
        admin.post(
            f"/api/v1/admin/networks/{OTHER_NETWORK}/address-pools",
            json=pool_request.model_dump(mode="json"),
        ).status_code
        == 403
    )
    assert (
        admin.put(
            relay_path,
            json={"role": "active", "capability_verified": False},
        ).status_code
        == 422
    )

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

    desired_config = desired(
        network_id=NETWORK,
        target_node_id=auth.node_id,
        revision=network_control.next_revision(NETWORK),
        parent_revision=0,
    )
    envelope = network_control.publish_desired_configs((desired_config,))[0]
    pull_path = "/api/v1/agent/network/desired-configs/query"
    pulled = agent.post(
        pull_path,
        json={
            "authentication": auth.model_dump(mode="json"),
            "after_revision": 0,
            "full_sync": False,
        },
    )
    assert pulled.status_code == 200
    assert pulled.json()[0]["config"]["target_node_id"] == str(auth.node_id)
    assert (
        agent.post(
            pull_path,
            json={
                "authentication": auth.model_dump(mode="json"),
                "after_revision": envelope.config.revision,
                "full_sync": True,
            },
        ).json()[0]["config"]["revision"]
        == envelope.config.revision
    )
    with pytest.raises(ValueError, match="after_revision"):
        network_control.pull_desired_configs(auth, after_revision=-1, full_sync=False)
    assert (
        agent.post(
            pull_path,
            json={
                "authentication": auth.model_dump(mode="json"),
                "after_revision": envelope.config.revision,
                "full_sync": False,
            },
        ).json()
        == []
    )
    acknowledgement = NetworkAcknowledgement(
        network_id=NETWORK,
        node_id=auth.node_id,
        revision=envelope.config.revision,
        stage=AcknowledgementStage.PENDING,
        acknowledged_at=clock.utcnow(),
    )
    acknowledged = agent.post(
        "/api/v1/agent/network/acknowledgements",
        json={
            "authentication": auth.model_dump(mode="json"),
            "acknowledgement": acknowledgement.model_dump(mode="json"),
        },
    )
    assert acknowledged.json() == {"status": "accepted"}
    path_status = NetworkPathStatus(
        network_id=NETWORK,
        node_id=auth.node_id,
        revision=envelope.config.revision,
        path_type="pending",
        candidate_count=0,
    )
    reported = agent.post(
        "/api/v1/agent/network/path-status",
        json={
            "authentication": auth.model_dump(mode="json"),
            "status": path_status.model_dump(mode="json"),
        },
    )
    assert reported.json() == {"status": "accepted"}
    assert (
        agent.post(
            "/api/v1/agent/network/path-status",
            json={
                "authentication": auth.model_dump(mode="json"),
                "status": path_status.model_copy(update={"node_id": NodeId.new()}).model_dump(
                    mode="json"
                ),
            },
        ).status_code
        == 403
    )
    assert (
        agent.post(
            "/api/v1/agent/network/path-status",
            json={
                "authentication": auth.model_dump(mode="json"),
                "status": path_status.model_copy(update={"revision": 999}).model_dump(mode="json"),
            },
        ).status_code
        == 400
    )
    invalid_auth = auth.model_copy(update={"refresh_credential": "x" * 43})
    assert (
        agent.post(
            pull_path,
            json={
                "authentication": invalid_auth.model_dump(mode="json"),
                "after_revision": 0,
                "full_sync": False,
            },
        ).status_code
        == 401
    )
    assert (
        agent.post(
            "/api/v1/agent/network/acknowledgements",
            json={
                "authentication": invalid_auth.model_dump(mode="json"),
                "acknowledgement": acknowledgement.model_dump(mode="json"),
            },
        ).status_code
        == 401
    )
    assert (
        agent.post(
            "/api/v1/agent/network/path-status",
            json={
                "authentication": invalid_auth.model_dump(mode="json"),
                "status": path_status.model_dump(mode="json"),
            },
        ).status_code
        == 401
    )
    assert (
        agent.post(
            "/api/v1/agent/network/acknowledgements",
            json={
                "authentication": auth.model_dump(mode="json"),
                "acknowledgement": acknowledgement.model_copy(
                    update={"node_id": NodeId.new()}
                ).model_dump(mode="json"),
            },
        ).status_code
        == 403
    )

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
