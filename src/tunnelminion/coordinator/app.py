"""Coordinator 独立 Agent API 与环回管理员 API 的应用边界。"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tunnelminion.coordinator.contracts import (
    AccessAssertionRequest,
    AccessAssertionResponse,
    AuthenticatedHeartbeat,
    HeartbeatResponse,
    NodeRegistrationResponse,
    NodeRevocationRequest,
    RegisteredNodeView,
    VerificationKeySet,
)
from tunnelminion.coordinator.identity import AssertionService
from tunnelminion.coordinator.registry import CoordinatorRegistryService, RegistryError
from tunnelminion.domain.identifiers import NetworkId, NodeId


class CoordinatorAgentBindConfig(BaseModel):
    """必须显式指定的 WireGuard 私网 Agent API 监听配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def validate_wireguard_host(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if (
            not address.is_private
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("Coordinator Agent API 只能绑定明确的 WireGuard 私网地址")
        return value


class CoordinatorAdminBindConfig(BaseModel):
    """默认且只允许环回地址的管理员 API 监听配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "127.0.0.1"
    port: int = Field(default=8791, ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def validate_loopback_host(cls, value: str) -> str:
        if not ipaddress.ip_address(value).is_loopback:
            raise ValueError("Coordinator 管理员 API 只能绑定环回地址")
        return value


class CoordinatorApplicationConfig(BaseModel):
    """不含秘密的 Coordinator 双应用配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data_path: Path
    agent_bind: CoordinatorAgentBindConfig
    admin_bind: CoordinatorAdminBindConfig = Field(default_factory=CoordinatorAdminBindConfig)


@dataclass(frozen=True)
class CoordinatorApplications:
    """由部署层分别启动的两个 FastAPI 应用。"""

    agent_app: FastAPI
    admin_app: FastAPI
    config: CoordinatorApplicationConfig


def build_coordinator_applications(
    config: CoordinatorApplicationConfig,
    *,
    registry: CoordinatorRegistryService | None = None,
    assertions: AssertionService | None = None,
) -> CoordinatorApplications:
    """建立隔离应用工厂；本函数不启动监听器。"""
    agent_app = FastAPI(
        title="TunnelMinion Coordinator Agent API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    admin_app = FastAPI(
        title="TunnelMinion Coordinator Admin API",
        docs_url="/api/docs",
        redoc_url=None,
    )

    async def agent_health() -> dict[str, str]:
        return {"status": "available", "boundary": "agent"}

    async def admin_health() -> dict[str, str]:
        return {"status": "available", "boundary": "admin"}

    agent_app.add_api_route("/api/v1/agent/health", agent_health, methods=["GET"])
    admin_app.add_api_route("/api/v1/admin/health", admin_health, methods=["GET"])

    if registry is not None:

        async def heartbeat(payload: AuthenticatedHeartbeat) -> HeartbeatResponse:
            try:
                return registry.heartbeat(payload.authentication, payload.heartbeat)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def list_nodes(network_id: str) -> tuple[RegisteredNodeView, ...]:
            return registry.list_nodes(NetworkId(network_id))

        async def rotate_refresh(
            network_id: str,
            node_id: str,
        ) -> NodeRegistrationResponse:
            try:
                return registry.admin_rotate_refresh(
                    NetworkId(network_id),
                    NodeId(node_id),
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def revoke_node(
            network_id: str,
            node_id: str,
            payload: NodeRevocationRequest,
        ) -> dict[str, str]:
            try:
                registry.revoke_node(
                    NetworkId(network_id),
                    NodeId(node_id),
                    reason=payload.reason,
                )
            except RegistryError as exc:
                raise _http_error(exc) from exc
            return {"status": "revoked"}

        async def restore_node(
            network_id: str,
            node_id: str,
        ) -> NodeRegistrationResponse:
            try:
                return registry.restore_node(NetworkId(network_id), NodeId(node_id))
            except RegistryError as exc:
                raise _http_error(exc) from exc

        agent_app.add_api_route(
            "/api/v1/agent/heartbeat",
            heartbeat,
            methods=["POST"],
            response_model=HeartbeatResponse,
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes",
            list_nodes,
            methods=["GET"],
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/rotate-refresh",
            rotate_refresh,
            methods=["POST"],
            response_model=NodeRegistrationResponse,
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/revoke",
            revoke_node,
            methods=["POST"],
        )
        admin_app.add_api_route(
            "/api/v1/admin/networks/{network_id}/nodes/{node_id}/restore",
            restore_node,
            methods=["POST"],
            response_model=NodeRegistrationResponse,
        )

    if assertions is not None:

        async def issue_assertion(
            payload: AccessAssertionRequest,
        ) -> AccessAssertionResponse:
            try:
                return assertions.issue(payload)
            except RegistryError as exc:
                raise _http_error(exc) from exc

        async def verification_keys() -> VerificationKeySet:
            return assertions.verification_keys()

        agent_app.add_api_route(
            "/api/v1/agent/assertions",
            issue_assertion,
            methods=["POST"],
            response_model=AccessAssertionResponse,
        )
        agent_app.add_api_route(
            "/api/v1/agent/verification-keys",
            verification_keys,
            methods=["GET"],
            response_model=VerificationKeySet,
        )
    return CoordinatorApplications(agent_app, admin_app, config)


def _http_error(error: RegistryError) -> HTTPException:
    status_by_code = {
        "unauthenticated": 401,
        "forbidden": 403,
        "conflict": 409,
        "version_incompatible": 426,
        "rate_limited": 429,
    }
    status_code = status_by_code.get(error.code.value, 400)
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code.value, "message": str(error)},
    )
