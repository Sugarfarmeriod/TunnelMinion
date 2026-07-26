"""Coordinator 双应用工厂与监听配置边界测试。"""

from pathlib import Path
from typing import Protocol, cast

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tunnelminion.coordinator.app import (
    CoordinatorAdminBindConfig,
    CoordinatorAgentBindConfig,
    CoordinatorApplicationConfig,
    build_coordinator_applications,
)


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...


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
