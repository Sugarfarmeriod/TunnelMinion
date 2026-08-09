"""阶段一受管路径模块的无模型、无应用和授权只读边界。"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import NoReturn, Protocol, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from tunnelminion.app import build_windows_application
from tunnelminion.model.secrets import KeyringSecretStore
from tunnelminion.network import managed_path_runtime
from tunnelminion.network.governance import NetworkOperationPolicy
from tunnelminion.network.managed_path_runtime import (
    NetworkAuthorizationReader,
)
from tunnelminion.platforms.windows.network_provider import WindowsNetworkProvider


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
    ) -> httpx.Response: ...

    def post(self, url: str) -> httpx.Response: ...


def test_phase_one_module_has_no_consumer_or_platform_dependencies() -> None:
    source = inspect.getsource(managed_path_runtime)
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = (
        "tunnelminion.agent",
        "tunnelminion.app",
        "tunnelminion.coordinator",
        "tunnelminion.gateway",
        "tunnelminion.macos_app",
        "tunnelminion.memory",
        "tunnelminion.model",
        "tunnelminion.platforms",
        "tunnelminion.web",
    )
    assert not any(name.startswith(prefix) for name in imported for prefix in forbidden)


def test_authorization_port_has_only_a_read_dependency_surface() -> None:
    reader_methods = {
        name
        for name, value in vars(NetworkAuthorizationReader).items()
        if callable(value) and not name.startswith("_")
    }
    assert reader_methods == {"list_grants"}


def test_phase_one_import_graph_only_reaches_network_and_domain_layers() -> None:
    source = inspect.getsource(managed_path_runtime)
    tree = ast.parse(source)
    project_imports = {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("tunnelminion")
    }
    assert project_imports
    assert all(
        name.startswith(("tunnelminion.domain", "tunnelminion.network")) for name in project_imports
    )


def test_real_local_consumers_cannot_create_authorization_or_apply_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """真实启动与只读消费路径没有 L3 授权 writer 或 Provider 写能力。"""
    writes: list[str] = []

    def forbidden_approve(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        writes.append("authorization_approve")
        raise AssertionError("本机消费路径不得创建 L3 授权")

    def forbidden_revoke(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        writes.append("authorization_revoke")
        raise AssertionError("本机消费路径不得撤销或扩大 L3 授权")

    async def forbidden_apply(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        writes.append("provider_apply")
        raise AssertionError("本机消费路径不得调用 Provider apply")

    def no_secret(_self: KeyringSecretStore, _name: str) -> None:
        return None

    monkeypatch.setattr(NetworkOperationPolicy, "approve", forbidden_approve)
    monkeypatch.setattr(NetworkOperationPolicy, "revoke", forbidden_revoke)
    monkeypatch.setattr(WindowsNetworkProvider, "apply", forbidden_apply)
    monkeypatch.setattr(KeyringSecretStore, "get", no_secret)

    bundle = build_windows_application(tmp_path / "local-app")
    with TestClient(bundle.app) as raw_client:
        client = cast(ApiClient, raw_client)
        assert client.get("/api/model-config").status_code == 200
        assert client.post("/api/threads").status_code == 200
        assert client.get("/api/threads").status_code == 200
        assert (
            client.get(
                "/api/memories",
                params={
                    "user": "local-user",
                    "network": "local-network",
                    "node_id": str(bundle.node_id),
                },
            ).status_code
            == 200
        )
        assert client.get("/api/resources/listeners").status_code == 200
        assert client.get("/api/resources/managed-node").status_code == 200
        assert client.get("/api/resources/coordinator").status_code == 200
        assert client.get("/api/resources/network-path").status_code == 200
        assert client.get("/resources").status_code == 200

    payload = bundle.managed_node.resource_payload()
    assert "services" in payload
    assert writes == []
