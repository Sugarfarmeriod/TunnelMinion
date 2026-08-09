"""阶段一受管路径模块的无模型、无应用和授权只读边界。"""

from __future__ import annotations

import ast
import inspect

from tunnelminion.network import managed_path_runtime
from tunnelminion.network.managed_path_runtime import (
    ManagedPathPhaseOneLifecycle,
    NetworkAuthorizationReader,
)


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


def test_authorization_port_and_phase_one_lifecycle_have_no_write_surface() -> None:
    reader_methods = {
        name
        for name, value in vars(NetworkAuthorizationReader).items()
        if callable(value) and not name.startswith("_")
    }
    assert reader_methods == {"list_grants"}
    lifecycle_source = inspect.getsource(ManagedPathPhaseOneLifecycle)
    assert ".apply(" not in lifecycle_source
    assert ".approve(" not in lifecycle_source
    assert ".revoke(" not in lifecycle_source
