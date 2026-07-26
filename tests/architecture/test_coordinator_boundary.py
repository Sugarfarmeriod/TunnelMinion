"""用可执行架构约束守住 Coordinator 控制面与数据面分离。"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from pydantic import BaseModel

import tunnelminion.coordinator.contracts as contracts

FORBIDDEN_FIELD_FRAGMENTS = {
    "authorization_header",
    "conversation",
    "environment_variables",
    "gateway_token",
    "memory",
    "model_api_key",
    "model_key",
    "operation_body",
    "operation_plan",
    "operation_result",
    "process_arguments",
    "remote_tool_body",
    "tool_arguments",
    "tool_body",
    "tool_output",
    "tool_result",
    "wireguard_private_key",
}
FORBIDDEN_IMPORT_PREFIXES = (
    "tunnelminion.agent",
    "tunnelminion.memory",
    "tunnelminion.model",
    "tunnelminion.operation",
    "tunnelminion.tools",
)


def coordinator_models() -> tuple[type[BaseModel], ...]:
    return tuple(
        value
        for value in vars(contracts).values()
        if inspect.isclass(value)
        and issubclass(value, BaseModel)
        and value.__module__ == contracts.__name__
    )


def test_coordinator_contracts_have_no_data_plane_or_private_fields() -> None:
    fields = {field_name for model in coordinator_models() for field_name in model.model_fields}

    assert fields.isdisjoint(FORBIDDEN_FIELD_FRAGMENTS)
    assert all(model.model_config.get("extra") == "forbid" for model in coordinator_models())


def test_coordinator_contracts_do_not_import_data_plane_implementations() -> None:
    source_path = Path(contracts.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )

    assert not any(
        module.startswith(prefix) for module in imported for prefix in FORBIDDEN_IMPORT_PREFIXES
    )
