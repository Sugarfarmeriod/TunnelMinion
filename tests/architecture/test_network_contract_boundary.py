"""受管网络契约的秘密字段、预算和 Provider 架构边界。"""

from __future__ import annotations

import inspect

from pydantic import BaseModel
from tests.network.factories import observation

import tunnelminion.network.contracts as network_contracts
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.network.provider import NetworkProvider
from tunnelminion.network.state import ManagedPathRecord


def _as_provider(value: NetworkProvider) -> NetworkProvider:
    return value


def test_network_models_forbid_unknown_fields_and_secret_names() -> None:
    schemas: list[str] = []
    for _, model in inspect.getmembers(network_contracts, inspect.isclass):
        if model.__module__ == network_contracts.__name__ and issubclass(model, BaseModel):
            schema = model.model_json_schema()
            schemas.append(str(schema).lower())
            assert schema.get("additionalProperties") is False

    combined = " ".join(schemas)
    assert "private_key" not in combined
    assert "preshared" not in combined
    assert "shell" not in combined
    assert "command" not in combined


def test_fake_implements_provider_protocol_and_state_module_is_imported() -> None:
    provider = InMemoryNetworkProvider(observation())

    assert _as_provider(provider) is provider
    assert ManagedPathRecord.__module__ == "tunnelminion.network.state"
