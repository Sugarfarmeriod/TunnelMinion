"""本地模型配置 API 与降级隔离测试。"""

from __future__ import annotations

from typing import Protocol, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.model.api import create_local_app
from tunnelminion.model.configuration import BorrowedModelConfig, ModelConfigurationService
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig


class ApiClient(Protocol):
    """屏蔽 Starlette 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...

    def post(self, url: str) -> httpx.Response: ...

    def put(self, url: str, *, json: object) -> httpx.Response: ...

    def delete(self, url: str) -> httpx.Response: ...


class Repository:
    """API 测试使用的内存配置仓库。"""

    def __init__(self) -> None:
        self.value: OpenAICompatibleConfig | None = None
        self.saved: tuple[OpenAICompatibleConfig, ...] = ()
        self.borrowed: BorrowedModelConfig | None = None

    def load(self) -> OpenAICompatibleConfig | None:
        return self.value

    def save(self, config: OpenAICompatibleConfig) -> None:
        self.value = config
        self.borrowed = None
        self.saved = (
            config,
            *(
                item
                for item in self.saved
                if (item.endpoint, item.model) != (config.endpoint, config.model)
            ),
        )

    def profiles(self) -> tuple[OpenAICompatibleConfig, ...]:
        return self.saved

    def load_borrowed(self) -> BorrowedModelConfig | None:
        return self.borrowed

    def save_borrowed(self, config: BorrowedModelConfig) -> None:
        self.borrowed = config
        self.value = None

    def delete(self) -> None:
        self.value = None
        self.saved = ()
        self.borrowed = None


class Secrets:
    """API 测试使用的内存秘密存储。"""

    def __init__(self) -> None:
        self.value: str | None = None

    def get(self, name: str) -> str | None:
        del name
        return self.value

    def set(self, name: str, value: str) -> None:
        del name
        self.value = value

    def delete(self, name: str) -> None:
        del name
        self.value = None


class Provider:
    """返回能力验证所需固定结构的 Provider。"""

    def __init__(self) -> None:
        self.error: ProviderError | None = None

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        if self.error is not None:
            raise self.error
        if request.tools:
            return ModelResponse(
                tool_calls=(ToolCall(call_id="call", name="report_capability", arguments={}),)
            )
        return ModelResponse(structured_output={"status": "ok"})


def test_model_config_crud_validation_and_degradation() -> None:
    repository = Repository()
    secrets = Secrets()
    provider = Provider()
    service = ModelConfigurationService(repository, secrets, lambda _c, _k: provider)
    client = cast(ApiClient, TestClient(create_local_app(service)))

    assert client.get("/api/model-config").json()["status"] == "unconfigured"
    assert client.get("/api/resources/health").json() == {"status": "available"}
    unavailable = client.post("/api/ai/runs/availability")
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["code"] == "model_not_found"
    assert client.post("/api/model-config/validate").status_code == 409

    saved = client.put(
        "/api/model-config",
        json={
            "endpoint": "http://10.77.0.1:8082/v1",
            "model": "/Volumes/DarkAI/model.gguf",
            "timeout_seconds": 10,
            "api_key": "secret-value",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["api_key_configured"] is True
    assert saved.json()["profiles"] == [
        {
            "endpoint": "http://10.77.0.1:8082/v1",
            "model": "/Volumes/DarkAI/model.gguf",
            "timeout_seconds": 10.0,
            "api_key_configured": True,
        }
    ]
    assert "secret-value" not in saved.text
    assert client.post("/api/model-config/validate").json()["status"] == "available"
    assert client.post("/api/ai/runs/availability").json() == {"available": True}

    deleted = client.delete("/api/model-config")
    assert deleted.status_code == 204
    assert repository.value is None
    assert secrets.value is None


def test_api_returns_diagnostic_validation_error() -> None:
    repository = Repository()
    secrets = Secrets()
    provider = Provider()
    provider.error = ProviderError(ProviderErrorCode.AUTHENTICATION_FAILED, "模型认证失败")
    service = ModelConfigurationService(repository, secrets, lambda _c, _k: provider)
    client = cast(ApiClient, TestClient(create_local_app(service)))
    response = client.put(
        "/api/model-config",
        json={"endpoint": "http://model.test/v1", "model": "qwen"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "authentication_failed",
        "message": "模型认证失败",
        "retryable": False,
    }


def test_borrowed_model_api_validates_peer_and_preserves_state_on_error() -> None:
    peer = NodeId.new()
    provider = Provider()
    repository = Repository()

    def factory(node_id: NodeId) -> Provider:
        if node_id != peer:
            raise KeyError("gateway_model_peer_not_found")
        return provider

    service = ModelConfigurationService(repository, Secrets(), borrowed_provider_factory=factory)
    client = cast(ApiClient, TestClient(create_local_app(service)))
    borrowed = client.put("/api/model/borrowed", json={"peer_node_id": str(peer)})
    assert borrowed.status_code == 200
    assert borrowed.json()["borrowed_from"] == str(peer)
    assert borrowed.json()["endpoint"] is None and borrowed.json()["model"] is None
    assert borrowed.json()["status"] == "available"
    assert client.post("/api/ai/runs/availability").status_code == 200
    missing = client.put("/api/model/borrowed", json={"peer_node_id": str(NodeId.new())})
    assert missing.status_code == 404
    assert missing.json()["detail"] == "gateway_model_peer_not_found"
    provider.error = ProviderError(ProviderErrorCode.QUOTA_EXCEEDED, "今天借用的额度已用完")
    rejected = client.put("/api/model/borrowed", json={"peer_node_id": str(peer)})
    assert rejected.status_code == 422
    assert rejected.json()["detail"] == {
        "code": "quota_exceeded",
        "message": "今天借用的额度已用完",
        "retryable": False,
    }
    assert client.get("/api/model-config").json() == borrowed.json()
    assert client.delete("/api/model-config").status_code == 204
    assert client.get("/api/model-config").json()["borrowed_from"] is None


@pytest.mark.parametrize(
    "payload",
    [{}, {"peer_node_id": "invalid"}, {"peer_node_id": str(NodeId.new()), "api_key": "secret"}],
)
def test_borrowed_model_api_rejects_invalid_input(payload: dict[str, str]) -> None:
    service = ModelConfigurationService(Repository(), Secrets())
    client = cast(ApiClient, TestClient(create_local_app(service)))
    assert client.put("/api/model/borrowed", json=payload).status_code == 422
