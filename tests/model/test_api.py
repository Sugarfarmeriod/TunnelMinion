"""本地模型配置 API 与降级隔离测试。"""

from __future__ import annotations

from typing import Protocol, cast

import httpx
from fastapi.testclient import TestClient

from tunnelminion.model.api import create_local_app
from tunnelminion.model.configuration import ModelConfigurationService
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

    def load(self) -> OpenAICompatibleConfig | None:
        return self.value

    def save(self, config: OpenAICompatibleConfig) -> None:
        self.value = config

    def delete(self) -> None:
        self.value = None


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
