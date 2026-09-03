"""模型配置、秘密存储和降级行为测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue

from tunnelminion.model.configuration import (
    MODEL_API_KEY_NAME,
    FileModelConfigurationRepository,
    ModelConfigurationInput,
    ModelConfigurationService,
    default_provider_factory,
)
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from tunnelminion.model.secrets import SecretStoreError


class MemoryRepository:
    """测试使用的非秘密配置仓库。"""

    def __init__(self) -> None:
        self.value: OpenAICompatibleConfig | None = None

    def load(self) -> OpenAICompatibleConfig | None:
        return self.value

    def save(self, config: OpenAICompatibleConfig) -> None:
        self.value = config

    def delete(self) -> None:
        self.value = None


class MemorySecrets:
    """测试使用的秘密存储。"""

    def __init__(self, value: str | None = None) -> None:
        self.values = {MODEL_API_KEY_NAME: value} if value is not None else {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class UnavailableSecrets(MemorySecrets):
    """模拟 macOS 无图形会话暂时无法读取 Keychain。"""

    def get(self, name: str) -> str | None:
        del name
        raise SecretStoreError("Keychain 当前不可访问")


class ValidationProvider:
    """按指定能力与响应执行验证的假 Provider。"""

    def __init__(
        self,
        *,
        capabilities: ModelCapabilities | None = None,
        tool_name: str | None = "report_capability",
        structured: JsonValue | None = None,
        error: ProviderError | None = None,
    ) -> None:
        self._capabilities = capabilities or ModelCapabilities(
            tool_calls=True, structured_output=True
        )
        self._tool_name = tool_name
        self._structured: JsonValue = (
            structured if structured is not None else cast(JsonValue, {"status": "ok"})
        )
        self._error = error
        self.calls = 0

    @property
    def capabilities(self) -> ModelCapabilities:
        return self._capabilities

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del cancellation
        self.calls += 1
        if self._error is not None:
            raise self._error
        if request.tools:
            calls = (
                ToolCall(call_id="call", name=self._tool_name, arguments={})
                if self._tool_name is not None
                else None
            )
            return ModelResponse(tool_calls=(calls,) if calls is not None else ())
        return ModelResponse(structured_output=self._structured)


def input_config(api_key: str | None = None) -> ModelConfigurationInput:
    """返回标准用户配置。"""
    return ModelConfigurationInput(
        endpoint="http://10.77.0.1:8082/v1",
        model="/Volumes/DarkAI/model.gguf",
        timeout_seconds=10,
        api_key=api_key,
    )


def service_with(
    provider: ModelProvider,
    repository: MemoryRepository | None = None,
    secrets: MemorySecrets | None = None,
) -> tuple[ModelConfigurationService, MemoryRepository, MemorySecrets]:
    """组装可观察依赖的配置服务。"""
    repository = repository or MemoryRepository()
    secrets = secrets or MemorySecrets()
    service = ModelConfigurationService(repository, secrets, lambda _config, _key: provider)
    return service, repository, secrets


def test_file_repository_round_trip_and_delete(tmp_path: Path) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "nested" / "model.json")
    assert repository.load() is None
    expected = input_config().provider_config()
    repository.save(expected)
    assert repository.load() == expected
    assert "api_key" not in (tmp_path / "nested" / "model.json").read_text(encoding="utf-8")
    repository.delete()
    repository.delete()
    assert repository.load() is None


def test_default_factory_creates_compatible_provider() -> None:
    provider = default_provider_factory(input_config().provider_config(), None)
    assert isinstance(provider, OpenAICompatibleProvider)


def test_create_provider_handles_configuration_disappearing_after_gate() -> None:
    """配置在门卫与创建之间消失时仍返回稳定错误。"""

    class VanishingRepository(MemoryRepository):
        def __init__(self) -> None:
            super().__init__()
            self.value = input_config().provider_config()
            self.loads = 0

        def load(self) -> OpenAICompatibleConfig | None:
            self.loads += 1
            return self.value if self.loads == 1 else None

    service = ModelConfigurationService(
        VanishingRepository(),
        MemorySecrets(),
        lambda _config, _key: ValidationProvider(),
    )

    with pytest.raises(ProviderError) as caught:
        service.create_provider()
    assert caught.value.code == ProviderErrorCode.MODEL_NOT_FOUND


def test_configure_valid_provider_and_never_exposes_secret() -> None:
    provider = ValidationProvider()
    service, repository, secrets = service_with(provider)
    view = asyncio.run(service.configure(input_config("top-secret")))
    assert view.status == "available"
    assert view.api_key_configured
    assert "top-secret" not in view.model_dump_json()
    assert repository.value is not None
    assert secrets.get(MODEL_API_KEY_NAME) == "top-secret"
    assert provider.calls == 2
    service.require_available()
    assert service.create_provider() is provider


def test_no_key_provider_works_when_keychain_is_unavailable() -> None:
    """没有 API Key 的本地模型不应被无关的 Keychain 会话阻断。"""
    provider = ValidationProvider()
    service, repository, _ = service_with(provider, secrets=UnavailableSecrets())

    view = asyncio.run(service.configure(input_config()))

    assert view.status == "available"
    assert not view.api_key_configured
    assert repository.value == input_config().provider_config()
    assert service.create_provider() is provider


def test_configure_retains_or_explicitly_removes_existing_key() -> None:
    service, _, secrets = service_with(ValidationProvider(), secrets=MemorySecrets("old-key"))
    retained = asyncio.run(service.configure(input_config()))
    assert retained.api_key_configured
    removed = asyncio.run(service.configure(input_config("")))
    assert not removed.api_key_configured
    assert secrets.get(MODEL_API_KEY_NAME) is None


@pytest.mark.parametrize(
    "provider",
    [
        ValidationProvider(
            capabilities=ModelCapabilities(tool_calls=False, structured_output=True)
        ),
        ValidationProvider(tool_name=None),
        ValidationProvider(tool_name="wrong"),
        ValidationProvider(structured=cast(JsonValue, {"status": "bad"})),
    ],
)
def test_rejects_incompatible_provider_without_saving(provider: ModelProvider) -> None:
    service, repository, _ = service_with(provider)
    with pytest.raises(ProviderError) as caught:
        asyncio.run(service.configure(input_config()))
    assert caught.value.code == ProviderErrorCode.CAPABILITY_INCOMPATIBLE
    assert repository.value is None


def test_validate_tracks_failure_and_recovery() -> None:
    repository = MemoryRepository()
    repository.value = input_config().provider_config()
    failing = ValidationProvider(
        error=ProviderError(ProviderErrorCode.TIMEOUT, "模型调用超时", retryable=True)
    )
    current: list[ModelProvider] = [failing]
    service = ModelConfigurationService(repository, MemorySecrets(), lambda _c, _k: current[0])
    unavailable = asyncio.run(service.validate())
    assert unavailable.status == "unavailable"
    assert unavailable.error_code == ProviderErrorCode.TIMEOUT
    with pytest.raises(ProviderError, match="超时"):
        service.require_available()

    recovered = ValidationProvider()
    current[0] = recovered
    available = asyncio.run(service.validate())
    assert available.status == "available"


def test_unconfigured_and_delete_are_safe() -> None:
    service, repository, secrets = service_with(ValidationProvider(), secrets=MemorySecrets("key"))
    assert service.view().status == "unconfigured"
    with pytest.raises(ProviderError) as validate_error:
        asyncio.run(service.validate())
    assert validate_error.value.code == ProviderErrorCode.MODEL_NOT_FOUND
    with pytest.raises(ProviderError) as run_error:
        service.require_available()
    assert run_error.value.code == ProviderErrorCode.MODEL_NOT_FOUND
    service.delete()
    assert repository.value is None
    assert secrets.get(MODEL_API_KEY_NAME) is None


def test_unconfigured_view_does_not_read_secret_store() -> None:
    class RejectingSecrets(MemorySecrets):
        def get(self, name: str) -> str | None:
            raise AssertionError(f"未配置模型时不得读取秘密：{name}")

    service = ModelConfigurationService(MemoryRepository(), RejectingSecrets())

    assert service.view().status == "unconfigured"
