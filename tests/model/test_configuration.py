"""模型配置、秘密存储和降级行为测试。"""

from __future__ import annotations

import asyncio
import json
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
    model_api_key_name,
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
        self.saved: tuple[OpenAICompatibleConfig, ...] = ()

    def load(self) -> OpenAICompatibleConfig | None:
        return self.value

    def save(self, config: OpenAICompatibleConfig) -> None:
        self.value = config
        self.saved = (
            config,
            *(
                item
                for item in self.saved
                if (item.endpoint, item.model) != (config.endpoint, config.model)
            ),
        )

    def profiles(self) -> tuple[OpenAICompatibleConfig, ...]:
        if self.value is not None and self.value not in self.saved:
            return (self.value, *self.saved)
        return self.saved

    def delete(self) -> None:
        self.value = None
        self.saved = ()


class MemorySecrets:
    """测试使用的秘密存储。"""

    def __init__(self, value: str | None = None, *, name: str = MODEL_API_KEY_NAME) -> None:
        self.values = {name: value} if value is not None else {}
        self.reads: list[str] = []

    def get(self, name: str) -> str | None:
        self.reads.append(name)
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


def input_config(
    api_key: str | None = None,
    *,
    endpoint: str = "http://10.77.0.1:8082/v1",
    model: str = "/Volumes/DarkAI/model.gguf",
) -> ModelConfigurationInput:
    """返回标准用户配置。"""
    return ModelConfigurationInput(
        endpoint=endpoint,
        model=model,
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
    assert repository.profiles() == (expected,)
    assert "api_key" not in (tmp_path / "nested" / "model.json").read_text(encoding="utf-8")
    repository.delete()
    repository.delete()
    assert repository.load() is None


def test_file_repository_reads_legacy_config_and_upgrades_on_save(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    legacy = input_config(model="legacy").provider_config()
    path.write_text(legacy.model_dump_json(), encoding="utf-8")
    repository = FileModelConfigurationRepository(path)

    assert repository.load() == legacy
    assert repository.profiles() == (legacy,)

    current = input_config(
        endpoint="https://api.deepseek.com/v1", model="deepseek-chat"
    ).provider_config()
    repository.save(current)

    assert repository.load() == current
    assert repository.profiles() == (current, legacy)
    stored = path.read_text(encoding="utf-8")
    assert '"version": 2' in stored
    assert "api_key" not in stored


@pytest.mark.parametrize(
    ("profiles", "error"),
    [
        (["active", "active"], "重复"),
        (["other"], "active 模型配置不在档案中"),
    ],
)
def test_file_repository_rejects_inconsistent_profile_state(
    tmp_path: Path, profiles: list[str], error: str
) -> None:
    path = tmp_path / "model.json"
    configs = {
        name: input_config(model=name).provider_config().model_dump(mode="json")
        for name in set([*profiles, "active"])
    }
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "active": configs["active"],
                "profiles": [configs[name] for name in profiles],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=error):
        FileModelConfigurationRepository(path).profiles()


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


def test_create_provider_reads_only_active_endpoint_secret() -> None:
    repository = MemoryRepository()
    inactive = input_config(
        endpoint="https://api.deepseek.com/v1",
        model="deepseek-chat",
    ).provider_config()
    active = input_config(
        endpoint="http://127.0.0.1:8080/v1",
        model="qwen-local",
    ).provider_config()
    repository.save(inactive)
    repository.save(active)
    secrets = MemorySecrets("deepseek-secret", name=model_api_key_name(inactive.endpoint))
    secrets.set(model_api_key_name(active.endpoint), "qwen-secret")
    received: list[str | None] = []
    service = ModelConfigurationService(
        repository,
        secrets,
        lambda _config, key: received.append(key) or ValidationProvider(),
    )

    service.create_provider()

    assert secrets.reads == [model_api_key_name(active.endpoint)]
    assert received == ["qwen-secret"]


def test_configure_valid_provider_and_never_exposes_secret() -> None:
    provider = ValidationProvider()
    service, repository, secrets = service_with(provider)
    view = asyncio.run(service.configure(input_config("top-secret")))
    assert view.status == "available"
    assert view.api_key_configured
    assert "top-secret" not in view.model_dump_json()
    assert repository.value is not None
    assert secrets.get(model_api_key_name(input_config().endpoint)) == "top-secret"
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
    secret_name = model_api_key_name(input_config().endpoint)
    service, _, secrets = service_with(
        ValidationProvider(), secrets=MemorySecrets("old-key", name=secret_name)
    )
    retained = asyncio.run(service.configure(input_config()))
    assert retained.api_key_configured
    removed = asyncio.run(service.configure(input_config("")))
    assert not removed.api_key_configured
    assert secrets.get(secret_name) is None


def test_switching_profiles_never_reuses_another_endpoint_key() -> None:
    repository = MemoryRepository()
    secrets = MemorySecrets()
    calls: list[tuple[str, str | None]] = []

    def factory(config: OpenAICompatibleConfig, api_key: str | None) -> ModelProvider:
        calls.append((config.endpoint, api_key))
        return ValidationProvider()

    service = ModelConfigurationService(repository, secrets, factory)
    deepseek = input_config(
        "deepseek-secret",
        endpoint="https://api.deepseek.com/v1",
        model="deepseek-chat",
    )
    qwen = input_config(endpoint="http://127.0.0.1:8080/v1", model="qwen-local")

    asyncio.run(service.configure(deepseek))
    asyncio.run(service.configure(qwen))
    qwen_view = service.view()

    assert calls[-1] == ("http://127.0.0.1:8080/v1", None)
    assert [(item.endpoint, item.model) for item in qwen_view.profiles] == [
        ("http://127.0.0.1:8080/v1", "qwen-local"),
        ("https://api.deepseek.com/v1", "deepseek-chat"),
    ]
    assert [item.api_key_configured for item in qwen_view.profiles] == [False, True]

    asyncio.run(service.configure(deepseek.model_copy(update={"api_key": None})))

    assert calls[-1] == ("https://api.deepseek.com/v1", "deepseek-secret")
    assert service.view().model == "deepseek-chat"


def test_legacy_unscoped_key_is_not_sent_to_any_endpoint() -> None:
    repository = MemoryRepository()
    repository.value = input_config(model="legacy").provider_config()
    secrets = MemorySecrets("ambiguous-secret")
    calls: list[str | None] = []

    def factory(_config: OpenAICompatibleConfig, api_key: str | None) -> ModelProvider:
        calls.append(api_key)
        return ValidationProvider()

    service = ModelConfigurationService(repository, secrets, factory)

    assert not service.view().api_key_configured
    asyncio.run(service.configure(input_config(model="legacy")))
    assert calls == [None]


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
    repository = MemoryRepository()
    config = input_config().provider_config()
    repository.save(config)
    secrets = MemorySecrets("legacy-key")
    secrets.set(model_api_key_name(config.endpoint), "scoped-key")
    service = ModelConfigurationService(repository, secrets, lambda _c, _k: ValidationProvider())
    service.delete()
    assert repository.value is None
    assert secrets.get(MODEL_API_KEY_NAME) is None
    assert secrets.get(model_api_key_name(config.endpoint)) is None

    assert service.view().status == "unconfigured"
    with pytest.raises(ProviderError) as validate_error:
        asyncio.run(service.validate())
    assert validate_error.value.code == ProviderErrorCode.MODEL_NOT_FOUND
    with pytest.raises(ProviderError) as run_error:
        service.require_available()
    assert run_error.value.code == ProviderErrorCode.MODEL_NOT_FOUND


def test_unconfigured_view_does_not_read_secret_store() -> None:
    class RejectingSecrets(MemorySecrets):
        def get(self, name: str) -> str | None:
            raise AssertionError(f"未配置模型时不得读取秘密：{name}")

    service = ModelConfigurationService(MemoryRepository(), RejectingSecrets())

    assert service.view().status == "unconfigured"
