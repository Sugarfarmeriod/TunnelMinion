"""模型配置、秘密存储和降级行为测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

import httpx
import pytest
from pydantic import JsonValue, ValidationError

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.model.configuration import (
    MODEL_API_KEY_NAME,
    BorrowedModelConfig,
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
from tunnelminion.model.secrets import (
    KEYCHAIN_APPROVAL_HINT,
    SecretStoreApprovalPendingError,
    SecretStoreError,
)


class MemoryRepository:
    """测试使用的非秘密配置仓库。"""

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
        if self.value is not None and self.value not in self.saved:
            return (self.value, *self.saved)
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


@pytest.mark.parametrize("disable_thinking", [False, True])
def test_file_repository_round_trip_and_delete(tmp_path: Path, disable_thinking: bool) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "nested" / "model.json")
    assert repository.load() is None
    expected = (
        input_config().provider_config().model_copy(update={"disable_thinking": disable_thinking})
    )
    repository.save(expected)
    assert repository.load() == expected
    assert repository.profiles() == (expected,)
    stored = json.loads((tmp_path / "nested" / "model.json").read_text(encoding="utf-8"))
    assert stored["active"]["disable_thinking"] is disable_thinking
    assert stored["profiles"][0]["disable_thinking"] is disable_thinking
    assert "api_key" not in (tmp_path / "nested" / "model.json").read_text(encoding="utf-8")
    repository.delete()
    repository.delete()
    assert repository.load() is None


def test_file_repository_reads_legacy_config_and_upgrades_on_save(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    legacy = input_config(model="legacy").provider_config()
    path.write_text(legacy.model_dump_json(exclude={"disable_thinking"}), encoding="utf-8")
    repository = FileModelConfigurationRepository(path)

    assert repository.load() == legacy
    assert repository.profiles() == (legacy,)
    assert not legacy.disable_thinking

    current = input_config(
        endpoint="https://api.deepseek.com/v1", model="deepseek-chat"
    ).provider_config()
    repository.save(current)

    assert repository.load() == current
    assert repository.profiles() == (current, legacy)
    stored = path.read_text(encoding="utf-8")
    assert '"version": 3' in stored
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


@pytest.mark.parametrize(
    ("content", "error_code"),
    [
        ('```json\n{"status": "ok"}\n```', None),
        ('```json\n{"status": "bad"}\n```', ProviderErrorCode.CAPABILITY_INCOMPATIBLE),
        ('说明\n```json\n{"status": "ok"}\n```', ProviderErrorCode.INVALID_RESPONSE),
    ],
)
@pytest.mark.parametrize("disable_thinking", [False, True])
def test_configuration_validates_fenced_json_before_saving(
    content: str, error_code: ProviderErrorCode | None, disable_thinking: bool
) -> None:
    calls: list[dict[str, object]] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        payload = json.loads(http_request.content)
        calls.append(payload)
        if payload.get("tools"):
            message = {
                "content": "",
                "tool_calls": [
                    {
                        "id": "capability-check",
                        "function": {
                            "name": "report_capability",
                            "arguments": '{"status":"ok"}',
                        },
                    }
                ],
            }
        else:
            message = {"content": content}
        return httpx.Response(200, json={"choices": [{"message": message}]})

    repository = MemoryRepository()
    secrets = MemorySecrets()
    service = ModelConfigurationService(
        repository,
        secrets,
        lambda config, api_key: OpenAICompatibleProvider(
            config, api_key, transport=httpx.MockTransport(handler)
        ),
    )
    value = input_config().model_copy(update={"disable_thinking": disable_thinking})
    if error_code is None:
        view = asyncio.run(service.configure(value))
        assert view.status == "available"
        assert view.disable_thinking is disable_thinking
        assert view.profiles[0].disable_thinking is disable_thinking
        assert repository.value == value.provider_config()
        assert asyncio.run(service.validate()).status == "available"
    else:
        with pytest.raises(ProviderError) as caught:
            asyncio.run(service.configure(value))
        assert caught.value.code == error_code
        assert repository.value is None
    assert len(calls) == (4 if error_code is None else 2)
    for payload in calls:
        if disable_thinking:
            assert payload["chat_template_kwargs"] == {"enable_thinking": False}
        else:
            assert "chat_template_kwargs" not in payload
    assert secrets.values == {}


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


@pytest.mark.parametrize("version", [2, 3])
def test_file_repository_reads_versioned_state_and_saves_version_three(
    tmp_path: Path, version: int
) -> None:
    path = tmp_path / "model.json"
    config = input_config().provider_config()
    path.write_text(
        json.dumps(
            {
                "version": version,
                "active": config.model_dump(mode="json", exclude={"disable_thinking"}),
                "profiles": [config.model_dump(mode="json", exclude={"disable_thinking"})],
            }
        ),
        encoding="utf-8",
    )
    repository = FileModelConfigurationRepository(path)
    assert repository.load() == config
    assert not config.disable_thinking
    assert repository.load_borrowed() is None
    assert repository.profiles() == (config,)
    borrowed = BorrowedModelConfig(peer_node_id=NodeId.new())
    repository.save_borrowed(borrowed)
    assert repository.load() is None
    assert repository.load_borrowed() == borrowed
    assert repository.profiles() == (config,)
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 3


def test_file_repository_rejects_two_active_model_sources(tmp_path: Path) -> None:
    config = input_config().provider_config().model_dump(mode="json")
    path = tmp_path / "model.json"
    path.write_text(
        json.dumps(
            {
                "version": 3,
                "active": config,
                "profiles": [config],
                "borrowed": {"peer_node_id": str(NodeId.new())},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="不能同时启用"):
        FileModelConfigurationRepository(path).load()


def test_borrow_switches_sources_preserves_profiles_and_tracks_availability(tmp_path: Path) -> None:
    peer = NodeId.new()
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    secrets = MemorySecrets()
    remote = ValidationProvider()
    current: list[ModelProvider] = [remote]

    def factory(node_id: NodeId) -> ModelProvider:
        assert node_id == peer
        return current[0]

    service = ModelConfigurationService(
        repository, secrets, lambda _config, _key: ValidationProvider(), factory
    )
    local = input_config("saved-local-key")
    asyncio.run(service.configure(local))
    view = asyncio.run(service.borrow(peer))
    assert view.borrowed_from == peer
    assert view.status == "available"
    assert view.endpoint is None and view.model is None and view.timeout_seconds is None
    assert not view.api_key_configured
    assert view.profiles[0].api_key_configured
    assert repository.load() is None
    assert repository.load_borrowed() == BorrowedModelConfig(peer_node_id=peer)
    assert remote.calls == 2
    assert service.create_provider() is remote
    # 借来的模型不能再借给别人，否则两台电脑互相借用会成环。
    with pytest.raises(ProviderError, match="不能转借"):
        service.create_lending_provider()
    assert secrets.values == {model_api_key_name(local.endpoint): "saved-local-key"}

    current[0] = ValidationProvider(
        error=ProviderError(
            ProviderErrorCode.BUSY, "对方电脑的模型正忙，请稍后再试", retryable=True
        )
    )
    failed = asyncio.run(service.validate())
    assert failed.borrowed_from == peer and failed.status == "unavailable"
    assert failed.error_code is ProviderErrorCode.BUSY
    with pytest.raises(ProviderError) as caught:
        service.create_provider()
    assert caught.value.retryable
    current[0] = remote
    assert asyncio.run(service.validate()).status == "available"
    assert service.view().error_code is None

    restored = asyncio.run(service.configure(input_config()))
    assert restored.borrowed_from is None
    assert isinstance(service.create_lending_provider(), ValidationProvider)
    assert repository.load_borrowed() is None
    assert repository.load() == local.provider_config()
    asyncio.run(service.borrow(peer))
    service.delete()
    assert repository.load_borrowed() is None
    assert repository.profiles() == ()
    assert secrets.values == {}
    assert service.view().borrowed_from is None
    assert service.view().status == "unconfigured"


@pytest.mark.parametrize(
    "provider",
    [
        ValidationProvider(tool_name="wrong"),
        ValidationProvider(structured={"status": "bad"}),
        ValidationProvider(
            error=ProviderError(ProviderErrorCode.QUOTA_EXCEEDED, "今天借用的额度已用完")
        ),
    ],
)
def test_failed_borrow_keeps_persisted_state_and_previous_error(
    tmp_path: Path, provider: ModelProvider
) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    repository.save(input_config().provider_config())
    error = ProviderError(ProviderErrorCode.TIMEOUT, "连不上对方电脑", retryable=True)
    service = ModelConfigurationService(
        repository,
        MemorySecrets(),
        lambda _config, _key: ValidationProvider(error=error),
        lambda _node: provider,
    )
    previous = asyncio.run(service.validate())
    stored = (tmp_path / "model.json").read_bytes()
    with pytest.raises(ProviderError):
        asyncio.run(service.borrow(NodeId.new()))
    assert service.view() == previous
    assert (tmp_path / "model.json").read_bytes() == stored


def test_borrow_requires_injected_factory_and_does_not_read_secrets() -> None:
    repository = MemoryRepository()
    secrets = MemorySecrets()
    service = ModelConfigurationService(repository, secrets)
    with pytest.raises(ProviderError) as caught:
        asyncio.run(service.borrow(NodeId.new()))
    assert caught.value.code is ProviderErrorCode.MODEL_NOT_FOUND
    assert repository.borrowed is None
    repository.save_borrowed(BorrowedModelConfig(peer_node_id=NodeId.new()))
    assert service.view().status == "available"
    assert secrets.reads == []
    assert asyncio.run(service.validate()).status == "unavailable"


def test_tool_limit_follows_local_model_and_is_unset_when_borrowing(tmp_path: Path) -> None:
    peer = NodeId.new()
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    service = ModelConfigurationService(
        repository,
        MemorySecrets(),
        lambda _config, _key: ValidationProvider(),
        lambda _node_id: ValidationProvider(),
    )
    assert service.tool_limit() is None
    limited = input_config().model_copy(update={"max_tools": 5})
    view = asyncio.run(service.configure(limited))
    assert view.max_tools == 5
    assert view.profiles[0].max_tools == 5
    assert service.tool_limit() == 5
    assert FileModelConfigurationRepository(tmp_path / "model.json").load() == (
        limited.provider_config()
    )
    asyncio.run(service.borrow(peer))
    assert service.tool_limit() is None
    assert service.view().max_tools is None


@pytest.mark.parametrize("value", [2, 13])
def test_tool_limit_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValidationError):
        ModelConfigurationInput.model_validate({**input_config().model_dump(), "max_tools": value})


class PendingSecrets(MemorySecrets):
    """钥匙串授权框还没点：读取一律等不到。"""

    def get(self, name: str) -> str | None:
        self.reads.append(name)
        raise SecretStoreApprovalPendingError


def test_waiting_keychain_is_reported_instead_of_a_missing_key() -> None:
    """授权框没点时，网页说去点允许，也不会不带密钥去请求模型、换来一个 401。"""
    repository = MemoryRepository()
    repository.save(input_config().provider_config())
    service, _, secrets = service_with(ValidationProvider(), repository, PendingSecrets())

    view = service.view()
    assert (view.status, view.error_code, view.error_message) == (
        "unavailable",
        ProviderErrorCode.KEYCHAIN_APPROVAL_PENDING,
        KEYCHAIN_APPROVAL_HINT,
    )
    assert not view.api_key_configured
    assert not view.profiles[0].api_key_configured
    with pytest.raises(ProviderError) as caught:
        service.create_provider()
    assert caught.value.code is ProviderErrorCode.KEYCHAIN_APPROVAL_PENDING
    assert caught.value.retryable

    validated = asyncio.run(service.validate())
    assert validated.error_code == ProviderErrorCode.KEYCHAIN_APPROVAL_PENDING

    # 填了新密钥时不用先读旧密钥，授权框没点也能保存。
    asyncio.run(service.configure(input_config("new-key")))
    assert secrets.values[model_api_key_name(input_config().endpoint)] == "new-key"
