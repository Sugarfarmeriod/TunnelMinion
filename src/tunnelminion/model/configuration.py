"""模型配置持久化、验证和故障降级。"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from tunnelminion.agent.context_contracts import ContextRequest, ContextTaskType
from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.agent.prompts import (
    PROVIDER_STRUCTURED_CAPABILITY_PROMPT,
    PROVIDER_TOOL_CAPABILITY_PROMPT,
)
from tunnelminion.domain.identifiers import NodeId, RunId, ThreadId
from tunnelminion.model.contracts import (
    ModelMessage,
    ModelProvider,
    ProviderError,
    ProviderErrorCode,
    ToolDefinition,
)
from tunnelminion.model.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from tunnelminion.model.secrets import (
    KEYCHAIN_APPROVAL_HINT,
    SecretStore,
    SecretStoreApprovalPendingError,
    SecretStoreError,
)

MODEL_API_KEY_NAME = "model-provider-api-key"


def model_api_key_name(endpoint: str) -> str:
    """为规范化 endpoint 派生不可逆的本机密钥名称。"""
    normalized = endpoint.rstrip("/")
    digest = hashlib.sha256(normalized.encode()).hexdigest()
    return f"{MODEL_API_KEY_NAME}:{digest}"


class ModelConfigurationInput(BaseModel):
    """本地 API 接收的模型配置；密钥永不进入持久化 JSON。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    model: str
    timeout_seconds: float = Field(default=30.0, ge=0.1, le=600.0)
    disable_thinking: bool = False
    max_output_tokens: int = Field(default=2048, ge=16, le=32768)
    max_tools: int | None = Field(default=None, ge=3, le=12)
    api_key: str | None = Field(default=None, max_length=4096)

    def provider_config(self) -> OpenAICompatibleConfig:
        """提取可以安全持久化的非秘密配置。"""
        return OpenAICompatibleConfig(
            endpoint=self.endpoint,
            model=self.model,
            timeout_seconds=self.timeout_seconds,
            disable_thinking=self.disable_thinking,
            max_output_tokens=self.max_output_tokens,
            max_tools=self.max_tools,
        )


class ModelConfigurationProfileView(BaseModel):
    """可切回且不包含秘密的模型配置档案。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    model: str
    timeout_seconds: float
    disable_thinking: bool = False
    max_output_tokens: int = Field(default=2048, ge=16, le=32768)
    max_tools: int | None = Field(default=None, ge=3, le=12)
    api_key_configured: bool = False


class BorrowedModelConfig(BaseModel):
    """借用模型的固定提供方。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    peer_node_id: NodeId


class ModelConfigurationView(BaseModel):
    """可安全返回给 Web UI 的配置视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str | None = None
    model: str | None = None
    timeout_seconds: float | None = None
    disable_thinking: bool = False
    max_output_tokens: int | None = Field(default=None, ge=16, le=32768)
    max_tools: int | None = Field(default=None, ge=3, le=12)
    api_key_configured: bool = False
    borrowed_from: NodeId | None = None
    profiles: tuple[ModelConfigurationProfileView, ...] = ()
    status: str = Field(pattern="^(unconfigured|available|unavailable)$")
    error_code: ProviderErrorCode | None = None
    error_message: str | None = None


class _StoredModelConfigurations(BaseModel):
    """版本化的 active 配置与非秘密档案。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[3] = 3
    active: OpenAICompatibleConfig | None = None
    borrowed: BorrowedModelConfig | None = None
    profiles: tuple[OpenAICompatibleConfig, ...] = ()

    @model_validator(mode="after")
    def validate_profiles(self) -> _StoredModelConfigurations:
        if self.active is not None and self.borrowed is not None:
            raise ValueError("本地模型与借用模型不能同时启用")
        keys = [(item.endpoint, item.model) for item in self.profiles]
        if len(keys) != len(set(keys)):
            raise ValueError("模型配置档案包含重复 endpoint/model")
        if self.active is not None and (self.active.endpoint, self.active.model) not in keys:
            raise ValueError("active 模型配置不在档案中")
        return self


class ModelConfigurationRepository(Protocol):
    """不包含密钥的模型配置仓库。"""

    def load(self) -> OpenAICompatibleConfig | None:
        """加载当前节点配置。"""
        ...

    def save(self, config: OpenAICompatibleConfig) -> None:
        """保存当前节点配置。"""
        ...

    def load_borrowed(self) -> BorrowedModelConfig | None:
        """加载借用模型配置。"""
        ...

    def save_borrowed(self, config: BorrowedModelConfig) -> None:
        """保存借用配置并停用本地模型。"""
        ...

    def profiles(self) -> tuple[OpenAICompatibleConfig, ...]:
        """列出可切回的非秘密配置。"""
        ...

    def delete(self) -> None:
        """删除当前节点配置。"""
        ...


class FileModelConfigurationRepository:
    """以原子替换方式保存不含秘密的本机 JSON 配置。"""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> OpenAICompatibleConfig | None:
        """从磁盘加载配置。"""
        return self._load_state().active

    def save(self, config: OpenAICompatibleConfig) -> None:
        """写临时文件后原子替换正式配置。"""
        current = self._load_state()
        profiles = (
            config,
            *(
                item
                for item in current.profiles
                if (item.endpoint, item.model) != (config.endpoint, config.model)
            ),
        )
        self._write_state(_StoredModelConfigurations(active=config, profiles=profiles))

    def profiles(self) -> tuple[OpenAICompatibleConfig, ...]:
        """读取当前文件中的全部非秘密配置。"""
        return self._load_state().profiles

    def load_borrowed(self) -> BorrowedModelConfig | None:
        """读取当前借用配置。"""
        return self._load_state().borrowed

    def save_borrowed(self, config: BorrowedModelConfig) -> None:
        """保留本地档案并原子切换到借用模型。"""
        self._write_state(
            _StoredModelConfigurations(borrowed=config, profiles=self._load_state().profiles)
        )

    def _load_state(self) -> _StoredModelConfigurations:
        if not self._path.exists():
            return _StoredModelConfigurations()
        value = cast(JsonValue, json.loads(self._path.read_text(encoding="utf-8")))
        if isinstance(value, dict) and value.get("version") in (2, 3):
            if value["version"] == 2:
                value = {**value, "version": 3}
            return _StoredModelConfigurations.model_validate(value)
        legacy = OpenAICompatibleConfig.model_validate(value)
        return _StoredModelConfigurations(active=legacy, profiles=(legacy,))

    def _write_state(self, state: _StoredModelConfigurations) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(f"{self._path.suffix}.tmp")
        temporary.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(self._path)

    def delete(self) -> None:
        """删除配置文件；不存在时保持幂等。"""
        self._path.unlink(missing_ok=True)


ProviderFactory = Callable[[OpenAICompatibleConfig, str | None], ModelProvider]


def default_provider_factory(config: OpenAICompatibleConfig, api_key: str | None) -> ModelProvider:
    """创建首个 OpenAI-compatible Provider。"""
    return OpenAICompatibleProvider(config, api_key)


class ModelConfigurationService:
    """协调模型验证、非秘密配置和操作系统密钥环。"""

    def __init__(
        self,
        repository: ModelConfigurationRepository,
        secrets: SecretStore,
        provider_factory: ProviderFactory = default_provider_factory,
        borrowed_provider_factory: Callable[[NodeId], ModelProvider] | None = None,
    ) -> None:
        self._repository = repository
        self._secrets = secrets
        self._provider_factory = provider_factory
        self._borrowed_provider_factory = borrowed_provider_factory
        self._last_error: ProviderError | None = None

    def view(self) -> ModelConfigurationView:
        """返回永不包含完整密钥的当前配置视图。"""
        config = self._repository.load()
        borrowed = self._repository.load_borrowed()
        profiles = tuple(self._profile_view(item) for item in self._repository.profiles())
        if config is None and borrowed is None:
            return ModelConfigurationView(status="unconfigured", profiles=profiles)
        error = self._last_error
        api_key_configured = False
        if config is not None:
            try:
                api_key_configured = self._optional_api_key(config) is not None
            except ProviderError as exc:
                error = error or exc
        return ModelConfigurationView(
            endpoint=config.endpoint if config is not None else None,
            model=config.model if config is not None else None,
            timeout_seconds=config.timeout_seconds if config is not None else None,
            disable_thinking=config is not None and config.disable_thinking,
            max_output_tokens=config.max_output_tokens if config is not None else None,
            max_tools=config.max_tools if config is not None else None,
            api_key_configured=api_key_configured,
            borrowed_from=borrowed.peer_node_id if borrowed is not None else None,
            profiles=profiles,
            status="unavailable" if error is not None else "available",
            error_code=error.code if error is not None else None,
            error_message=str(error) if error is not None else None,
        )

    async def configure(self, value: ModelConfigurationInput) -> ModelConfigurationView:
        """验证成功后才保存配置与可选密钥。"""
        config = value.provider_config()
        api_key = value.api_key if value.api_key is not None else self._optional_api_key(config)
        await self._validate_provider(config, api_key)
        self._repository.save(config)
        if value.api_key is not None:
            secret_name = model_api_key_name(config.endpoint)
            if value.api_key:
                self._secrets.set(secret_name, value.api_key)
            else:
                self._secrets.delete(secret_name)
        self._last_error = None
        return self.view()

    async def borrow(self, peer_node_id: NodeId) -> ModelConfigurationView:
        """验证对端模型能力后才切换配置。"""
        config = BorrowedModelConfig(peer_node_id=peer_node_id)
        await self._validate_provider(config, None)
        self._repository.save_borrowed(config)
        self._last_error = None
        return self.view()

    async def validate(self) -> ModelConfigurationView:
        """重新验证已保存配置并更新运行时可用状态。"""
        config = self._repository.load_borrowed() or self._repository.load()
        if config is None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "尚未配置模型")
        try:
            api_key = (
                self._optional_api_key(config)
                if isinstance(config, OpenAICompatibleConfig)
                else None
            )
            await self._validate_provider(config, api_key)
            self._last_error = None
        except ProviderError as exc:
            self._last_error = exc
        return self.view()

    def delete(self) -> None:
        """同时删除全部非秘密配置和对应操作系统密钥。"""
        for name in {model_api_key_name(item.endpoint) for item in self._repository.profiles()}:
            self._secrets.delete(name)
        self._secrets.delete(MODEL_API_KEY_NAME)
        self._repository.delete()
        self._last_error = None

    def require_available(self) -> None:
        """在创建新 AI run 前执行降级门卫。"""
        if self._repository.load() is None and self._repository.load_borrowed() is None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "模型未配置或不可用")
        if self._last_error is not None:
            raise ProviderError(
                self._last_error.code,
                str(self._last_error),
                retryable=self._last_error.retryable,
            )

    def tool_limit(self) -> int | None:
        """当前本机模型的工具上限；借用模型时不知道对方是什么模型，不设上限。"""
        config = self._repository.load()
        return config.max_tools if config is not None else None

    def create_provider(self) -> ModelProvider:
        """为一次 Agent run 创建当前已配置且通过门卫的 Provider。"""
        self.require_available()
        borrowed = self._repository.load_borrowed()
        if borrowed is not None:
            return self._borrowed_provider(borrowed.peer_node_id)
        config = self._repository.load()
        if config is None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "尚未配置模型")
        return self._provider_factory(config, self._optional_api_key(config))

    def create_lending_provider(self) -> ModelProvider:
        """为借给其他电脑的调用创建 Provider；借来的模型不能转借，避免互相借用成环。"""
        if self._repository.load_borrowed() is not None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "本机的模型也是借来的，不能转借")
        return self.create_provider()

    def _borrowed_provider(self, peer_node_id: NodeId) -> ModelProvider:
        if self._borrowed_provider_factory is None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "对方电脑还没有配置模型")
        return self._borrowed_provider_factory(peer_node_id)

    def _optional_api_key(self, config: OpenAICompatibleConfig) -> str | None:
        """无 Key Provider 在无图形 Keychain 会话中仍可运行；钥匙串在等授权时照实报出。"""
        try:
            return self._secrets.get(model_api_key_name(config.endpoint))
        except SecretStoreApprovalPendingError:
            raise ProviderError(
                ProviderErrorCode.KEYCHAIN_APPROVAL_PENDING, KEYCHAIN_APPROVAL_HINT, retryable=True
            ) from None
        except SecretStoreError:
            return None

    def _profile_view(self, config: OpenAICompatibleConfig) -> ModelConfigurationProfileView:
        return ModelConfigurationProfileView(
            endpoint=config.endpoint,
            model=config.model,
            timeout_seconds=config.timeout_seconds,
            disable_thinking=config.disable_thinking,
            max_output_tokens=config.max_output_tokens,
            max_tools=config.max_tools,
            api_key_configured=self._profile_has_key(config),
        )

    def _profile_has_key(self, config: OpenAICompatibleConfig) -> bool:
        try:
            return self._optional_api_key(config) is not None
        except ProviderError:
            return False

    async def _validate_provider(
        self, config: OpenAICompatibleConfig | BorrowedModelConfig, api_key: str | None
    ) -> None:
        provider = (
            self._borrowed_provider(config.peer_node_id)
            if isinstance(config, BorrowedModelConfig)
            else self._provider_factory(config, api_key)
        )
        if not provider.capabilities.tool_calls or not provider.capabilities.structured_output:
            raise ProviderError(
                ProviderErrorCode.CAPABILITY_INCOMPATIBLE,
                "Provider 未声明工具调用和结构化输出能力",
            )

        tool = ToolDefinition(
            name="report_capability",
            description="报告模型能力验证结果",
            input_schema={
                "type": "object",
                "properties": {"status": {"type": "string", "enum": ["ok"]}},
                "required": ["status"],
                "additionalProperties": False,
            },
        )
        runtime = ContextModelRuntime(
            provider,
            provider_name="remote"
            if isinstance(config, BorrowedModelConfig)
            else "openai-compatible",
            model_name=str(config.peer_node_id)
            if isinstance(config, BorrowedModelConfig)
            else config.model,
            tool_schema_version="provider-capability/v1",
        )
        thread_id = ThreadId.new()
        run_id = RunId.new()
        tool_response = (
            await runtime.invoke(
                ContextRequest(
                    task_type=ContextTaskType.PROVIDER_VALIDATION,
                    current_intent="验证 Provider 工具调用能力",
                    thread_id=thread_id,
                    run_id=run_id,
                    prompt_id=PROVIDER_TOOL_CAPABILITY_PROMPT.prompt_id,
                    prompt_version=PROVIDER_TOOL_CAPABILITY_PROMPT.version,
                    messages=(
                        ModelMessage(
                            role="user",
                            content=PROVIDER_TOOL_CAPABILITY_PROMPT.template,
                        ),
                    ),
                    tools=(tool,),
                    require_tool_call=True,
                )
            )
        ).response
        if not tool_response.tool_calls or tool_response.tool_calls[0].name != tool.name:
            raise ProviderError(
                ProviderErrorCode.CAPABILITY_INCOMPATIBLE,
                "模型未返回要求的结构化工具调用",
            )

        structured_response = (
            await runtime.invoke(
                ContextRequest(
                    task_type=ContextTaskType.PROVIDER_VALIDATION,
                    current_intent="验证 Provider 结构化输出能力",
                    thread_id=thread_id,
                    run_id=run_id,
                    prompt_id=PROVIDER_STRUCTURED_CAPABILITY_PROMPT.prompt_id,
                    prompt_version=PROVIDER_STRUCTURED_CAPABILITY_PROMPT.version,
                    messages=(
                        ModelMessage(
                            role="user",
                            content=PROVIDER_STRUCTURED_CAPABILITY_PROMPT.template,
                        ),
                    ),
                    response_schema={
                        "type": "object",
                        "properties": {"status": {"type": "string", "enum": ["ok"]}},
                        "required": ["status"],
                        "additionalProperties": False,
                    },
                )
            )
        ).response
        if structured_response.structured_output != {"status": "ok"}:
            raise ProviderError(
                ProviderErrorCode.CAPABILITY_INCOMPATIBLE,
                "模型未返回要求的结构化 JSON 结果",
            )
