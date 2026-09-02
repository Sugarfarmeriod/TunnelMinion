"""模型配置持久化、验证和故障降级。"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.agent.context_contracts import ContextRequest, ContextTaskType
from tunnelminion.agent.context_runtime import ContextModelRuntime
from tunnelminion.agent.prompts import (
    PROVIDER_JSON_OBJECT_CAPABILITY_PROMPT,
    PROVIDER_TOOL_CAPABILITY_PROMPT,
)
from tunnelminion.domain.identifiers import RunId, ThreadId
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
from tunnelminion.model.secrets import SecretStore, SecretStoreError

MODEL_API_KEY_NAME = "model-provider-api-key"


class ModelConfigurationInput(BaseModel):
    """本地 API 接收的模型配置；密钥永不进入持久化 JSON。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    model: str
    timeout_seconds: float = Field(default=30.0, ge=0.1, le=600.0)
    api_key: str | None = Field(default=None, max_length=4096)

    def provider_config(self) -> OpenAICompatibleConfig:
        """提取可以安全持久化的非秘密配置。"""
        return OpenAICompatibleConfig(
            endpoint=self.endpoint,
            model=self.model,
            timeout_seconds=self.timeout_seconds,
        )


class ModelConfigurationView(BaseModel):
    """可安全返回给 Web UI 的配置视图。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str | None = None
    model: str | None = None
    timeout_seconds: float | None = None
    api_key_configured: bool = False
    status: str = Field(pattern="^(unconfigured|available|unavailable)$")
    error_code: ProviderErrorCode | None = None
    error_message: str | None = None


class ModelConfigurationRepository(Protocol):
    """不包含密钥的模型配置仓库。"""

    def load(self) -> OpenAICompatibleConfig | None:
        """加载当前节点配置。"""
        ...

    def save(self, config: OpenAICompatibleConfig) -> None:
        """保存当前节点配置。"""
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
        if not self._path.exists():
            return None
        return OpenAICompatibleConfig.model_validate_json(self._path.read_text(encoding="utf-8"))

    def save(self, config: OpenAICompatibleConfig) -> None:
        """写临时文件后原子替换正式配置。"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(f"{self._path.suffix}.tmp")
        temporary.write_text(config.model_dump_json(indent=2), encoding="utf-8")
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
    ) -> None:
        self._repository = repository
        self._secrets = secrets
        self._provider_factory = provider_factory
        self._last_error: ProviderError | None = None

    def view(self) -> ModelConfigurationView:
        """返回永不包含完整密钥的当前配置视图。"""
        config = self._repository.load()
        key_configured = self._optional_api_key() is not None
        if config is None:
            return ModelConfigurationView(status="unconfigured")
        error = self._last_error
        return ModelConfigurationView(
            endpoint=config.endpoint,
            model=config.model,
            timeout_seconds=config.timeout_seconds,
            api_key_configured=key_configured,
            status="unavailable" if error is not None else "available",
            error_code=error.code if error is not None else None,
            error_message=str(error) if error is not None else None,
        )

    async def configure(self, value: ModelConfigurationInput) -> ModelConfigurationView:
        """验证成功后才保存配置与可选密钥。"""
        config = value.provider_config()
        current_key = self._optional_api_key()
        api_key = value.api_key if value.api_key is not None else current_key
        await self._validate_provider(config, api_key)
        self._repository.save(config)
        if value.api_key is not None:
            if value.api_key:
                self._secrets.set(MODEL_API_KEY_NAME, value.api_key)
            else:
                self._secrets.delete(MODEL_API_KEY_NAME)
        self._last_error = None
        return self.view()

    async def validate(self) -> ModelConfigurationView:
        """重新验证已保存配置并更新运行时可用状态。"""
        config = self._repository.load()
        if config is None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "尚未配置模型")
        api_key = self._optional_api_key()
        try:
            await self._validate_provider(config, api_key)
            self._last_error = None
        except ProviderError as exc:
            self._last_error = exc
        return self.view()

    def delete(self) -> None:
        """同时删除非秘密配置和操作系统密钥。"""
        self._repository.delete()
        self._secrets.delete(MODEL_API_KEY_NAME)
        self._last_error = None

    def require_available(self) -> None:
        """在创建新 AI run 前执行降级门卫。"""
        view = self.view()
        if view.status != "available":
            code = view.error_code or ProviderErrorCode.MODEL_NOT_FOUND
            message = view.error_message or "模型未配置或不可用"
            raise ProviderError(code, message)

    def create_provider(self) -> ModelProvider:
        """为一次 Agent run 创建当前已配置且通过门卫的 Provider。"""
        self.require_available()
        config = self._repository.load()
        if config is None:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "尚未配置模型")
        return self._provider_factory(config, self._optional_api_key())

    def _optional_api_key(self) -> str | None:
        """无 Key Provider 在无图形 Keychain 会话中仍可运行。"""
        try:
            return self._secrets.get(MODEL_API_KEY_NAME)
        except SecretStoreError:
            return None

    async def _validate_provider(self, config: OpenAICompatibleConfig, api_key: str | None) -> None:
        provider = self._provider_factory(config, api_key)
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
            provider_name="openai-compatible",
            model_name=config.model,
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
                    prompt_id=PROVIDER_JSON_OBJECT_CAPABILITY_PROMPT.prompt_id,
                    prompt_version=PROVIDER_JSON_OBJECT_CAPABILITY_PROMPT.version,
                    messages=(
                        ModelMessage(
                            role="user",
                            content=PROVIDER_JSON_OBJECT_CAPABILITY_PROMPT.template,
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
