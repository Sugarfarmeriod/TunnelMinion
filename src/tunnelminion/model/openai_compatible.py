"""OpenAI-compatible Chat Completions Provider。"""

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

import httpx
from jsonschema import SchemaError, ValidationError, validate
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ProviderError,
    ProviderErrorCode,
    ToolCall,
)


class OpenAICompatibleConfig(BaseModel):
    """不包含秘密的 OpenAI-compatible 连接配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str = Field(min_length=1)
    model: str = Field(min_length=1)
    timeout_seconds: float = Field(default=30.0, ge=0.1, le=600.0)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        """只允许明确的 HTTP(S) API 根地址。"""
        normalized = value.rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("endpoint 必须使用 http:// 或 https://")
        return normalized


class OpenAICompatibleProvider:
    """通过 `/chat/completions` 调用兼容服务。"""

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        api_key: str | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._api_key = api_key
        self._transport = transport

    @property
    def capabilities(self) -> ModelCapabilities:
        """兼容适配器支持工具与 JSON Schema 请求，最终以实测为准。"""
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        """发送请求并把兼容响应归一化为 Provider 契约。"""
        if cancellation is not None and cancellation.cancelled:
            raise ProviderError(ProviderErrorCode.CANCELLED, "模型调用已取消")

        payload = self._build_payload(request)
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        async with httpx.AsyncClient(transport=self._transport) as client:
            request_task = asyncio.create_task(
                client.post(
                    f"{self._config.endpoint}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self._config.timeout_seconds,
                )
            )
            cancel_task = (
                asyncio.create_task(cancellation.wait()) if cancellation is not None else None
            )
            waiters: set[asyncio.Task[Any]] = {request_task}
            if cancel_task is not None:
                waiters.add(cancel_task)

            try:
                done, _ = await asyncio.wait(
                    waiters,
                    timeout=self._config.timeout_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if cancel_task is not None and cancel_task in done:
                    request_task.cancel()
                    await asyncio.gather(request_task, return_exceptions=True)
                    raise ProviderError(ProviderErrorCode.CANCELLED, "模型调用已取消")
                if request_task not in done:
                    request_task.cancel()
                    await asyncio.gather(request_task, return_exceptions=True)
                    raise ProviderError(
                        ProviderErrorCode.TIMEOUT,
                        "模型调用超时",
                        retryable=True,
                    )
                response = await request_task
            except httpx.TimeoutException as exc:
                raise ProviderError(
                    ProviderErrorCode.TIMEOUT, "模型调用超时", retryable=True
                ) from exc
            except httpx.ConnectError as exc:
                raise ProviderError(
                    ProviderErrorCode.NETWORK_UNREACHABLE,
                    "无法连接模型服务",
                    retryable=True,
                ) from exc
            finally:
                if cancel_task is not None:
                    cancel_task.cancel()
                    await asyncio.gather(cancel_task, return_exceptions=True)

        self._raise_for_status(response)
        return self._parse_response(response, request)

    def _build_payload(self, request: ModelRequest) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self._config.model,
            "messages": [self._serialize_message(message) for message in request.messages],
        }
        if request.tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema,
                    },
                }
                for tool in request.tools
            ]
            if request.require_tool_call:
                payload["tool_choice"] = "required"
        if request.response_schema is not None:
            payload["response_format"] = {"type": "json_object"}
        return payload

    @staticmethod
    def _serialize_message(message: ModelMessage) -> dict[str, object]:
        """转换公开消息，同时保留 OpenAI 工具循环关联字段。"""
        serialized: dict[str, object] = {"role": message.role, "content": message.content}
        if message.tool_calls:
            serialized["tool_calls"] = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments, ensure_ascii=False),
                    },
                }
                for call in message.tool_calls
            ]
        if message.tool_call_id is not None:
            serialized["tool_call_id"] = message.tool_call_id
        if message.name is not None:
            serialized["name"] = message.name
        return serialized

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code in {401, 403}:
            raise ProviderError(ProviderErrorCode.AUTHENTICATION_FAILED, "模型认证失败")
        if response.status_code == 404:
            raise ProviderError(ProviderErrorCode.MODEL_NOT_FOUND, "模型或 API 路径不存在")
        if response.is_error:
            raise ProviderError(
                ProviderErrorCode.INVALID_RESPONSE,
                f"模型服务返回 HTTP {response.status_code}",
                retryable=response.status_code >= 500,
            )

    @staticmethod
    def _parse_response(response: httpx.Response, request: ModelRequest) -> ModelResponse:
        try:
            data = cast(dict[str, Any], response.json())
            message = cast(dict[str, Any], data["choices"][0]["message"])
            raw_calls = cast(list[dict[str, Any]], message.get("tool_calls") or [])
            tool_calls = tuple(
                ToolCall(
                    call_id=str(item["id"]),
                    name=str(item["function"]["name"]),
                    arguments=cast(dict[str, JsonValue], json.loads(item["function"]["arguments"])),
                )
                for item in raw_calls
            )
            content = message.get("content")
            structured: JsonValue | None = None
            if request.response_schema is not None:
                structured = cast(JsonValue, json.loads(str(content)))
                validate(instance=structured, schema=request.response_schema)
            raw_usage = cast(dict[str, Any], data.get("usage", {}))
            usage = ModelUsage(
                input_tokens=raw_usage.get("prompt_tokens"),
                output_tokens=raw_usage.get("completion_tokens"),
                total_tokens=raw_usage.get("total_tokens"),
            )
            return ModelResponse(
                content=cast(str | None, content),
                tool_calls=tool_calls,
                structured_output=structured,
                usage=usage,
            )
        except (
            KeyError,
            IndexError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            SchemaError,
            ValidationError,
        ) as exc:
            raise ProviderError(
                ProviderErrorCode.INVALID_RESPONSE, "模型响应不符合兼容协议"
            ) from exc
