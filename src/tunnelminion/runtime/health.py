"""外部模型的有界、只读、零秘密健康检查。"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path
from time import perf_counter

import httpx
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.model.configuration import FileModelConfigurationRepository


class ModelHealthStatus(StrEnum):
    """外部模型的脱敏可用状态。"""

    UNCONFIGURED = "unconfigured"
    REACHABLE = "reachable"
    UNAVAILABLE = "unavailable"


class ModelHealthResult(BaseModel):
    """不含 endpoint、请求/响应正文或凭据的模型健康结果。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ModelHealthStatus
    code: str
    endpoint_sha256: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    http_status: int | None = Field(default=None, ge=100, le=599)
    latency_ms: int | None = Field(default=None, ge=0)


async def probe_external_model(
    data_dir: Path,
    timeout_seconds: float,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ModelHealthResult:
    """仅 GET `/models`；模型失败不会改变确定性组件的预检结论。"""
    try:
        config = FileModelConfigurationRepository(data_dir / "model.json").load()
    except (OSError, ValueError):
        return ModelHealthResult(status=ModelHealthStatus.UNAVAILABLE, code="model_config_invalid")
    if config is None:
        return ModelHealthResult(status=ModelHealthStatus.UNCONFIGURED, code="model_unconfigured")

    endpoint_hash = hashlib.sha256(config.endpoint.encode()).hexdigest()
    started = perf_counter()
    try:
        async with httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout_seconds,
        ) as client:
            response = await client.get(f"{config.endpoint}/models")
        latency_ms = max(0, round((perf_counter() - started) * 1000))
        if 200 <= response.status_code < 300:
            return ModelHealthResult(
                status=ModelHealthStatus.REACHABLE,
                code="model_reachable",
                endpoint_sha256=endpoint_hash,
                http_status=response.status_code,
                latency_ms=latency_ms,
            )
        return ModelHealthResult(
            status=ModelHealthStatus.UNAVAILABLE,
            code="model_http_error",
            endpoint_sha256=endpoint_hash,
            http_status=response.status_code,
            latency_ms=latency_ms,
        )
    except httpx.TimeoutException:
        code = "model_timeout"
    except httpx.HTTPError:
        code = "model_unreachable"
    return ModelHealthResult(
        status=ModelHealthStatus.UNAVAILABLE,
        code=code,
        endpoint_sha256=endpoint_hash,
        latency_ms=max(0, round((perf_counter() - started) * 1000)),
    )
