"""外部模型只读健康检查测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.runtime import (
    ModelHealthStatus,
    probe_external_model,
)


def test_model_health_is_unconfigured_without_model_file(tmp_path: Path) -> None:
    result = asyncio.run(probe_external_model(tmp_path, 0.1))
    assert result.status is ModelHealthStatus.UNCONFIGURED
    assert result.endpoint_sha256 is None


def test_model_health_reports_invalid_config(tmp_path: Path) -> None:
    (tmp_path / "model.json").write_text("{}", encoding="utf-8")
    result = asyncio.run(probe_external_model(tmp_path, 0.1))
    assert result.status is ModelHealthStatus.UNAVAILABLE
    assert result.code == "model_config_invalid"


def test_model_health_gets_models_without_secret_or_response_body(tmp_path: Path) -> None:
    endpoint = "http://model.internal:8082/v1/private-do-not-print"
    FileModelConfigurationRepository(tmp_path / "model.json").save(
        OpenAICompatibleConfig(endpoint=endpoint, model="fixture")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/private-do-not-print/models"
        assert "authorization" not in request.headers
        return httpx.Response(200, json={"secret": "response-must-not-print"})

    result = asyncio.run(
        probe_external_model(tmp_path, 0.5, transport=httpx.MockTransport(handler))
    )
    serialized = result.model_dump_json()
    assert result.status is ModelHealthStatus.REACHABLE
    assert result.http_status == 200
    assert endpoint not in serialized
    assert "do-not-print" not in serialized
    assert "response-must-not-print" not in serialized


def test_model_unavailable_remains_a_nonthrowing_health_result(tmp_path: Path) -> None:
    FileModelConfigurationRepository(tmp_path / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://model.internal:8082/v1", model="fixture")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        raise httpx.ConnectError("offline")

    result = asyncio.run(
        probe_external_model(tmp_path, 0.1, transport=httpx.MockTransport(handler))
    )
    assert result.status is ModelHealthStatus.UNAVAILABLE
    assert result.code == "model_unreachable"


def test_model_health_reports_http_error_and_timeout(tmp_path: Path) -> None:
    FileModelConfigurationRepository(tmp_path / "model.json").save(
        OpenAICompatibleConfig(endpoint="http://model.internal:8082/v1", model="fixture")
    )

    http_error = asyncio.run(
        probe_external_model(
            tmp_path,
            0.1,
            transport=httpx.MockTransport(lambda request: httpx.Response(503, request=request)),
        )
    )

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("late", request=request)

    timed_out = asyncio.run(
        probe_external_model(tmp_path, 0.1, transport=httpx.MockTransport(timeout))
    )
    assert (http_error.status, http_error.code, http_error.http_status) == (
        ModelHealthStatus.UNAVAILABLE,
        "model_http_error",
        503,
    )
    assert timed_out.code == "model_timeout"
