import asyncio
from pathlib import Path
from typing import Protocol, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from tunnelminion.agent.conversation import RunStatus, RunView, StartRunInput
from tunnelminion.app import build_windows_application
from tunnelminion.model.configuration import ModelConfigurationService
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ProviderErrorCode,
)


class FailingProvider:
    """固定失败的模型，证明非 AI 控制面不依赖模型恢复。"""

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(tool_calls=True, structured_output=True)

    async def complete(
        self,
        request: ModelRequest,
        cancellation: CancellationToken | None = None,
    ) -> ModelResponse:
        del request, cancellation
        raise ProviderError(
            ProviderErrorCode.TIMEOUT,
            "不应进入普通记录的模型响应正文",
            retryable=True,
        )


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def get(self, url: str) -> httpx.Response: ...


def test_model_failure_keeps_resource_and_operation_controls_available(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def failing_provider(_self: ModelConfigurationService) -> FailingProvider:
        return FailingProvider()

    monkeypatch.setattr(ModelConfigurationService, "create_provider", failing_provider)
    root = tmp_path / "runtime-degradation"
    bundle = build_windows_application(root)

    async def failed_conversation() -> RunView:
        thread = bundle.conversation_service.create_thread()
        started = await bundle.conversation_service.start_run(
            thread.thread_id,
            StartRunInput(
                question="读取节点状态",
                tool_names=("get_node_summary",),
            ),
        )
        _ = [event async for event in bundle.conversation_service.stream_events(started.run_id)]
        return bundle.conversation_service.get_run(started.run_id)

    failed = asyncio.run(failed_conversation())
    assert failed.status is RunStatus.FAILED
    failure = failed.failure
    assert failure is not None
    assert failure.category.value == "prompt_or_model"
    assert failure.reason.value == "model_timeout"
    assert "模型响应正文" not in failure.model_dump_json()

    with TestClient(bundle.app, base_url="http://127.0.0.1") as raw_client:
        client = cast(ApiClient, raw_client)
        resource = client.get("/api/resources/node-summary")
        operations = client.get("/api/operations")
        resource_page = client.get("/resources")
        operation_page = client.get("/operations")

    assert resource.status_code == 200
    assert cast(dict[str, object], resource.json())["status"] in {
        "success",
        "partial",
        "failed",
    }
    assert operations.status_code == 200
    assert operations.json() == []
    assert resource_page.status_code == 200
    assert operation_page.status_code == 200
