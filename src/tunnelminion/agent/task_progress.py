"""持续任务保存的公开工具观察，不包含模型隐藏推理或授权。"""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict

from tunnelminion.tools.contracts import ToolCallContext, ToolExecutionRequest, ToolExecutionResult


class TaskObservation(BaseModel):
    """一次实际执行完毕的检查及其发生时间。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request: ToolExecutionRequest
    result: ToolExecutionResult
    observed_at: AwareDatetime


class TaskProgress(BaseModel):
    """任务进度用于继续调查，不能代替新的实时证据或恢复权限。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observations: tuple[TaskObservation, ...] = ()

    def record(
        self, request: ToolExecutionRequest, result: ToolExecutionResult, at: datetime
    ) -> TaskProgress:
        """只追加已返回的工具结果，未完成调用交给新的调查决定。"""
        return self.model_copy(
            update={
                "observations": (
                    *self.observations,
                    TaskObservation(request=request, result=result, observed_at=at),
                )
            }
        )

    def messages(
        self, context: ToolCallContext, allowed_tools: tuple[str, ...]
    ) -> list[dict[str, object]]:
        """以标准工具消息带回同一对象的历史观察，不重放调用。"""
        messages: list[dict[str, object]] = []
        for observation in self.observations:
            request = observation.request
            if (
                request.context.thread_id != context.thread_id
                or request.context.caller_node_id != context.caller_node_id
                or request.context.execution_node_id != context.execution_node_id
                or request.tool_name not in allowed_tools
            ):
                continue
            call_id = f"history-{observation.result.tool_run_id}"
            messages.extend(
                (
                    {
                        "role": "assistant",
                        "content": "这是上次任务的历史检查，只说明当时状态，不是当前实时事实。",
                        "tool_calls": [
                            {
                                "name": request.tool_name,
                                "args": request.arguments,
                                "id": call_id,
                                "type": "tool_call",
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": json.dumps(
                            {
                                "trust": "untrusted-historical-tool-data",
                                "observed_at": observation.observed_at.isoformat(),
                                "result": observation.result.model_dump(mode="json"),
                            },
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    },
                )
            )
        return messages
