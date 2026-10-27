"""请求方的委派工具：把问题交给另一台电脑的 Agent，等它查完后取回结论。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from time import monotonic
from typing import Protocol, cast

from pydantic import JsonValue

from tunnelminion.agent.delegation_progress import (
    DelegationPhase,
    DelegationProgress,
    DelegationProgressSink,
)
from tunnelminion.domain.delegation import (
    DELEGATE_TOOL_NAME,
    MAX_SECONDS,
    TERMINAL_DELEGATION_STATUSES,
    DelegationProposedRepair,
    DelegationRecord,
    DelegationStatus,
)
from tunnelminion.domain.errors import ErrorCode, ToolError
from tunnelminion.domain.identifiers import DelegationId, NodeId
from tunnelminion.domain.service_marks import MARK_KEY_PATTERN
from tunnelminion.domain.tools import DataSensitivity, Platform, RiskLevel, ToolDefinition
from tunnelminion.domain.versioning import ProtocolVersion
from tunnelminion.gateway.client import FixedGatewayClient, RemoteGatewayError
from tunnelminion.gateway.configuration import GatewayConfigurationService
from tunnelminion.tools.audit import AuditSink
from tunnelminion.tools.contracts import ToolAdapterError, ToolCancellationToken
from tunnelminion.tools.registry import ToolRegistry
from tunnelminion.tools.runtime import current_tool_call_context

# 在被委派方的上限之外留出网络和排队的余量。
_WAIT_SECONDS = MAX_SECONDS + 10
ProposedRepairsSink = Callable[[NodeId, tuple[DelegationProposedRepair, ...]], None]


class DelegationClient(Protocol):
    """委派需要的对端客户端能力。"""

    async def submit_delegation(
        self, question: str, service_key: str | None = None
    ) -> DelegationRecord: ...

    async def get_delegation(self, delegation_id: DelegationId) -> DelegationRecord: ...

    async def cancel_delegation(self, delegation_id: DelegationId) -> DelegationRecord: ...


class DelegationPeer(Protocol):
    """可以委派的一台电脑。"""

    @property
    def node_id(self) -> NodeId: ...

    @property
    def platform(self) -> Platform | None: ...

    @property
    def host(self) -> str: ...


_PLATFORM_NAMES = {Platform.WINDOWS: "Windows 电脑", Platform.MACOS: "macOS 电脑（Mac）"}


def delegate_tool_definition(peers: Sequence[DelegationPeer], platform: Platform) -> ToolDefinition:
    """委派工具的定义；描述里写明本机是哪台、能交给哪几台，模型据此判断和填写 node_id。"""
    listing = "；".join(
        f"{_PLATFORM_NAMES[peer.platform] if peer.platform else '未知平台的电脑'}"
        f"，地址 {peer.host}，node_id={peer.node_id}"
        for peer in peers
    )
    return ToolDefinition.model_validate(
        {
            "name": DELEGATE_TOOL_NAME,
            "version": ProtocolVersion(major=1, minor=0),
            "description": (
                f"你所在的是一台{_PLATFORM_NAMES[platform]}，其他工具只能查看这台电脑。"
                "问题涉及另一台电脑上的程序或服务时，必须用本工具把问题交给那台电脑的 "
                "TunnelMinion Agent，由它用那台电脑的本机工具查清楚，回报结论、确认的事实、"
                f"未知和证据摘要；不要用本机工具去查别的电脑。可以交给的电脑：{listing}。"
            )[:1000],
            "input_schema": {
                "type": "object",
                "properties": {
                    "node_id": {"type": "string", "pattern": r"^node_[0-9a-f]{32}$"},
                    "question": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "service_key": {"type": "string", "pattern": MARK_KEY_PATTERN},
                },
                "required": ["node_id", "question"],
                "additionalProperties": False,
            },
            "output_schema": {"type": "object"},
            "risk_level": RiskLevel.READ_ONLY,
            "platforms": [platform],
            "permissions": ["delegate-to-peer"],
            "timeout_seconds": _WAIT_SECONDS + 5,
            "max_result_bytes": 64_000,
            "data_sensitivity": DataSensitivity.SYSTEM_METADATA,
        }
    )


class DelegateToNodeAdapter:
    """提交委派、等待结论；本机取消时请对端也停下。"""

    def __init__(
        self,
        client_for: Callable[[NodeId], DelegationClient],
        *,
        poll_seconds: float = 1.0,
        wait_seconds: float = _WAIT_SECONDS,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = monotonic,
        progress_sink: DelegationProgressSink | None = None,
        proposed_repairs_sink: ProposedRepairsSink | None = None,
    ) -> None:
        self._client_for = client_for
        self._poll_seconds = poll_seconds
        self._wait_seconds = wait_seconds
        self._sleep = sleep
        self._clock = clock
        self._progress_sink = progress_sink
        self._proposed_repairs_sink = proposed_repairs_sink

    async def execute(
        self, arguments: dict[str, JsonValue], cancellation: ToolCancellationToken
    ) -> JsonValue:
        try:
            node_id = NodeId(str(arguments["node_id"]))
            client = self._client_for(node_id)
        except (ValueError, KeyError) as exc:
            raise _error(ErrorCode.INVALID_ARGUMENT, "没有这台可以委派的电脑") from exc
        question = str(arguments["question"])
        service_key = arguments.get("service_key")
        try:
            record = await client.submit_delegation(
                question, str(service_key) if service_key is not None else None
            )
        except RemoteGatewayError as exc:
            raise _error(exc.code, str(exc)) from exc
        delegation_id = record.delegation_id
        context = current_tool_call_context.get(None)

        def report(phase: DelegationPhase) -> None:
            if self._progress_sink is not None and context is not None:
                self._progress_sink(
                    context,
                    DelegationProgress(
                        delegation_id=delegation_id, peer_node_id=node_id, phase=phase
                    ),
                )

        phase: DelegationPhase = "failed"
        try:
            report("submitted")
            deadline = self._clock() + self._wait_seconds
            investigating = False
            while record.status not in TERMINAL_DELEGATION_STATUSES:
                if cancellation.cancelled:
                    record = await client.cancel_delegation(delegation_id)
                    phase = "cancelled"
                    break
                if self._clock() >= deadline:
                    await client.cancel_delegation(delegation_id)
                    raise _error(ErrorCode.REMOTE_TIMEOUT, "对方电脑没有在时限内查完")
                await self._sleep(self._poll_seconds)
                record = await client.get_delegation(delegation_id)
                if record.status is DelegationStatus.RUNNING and not investigating:
                    report("investigating")
                    investigating = True
            output = cast(
                JsonValue,
                {
                    "answered_by": str(record.executing_node_id),
                    "status": record.status.value,
                    "error_code": record.error_code.value if record.error_code else None,
                    "result": record.result.model_dump(mode="json") if record.result else None,
                },
            )
            if phase != "cancelled":
                phase = (
                    "answered"
                    if record.status is DelegationStatus.COMPLETED
                    else "cancelled"
                    if record.status is DelegationStatus.CANCELLED
                    else "failed"
                )
            if (
                phase == "answered"
                and record.result is not None
                and record.result.proposed_repairs
                and self._proposed_repairs_sink is not None
            ):
                self._proposed_repairs_sink(node_id, record.result.proposed_repairs)
            return output
        except asyncio.CancelledError:
            await client.cancel_delegation(delegation_id)
            phase = "cancelled" if cancellation.cancelled else "failed"
            raise
        except RemoteGatewayError as exc:
            raise _error(exc.code, str(exc)) from exc
        finally:
            report(phase)


def _error(code: ErrorCode, message: str) -> ToolAdapterError:
    return ToolAdapterError(ToolError(code=code, message=message))


def register_delegate_tool(
    registry: ToolRegistry,
    platform: Platform,
    configuration: GatewayConfigurationService,
    local_node_id: NodeId,
    audit_sink: AuditSink,
    *,
    progress_sink: DelegationProgressSink | None = None,
    proposed_repairs_sink: ProposedRepairsSink | None = None,
) -> bool:
    """本机配置了带平台信息的对端时，注册委派工具；没有对端时不注册。"""
    view = configuration.view()
    peers = tuple(peer for peer in view.peers if peer.platform is not None)
    if not view.configured or not peers:
        return False

    def client_for(node_id: NodeId) -> DelegationClient:
        peer = configuration.resolve_delegation_peer(node_id)
        return FixedGatewayClient(
            peer.endpoint, peer.token, local_node_id, peer.node_id, audit_sink
        )

    registry.register(
        delegate_tool_definition(peers, platform),
        DelegateToNodeAdapter(
            client_for, progress_sink=progress_sink, proposed_repairs_sink=proposed_repairs_sink
        ),
    )
    return True
