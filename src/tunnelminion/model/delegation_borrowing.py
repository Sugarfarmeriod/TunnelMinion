"""处理委派时自动借用委派方的模型。

被委派的电脑既没有配置模型、也没有借用别的电脑的模型时，为了这一次委派临时借用发起委派那台电脑的
模型来回答：

- 只借同一机主的电脑（`relationship == "mine"`）；朋友的电脑不自动借。
- 委派方允不允许借、额度够不够，由委派方自己的网关按现有借用规则判断，用量记在委派方给这台电脑的
  每日额度里。委派方的模型本身是借来的时，它不会转借，这次委派照常报“还没有配置模型”。
- 只用于这一次委派，不写进这台电脑的模型配置。
- 请求头里标明用途，委派方的网关据此在日志里写明“为委派自动借用”。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.gateway.client import FixedGatewayClient
from tunnelminion.gateway.configuration import GatewayToolPeer
from tunnelminion.gateway.contracts import DELEGATION_MODEL_PURPOSE
from tunnelminion.model.contracts import ModelProvider
from tunnelminion.model.remote import RemoteModelProvider
from tunnelminion.tools.audit import AuditSink


class CallerModelGateway(Protocol):
    """借用委派方模型需要的网关信息。"""

    def relationship(self, node_id: NodeId) -> str: ...

    def resolve_model_peer(self, node_id: NodeId) -> GatewayToolPeer: ...


def caller_model_provider_factory(
    gateway: CallerModelGateway, node_id: NodeId, audit: AuditSink
) -> Callable[[NodeId], ModelProvider | None]:
    """返回“借委派方模型”的提供方工厂；不该借或借不了时返回 None。"""

    def provider(caller: NodeId) -> ModelProvider | None:
        if gateway.relationship(caller) != "mine":
            return None
        try:
            peer = gateway.resolve_model_peer(caller)
        except (KeyError, RuntimeError):
            return None
        client = FixedGatewayClient(
            peer.endpoint,
            peer.token,
            node_id,
            peer.node_id,
            audit,
            model_purpose=DELEGATION_MODEL_PURPOSE,
        )
        return RemoteModelProvider(client, node_id)

    return provider
