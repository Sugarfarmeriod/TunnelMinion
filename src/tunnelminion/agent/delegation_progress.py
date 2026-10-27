"""委派的公开进度，只携带身份与阶段。"""

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from tunnelminion.domain.identifiers import DelegationId, NodeId
from tunnelminion.tools.contracts import ToolCallContext

DelegationPhase = Literal["submitted", "investigating", "answered", "failed", "cancelled"]


class DelegationProgress(BaseModel):
    """不含问题或远端证据的委派进度。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    delegation_id: DelegationId
    peer_node_id: NodeId
    phase: DelegationPhase


DelegationProgressSink = Callable[[ToolCallContext, DelegationProgress], None]
