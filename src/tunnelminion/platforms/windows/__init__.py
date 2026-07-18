"""Windows 节点的只读系统能力。"""

from tunnelminion.platforms.windows.adapters import (
    DockerServicesAdapter,
    NetworkListenersAdapter,
    NodeSummaryAdapter,
    ProcessSummaryAdapter,
    ServiceReachabilityAdapter,
    WireGuardStatusAdapter,
)
from tunnelminion.platforms.windows.definitions import register_windows_tools

__all__ = [
    "DockerServicesAdapter",
    "NetworkListenersAdapter",
    "NodeSummaryAdapter",
    "ProcessSummaryAdapter",
    "ServiceReachabilityAdapter",
    "WireGuardStatusAdapter",
    "register_windows_tools",
]
