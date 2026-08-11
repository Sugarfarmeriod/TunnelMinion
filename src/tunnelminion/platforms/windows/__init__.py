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
from tunnelminion.platforms.windows.path_probe import WindowsPathProbe

__all__ = [
    "DockerServicesAdapter",
    "NetworkListenersAdapter",
    "NodeSummaryAdapter",
    "ProcessSummaryAdapter",
    "ServiceReachabilityAdapter",
    "WindowsPathProbe",
    "WireGuardStatusAdapter",
    "register_windows_tools",
]
