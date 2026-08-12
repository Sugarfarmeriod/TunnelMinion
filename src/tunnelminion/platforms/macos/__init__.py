"""macOS 只读平台适配层。"""

from tunnelminion.platforms.macos.definitions import register_macos_tools
from tunnelminion.platforms.macos.path_probe import MacOSPathProbe

__all__ = ["MacOSPathProbe", "register_macos_tools"]
