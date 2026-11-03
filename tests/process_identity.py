"""测试期间产品代码看到的“本进程号”。

产品代码会跳过本进程自己的监听和服务。测试里的假进程号如果恰好等于测试进程的真实进程号，
结果就会随机器变化（Windows 进程号都是 4 的倍数，CI 上撞到过 2024）。测试期间把这些模块看到的
本进程号固定成 `OWN_PID`，任何假进程号都不会和它相撞；要验证“跳过本进程”的测试直接用 `OWN_PID`。
"""

from __future__ import annotations

import os

# 大于 macOS 最大进程号且不是 4 的倍数，不可能是真实进程，也不和测试里写死的假进程号重复。
OWN_PID = 4_194_301

# 用 `os.getpid()` 判断“是不是本进程”的产品模块。
OWN_PID_MODULES = (
    "tunnelminion.agent.service_observation",
    "tunnelminion.app",
    "tunnelminion.gateway.services",
    "tunnelminion.macos_app",
    "tunnelminion.mcp_server",
    "tunnelminion.platforms.program_name",
    "tunnelminion.platforms.python_entrypoint",
    "tunnelminion.platforms.windows.adapters",
    "tunnelminion.repair.launch_records",
    "tunnelminion.web.service_map",
)


class OsWithFixedPid:
    """除 `getpid` 固定返回 `OWN_PID` 外，其余属性都转给真实的 `os` 模块。"""

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)

    @staticmethod
    def getpid() -> int:
        return OWN_PID
