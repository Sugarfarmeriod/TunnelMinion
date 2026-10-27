"""供原对话展示的修复结论，不回传命令和路径。"""

from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.repair.contracts import RepairCheckName, RepairErrorCode, RepairRecord

_CHECKS = {
    RepairCheckName.CONTAINER_RUNNING: "容器运行",
    RepairCheckName.PORT_LISTENING: "端口监听",
    RepairCheckName.WEB_PAGE: "首页访问",
}
_ERRORS = {
    RepairErrorCode.NOT_ELIGIBLE: "这个服务不符合修复条件",
    RepairErrorCode.PROTECTED_TARGET: "这是受保护的程序",
    RepairErrorCode.NO_LAUNCH_RECORD: "没有启动记录",
    RepairErrorCode.UNSUPPORTED_LAUNCH: "原来的启动方式不支持自动修复",
    RepairErrorCode.INTERPRETER_MISSING: "原来的 Python 解释器不在了",
    RepairErrorCode.ENTRY_MISSING: "脚本入口不在了",
    RepairErrorCode.WORKING_DIRECTORY_MISSING: "原来的工作目录不在了",
    RepairErrorCode.OTHER_ACCOUNT: "原来由别的账户运行",
    RepairErrorCode.PORT_IN_USE: "原来的端口被别的程序占了",
    RepairErrorCode.ALREADY_RUNNING: "脚本已经自己启动了，无需再修",
    RepairErrorCode.DOCKER_UNAVAILABLE: "Docker 没开",
    RepairErrorCode.CONTAINER_MISSING: "容器已经不存在了",
    RepairErrorCode.SERVICE_CHANGED: "执行前核对发现情况变了，没有动手",
    RepairErrorCode.BUSY: "这台电脑正在修另一个服务",
    RepairErrorCode.RATE_LIMITED: "这个服务一小时内的修复次数已用完",
    RepairErrorCode.EXECUTION_FAILED: "执行中途出错，结果还不能确认",
    RepairErrorCode.INTERRUPTED: "上次修复被打断，结果还不能确认",
}


def repair_result_text(record: RepairRecord) -> str:
    if record.status is OperationStatus.REJECTED:
        return "已取消。这次先不修，服务保持现在的样子。"
    if record.status is OperationStatus.AUTHORIZATION_EXPIRED:
        return "已过期。这次修复没有继续，需要的话请让 Agent 重新提出。"
    verification = record.verification
    if record.status is OperationStatus.SUCCEEDED:
        checks = (
            "、".join(
                dict.fromkeys(
                    _CHECKS[item.name]
                    for item in verification.checks
                    if item.name is not RepairCheckName.WEB_PAGE
                    or item.detail != "这个端口不是网页，只确认了端口在听。"
                )
            )
            if verification
            else "服务状态"
        )
        return f"修好了。已确认：{checks}正常。"
    reason = (
        _ERRORS.get(record.error.code, "执行后的确认没有通过")
        if record.error
        else "执行结果还不能确认"
    )
    if verification is not None:
        failed = "、".join(
            dict.fromkeys(_CHECKS[item.name] for item in verification.checks if not item.passed)
        )
        reason = f"卡在{failed}检查" if failed else reason
    message = f"没修好，{reason}。"
    if verification is not None and verification.log_excerpt:
        log = verification.log_excerpt.casefold()
        gist = next(
            (
                summary
                for terms, summary in (
                    (("permission denied", "access is denied"), "运行权限不足"),
                    (("modulenotfounderror", "no module named"), "缺少需要的模块"),
                    (("no such file", "filenotfounderror"), "需要的文件不在了"),
                    (("address already in use", "port is already allocated"), "端口被占用"),
                    (("connection refused",), "依赖的服务连接不上"),
                    (("timeout", "timed out"), "等待响应超时"),
                    (("out of memory", "memoryerror"), "可用内存不足"),
                )
                if any(term in log for term in terms)
            ),
            "服务启动失败，详细日志留在本机修复记录中",
        )
        message += f"日志要点：{gist}。"
    return message + "请检查服务当前状态，Agent 不会自动重试。"
