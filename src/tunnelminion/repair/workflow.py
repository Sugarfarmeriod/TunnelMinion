"""批准后的本机执行、验证和收场；不经过模型。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path

from tunnelminion.domain.identifiers import OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus, transition_operation
from tunnelminion.repair.compose_order import (
    COMPOSE_READY_SECONDS,
    container_steps,
    wait_until_ready,
)
from tunnelminion.repair.contracts import (
    REPAIR_ACTIVE_STATUSES,
    REPAIR_RATE_LIMIT,
    REPAIR_RATE_WINDOW_SECONDS,
    ContainerRepairTarget,
    ContainerRuntime,
    ContainerSnapshot,
    HostInspector,
    LaunchAgentJob,
    LaunchAgentRepairTarget,
    LaunchAgentRuntime,
    LaunchRecord,
    LocalVerifier,
    ProcessLauncher,
    ProgramRepairTarget,
    PythonRepairTarget,
    RepairAuditAction,
    RepairCheck,
    RepairCheckName,
    RepairClaimResult,
    RepairCleanup,
    RepairCleanupResult,
    RepairError,
    RepairErrorCode,
    RepairExecution,
    RepairRecord,
    RepairStore,
    RepairVerification,
    StuckProgramRepairTarget,
    WindowsServiceRepairTarget,
    WindowsServiceRuntime,
)
from tunnelminion.repair.eligibility import (
    AUTHORIZATION_EXPIRED_ERROR,
    RepairRefusal,
    check_hidden,
    check_launch_agent,
    check_program,
    check_python,
    check_windows_service,
    check_windows_service_runtime,
    find_stuck_process,
    read_containers,
)
from tunnelminion.repair.launch_agents import UnsupportedLaunchAgents
from tunnelminion.repair.planning import NOT_STUCK_ERROR
from tunnelminion.repair.windows_services import UnsupportedWindowsServices

_FAILURE_NEXT_STEP = "看看日志要点；Agent 不会自动重试。"
_UNCERTAIN_NEXT_STEP = "请检查一下这个服务现在的状态。"
_LAUNCH_AGENT_LEFT_ALONE = "后台服务归 macOS 管，修复失败后 Agent 不会再动它。"
_WINDOWS_SERVICE_LEFT_ALONE = "Windows 服务归系统的服务管理管，修复失败后 Agent 不会再动它。"
_SERVICE_CHANGED = RepairError(
    code=RepairErrorCode.SERVICE_CHANGED,
    message="情况变了：服务和批准时看到的不一样，Agent 没有动手。",
)


class RepairWorkflow:
    def __init__(
        self,
        store: RepairStore,
        containers: ContainerRuntime,
        launcher: ProcessLauncher,
        host: HostInspector,
        verifier: LocalVerifier,
        marks: Callable[[], Mapping[str, ServiceMark]],
        log_dir: Path,
        clock: Callable[[], datetime],
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        container_verify_seconds: float = 60,
        python_verify_seconds: float = 30,
        interrupted_after_seconds: float = 900,
        launch_agents: LaunchAgentRuntime | None = None,
        windows_services: WindowsServiceRuntime | None = None,
        is_stuck: Callable[[str], bool] = lambda _key: False,
        stuck_grace_seconds: float = 10,
        service_stop_seconds: float = 30,
    ) -> None:
        self._launch_agents = launch_agents or UnsupportedLaunchAgents()
        self._windows_services = windows_services or UnsupportedWindowsServices()
        self._is_stuck = is_stuck
        self._stuck_grace_seconds = stuck_grace_seconds
        self._service_stop_seconds = service_stop_seconds
        self._store = store
        self._containers = containers
        self._launcher = launcher
        self._host = host
        self._verifier = verifier
        self._marks = marks
        self._log_dir = log_dir
        self._clock = clock
        self._sleep = sleep
        self._container_verify_seconds = container_verify_seconds
        self._python_verify_seconds = python_verify_seconds
        self._interrupted_after_seconds = interrupted_after_seconds

    def _event(self, record: RepairRecord, action: RepairAuditAction, detail: str) -> RepairRecord:
        for offset in range(0, len(detail), 2_000):
            record = record.with_event(
                action, detail[offset : offset + 2_000], actor="repair-workflow", at=self._clock()
            )
        return record

    def _transition(
        self,
        record: RepairRecord,
        status: OperationStatus,
        action: RepairAuditAction,
        detail: str,
    ) -> RepairRecord:
        record = transition_operation(record, status, reason=detail, occurred_at=self._clock())
        record = self._event(record, action, detail)
        self._store.put(record)
        return record

    def _expire(self, record: RepairRecord) -> RepairRecord:
        return self._transition(
            record.model_copy(update={"error": AUTHORIZATION_EXPIRED_ERROR}),
            OperationStatus.AUTHORIZATION_EXPIRED,
            RepairAuditAction.EXPIRED,
            AUTHORIZATION_EXPIRED_ERROR.message,
        )

    async def execute(self, operation_id: OperationId) -> RepairRecord:
        record = self._store.get(operation_id)
        if record is None:
            raise KeyError(operation_id)
        if record.status is not OperationStatus.AUTHORIZED:
            return record
        claimed = False
        try:
            now = self._clock()
            authorization = record.authorization
            if authorization is None or authorization.expires_at is None:
                raise ValueError("authorization")
            if authorization.expires_at <= now:
                return self._expire(record)
            target = record.plan.target
            items: tuple[ContainerSnapshot, ...] = ()
            try:
                check_hidden(self._marks().get(record.plan.service_key))
                if isinstance(target, ContainerRepairTarget):
                    items = await read_containers(
                        self._containers,
                        compose_project=target.compose_project,
                        container_name=target.container_name,
                    )
                    if {item.container_id for item in items} != {
                        item.container_id for item in target.containers
                    }:
                        raise RepairRefusal(
                            RepairError(
                                code=RepairErrorCode.SERVICE_CHANGED,
                                message="情况变了：容器和批准时看到的不一样，Agent 没有动手。",
                            )
                        )
                elif isinstance(target, LaunchAgentRepairTarget):
                    if target.stuck and not self._is_stuck(record.plan.service_key):
                        raise RepairRefusal(NOT_STUCK_ERROR)
                    job = await check_launch_agent(
                        target.label,
                        target.ports,
                        self._launch_agents,
                        self._host,
                        stuck=target.stuck,
                    )
                    if (job.uid, job.plist_path, job.plist_sha256) != (
                        target.uid,
                        target.plist_path,
                        target.plist_sha256,
                    ):
                        raise RepairRefusal(
                            RepairError(
                                code=RepairErrorCode.SERVICE_CHANGED,
                                message=(
                                    "情况变了：后台服务的配置文件和批准时不一样，Agent 没有动手。"
                                ),
                            )
                        )
                elif isinstance(target, ProgramRepairTarget):
                    check_program(target.launch, self._host)
                elif isinstance(target, StuckProgramRepairTarget):
                    if not self._is_stuck(record.plan.service_key):
                        raise RepairRefusal(NOT_STUCK_ERROR)
                    if isinstance(target.launch, LaunchRecord):
                        check_python(target.launch, self._host, ports_free=False)
                    else:
                        check_program(target.launch, self._host, ports_free=False)
                    pid, started_at = find_stuck_process(target.launch, self._host)
                    if (
                        pid != target.process_id
                        or abs((started_at - target.process_started_at).total_seconds()) > 1
                    ):
                        raise RepairRefusal(_SERVICE_CHANGED)
                elif isinstance(target, WindowsServiceRepairTarget):
                    check_windows_service_runtime(self._windows_services)
                    info = self._windows_services.inspect(target.service_name)
                    if (
                        info is None
                        or info.binary_path != target.binary_path
                        or info.running is not target.restart
                    ):
                        raise RepairRefusal(_SERVICE_CHANGED)
                    stuck = self._is_stuck(record.plan.service_key)
                    if target.restart and not stuck:
                        raise RepairRefusal(NOT_STUCK_ERROR)
                    check_windows_service(info, stuck=stuck, ports=target.ports, host=self._host)
                else:
                    check_python(target.launch, self._host)
            except RepairRefusal as exc:
                current = self._store.get(operation_id)
                if current is not None and current.status is not OperationStatus.AUTHORIZED:
                    return current
                error = exc.error.model_copy(
                    update={"next_step": "情况变了，让 Agent 重新看一下。"}
                )
                return self._transition(
                    record.model_copy(update={"error": error}),
                    OperationStatus.CANCELLED,
                    RepairAuditAction.PRECHECK_FAILED,
                    error.message,
                )
            now = self._clock()
            if authorization.expires_at <= now:
                return self._expire(record)
            self.recover_interrupted(now)
            record = self._event(
                record, RepairAuditAction.PRECHECK_PASSED, record.plan.action_summary
            )
            executing = transition_operation(
                record.model_copy(update={"execution": RepairExecution(started_at=now)}),
                OperationStatus.EXECUTING,
                reason=record.plan.action_summary,
                occurred_at=self._clock(),
            )
            result = self._store.claim_execution(
                executing,
                rate_window_start=now - timedelta(seconds=REPAIR_RATE_WINDOW_SECONDS),
                rate_limit=REPAIR_RATE_LIMIT,
            )
            if result is RepairClaimResult.STATE_CONFLICT:
                return self._store.get(operation_id) or record
            if result is not RepairClaimResult.CLAIMED:
                error = (
                    RepairError(
                        code=RepairErrorCode.BUSY,
                        message="这台电脑正在执行另一个修复，请等它结束再试。",
                    )
                    if result is RepairClaimResult.BUSY
                    else RepairError(
                        code=RepairErrorCode.RATE_LIMITED,
                        message="这个服务 1 小时内已经修了 3 次，先停一停，可能有别的问题。",
                    )
                )
                return self._transition(
                    record.model_copy(update={"error": error}),
                    OperationStatus.CANCELLED,
                    RepairAuditAction.FINISHED,
                    error.message,
                )
            record = executing
            claimed = True
            execution = executing.execution
            assert execution is not None
            if isinstance(target, ContainerRepairTarget):
                steps, _ = container_steps(items, compose=target.compose_project is not None)
                for step in steps:
                    run = {
                        "start": self._containers.start,
                        "restart": self._containers.restart,
                        "stop": self._containers.stop,
                    }[step.action]
                    command = await run(step.container_ids)
                    execution = execution.model_copy(
                        update={"commands": (*execution.commands, command)}
                    )
                    record = self._event(
                        record.model_copy(update={"execution": execution}),
                        RepairAuditAction.COMMAND_EXECUTED,
                        " ".join(command.argv),
                    )
                    self._store.put(record)
                    if command.exit_code != 0:
                        return self._rollback(
                            record,
                            RepairError(
                                code=RepairErrorCode.EXECUTION_FAILED,
                                message="Docker 没能停下这些容器。"
                                if step.action == "stop"
                                else "Docker 没能启动这些容器。",
                                next_step=_FAILURE_NEXT_STEP,
                            ),
                            RepairCleanupResult.NOTHING_TO_UNDO,
                            "容器修复失败后不再动它。",
                        )
                    if not step.wait_ready:
                        continue
                    pending = await wait_until_ready(
                        self._containers,
                        compose_project=target.compose_project,
                        container_name=target.container_name,
                        waiting=step.containers,
                        clock=self._clock,
                        sleep=self._sleep,
                    )
                    if pending is not None:
                        return self._rollback(
                            record,
                            RepairError(
                                code=RepairErrorCode.EXECUTION_FAILED,
                                message=(
                                    f"{pending.name} 等了 {COMPOSE_READY_SECONDS:.0f} 秒还没准备好"
                                    f"（{pending.health or pending.status}），"
                                    "没有接着启动依赖它的容器。"
                                )[:500],
                                next_step=_FAILURE_NEXT_STEP,
                            ),
                            RepairCleanupResult.NOTHING_TO_UNDO,
                            "容器修复失败后不再动它。",
                        )
            elif isinstance(target, WindowsServiceRepairTarget):
                failed = await self._run_windows_service(record, target)
                if isinstance(failed, RepairRecord):
                    return failed
                record = failed[0]
                execution = failed[1]
            elif isinstance(target, LaunchAgentRepairTarget):
                command = await self._launch_agents.kickstart(target.label, kill=target.stuck)
                execution = execution.model_copy(
                    update={"commands": (*execution.commands, command)}
                )
                record = self._event(
                    record.model_copy(update={"execution": execution}),
                    RepairAuditAction.COMMAND_EXECUTED,
                    " ".join(command.argv),
                )
                self._store.put(record)
                if command.exit_code != 0:
                    return self._rollback(
                        record,
                        RepairError(
                            code=RepairErrorCode.EXECUTION_FAILED,
                            message="macOS 没能启动这个后台服务。",
                            next_step=_FAILURE_NEXT_STEP,
                        ),
                        RepairCleanupResult.NOTHING_TO_UNDO,
                        _LAUNCH_AGENT_LEFT_ALONE,
                    )
            else:
                if isinstance(target, StuckProgramRepairTarget):
                    forcibly = self._launcher.end_stuck(
                        target.process_id,
                        target.process_started_at,
                        grace_seconds=self._stuck_grace_seconds,
                    )
                    execution = execution.model_copy(
                        update={
                            "ended_process_id": target.process_id,
                            "ended_forcibly": forcibly,
                        }
                    )
                    record = self._event(
                        record.model_copy(update={"execution": execution}),
                        RepairAuditAction.PROCESS_ENDED,
                        f"进程 {target.process_id}："
                        + (
                            "没能结束"
                            if forcibly is None
                            else "礼貌结束后等不到退出，已强制结束"
                            if forcibly
                            else "已结束"
                        ),
                    )
                    self._store.put(record)
                    if forcibly is None:
                        return self._rollback(
                            record,
                            RepairError(
                                code=RepairErrorCode.EXECUTION_FAILED,
                                message="没能结束卡住的进程，Agent 没有重新运行它。",
                                next_step=_UNCERTAIN_NEXT_STEP,
                            ),
                            RepairCleanupResult.NOTHING_TO_UNDO,
                            "卡住的进程没能结束，没有拉起新的进程。",
                        )
                try:
                    spawned = self._launcher.launch(
                        target.launch, log_path=self._log_dir / f"{operation_id}.log"
                    )
                except OSError:
                    return self._rollback(
                        record,
                        RepairError(
                            code=RepairErrorCode.EXECUTION_FAILED,
                            message="程序没能启动。",
                            next_step=_FAILURE_NEXT_STEP,
                        ),
                        RepairCleanupResult.NOTHING_TO_UNDO,
                        "程序没有启动，不需要收场。",
                    )
                execution = execution.model_copy(update={"spawned": spawned})
                record = self._event(
                    record.model_copy(update={"execution": execution}),
                    RepairAuditAction.PROCESS_SPAWNED,
                    spawned.log_path,
                )
                self._store.put(record)
            execution = execution.model_copy(update={"finished_at": self._clock()})
            record = self._transition(
                record.model_copy(update={"execution": execution}),
                OperationStatus.VERIFYING,
                RepairAuditAction.VERIFIED,
                record.plan.verification_summary,
            )
            verification = await self._verify(record)
            record = record.model_copy(update={"verification": verification})
            record = self._event(
                record, RepairAuditAction.VERIFIED, record.plan.verification_summary
            )
            self._store.put(record)
            if verification.passed:
                return self._transition(
                    record, OperationStatus.SUCCEEDED, RepairAuditAction.FINISHED, "修好了。"
                )
            if isinstance(target, ContainerRepairTarget):
                return self._rollback(
                    record,
                    RepairError(
                        code=RepairErrorCode.VERIFICATION_FAILED,
                        message="容器重启了，但服务还是没起来。",
                        next_step=_FAILURE_NEXT_STEP,
                    ),
                    RepairCleanupResult.NOTHING_TO_UNDO,
                    "容器修复失败后不再动它，保持现在的状态。",
                )
            if isinstance(target, LaunchAgentRepairTarget):
                return self._rollback(
                    record,
                    RepairError(
                        code=RepairErrorCode.VERIFICATION_FAILED,
                        message="后台服务重新启动了，但服务还是没起来。",
                        next_step=_FAILURE_NEXT_STEP,
                    ),
                    RepairCleanupResult.NOTHING_TO_UNDO,
                    _LAUNCH_AGENT_LEFT_ALONE,
                )
            if isinstance(target, WindowsServiceRepairTarget):
                return self._rollback(
                    record,
                    RepairError(
                        code=RepairErrorCode.VERIFICATION_FAILED,
                        message="Windows 服务启动了，但服务还是没起来。",
                        next_step=_FAILURE_NEXT_STEP,
                    ),
                    RepairCleanupResult.NOTHING_TO_UNDO,
                    _WINDOWS_SERVICE_LEFT_ALONE,
                )
            error = RepairError(
                code=RepairErrorCode.VERIFICATION_FAILED,
                message="程序拉起来了，但端口一直没起来。",
                next_step=_FAILURE_NEXT_STEP,
            )
            record = self._transition(
                record.model_copy(update={"error": error}),
                OperationStatus.ROLLING_BACK,
                RepairAuditAction.CLEANED_UP,
                error.message,
            )
            assert execution.spawned is not None
            if not self._launcher.is_alive(execution.spawned):
                result = RepairCleanupResult.SPAWNED_ALREADY_EXITED
                detail = "这次拉起的进程已经自己退出了。"
            elif self._launcher.stop(execution.spawned):
                result = RepairCleanupResult.STOPPED_SPAWNED
                detail = "已经停掉这次拉起的进程，回到修复前的样子。"
            else:
                result = RepairCleanupResult.STOP_FAILED
                detail = "没能停掉这次拉起的进程，请手动检查。"
            return self._finish_cleanup(record, result, detail)
        except Exception:
            try:
                current = self._store.get(operation_id)
            except Exception:
                current = None
            if (
                not claimed
                and current is not None
                and current.status is not OperationStatus.AUTHORIZED
            ):
                return current
            record = current or record
            error = RepairError(
                code=RepairErrorCode.EXECUTION_FAILED,
                message="修复中途出错了，结果不确定。",
                next_step=_UNCERTAIN_NEXT_STEP,
            )
            try:
                return self._rollback(record, error, RepairCleanupResult.STOP_FAILED, error.message)
            except Exception:
                return record.model_copy(update={"error": error})

    async def _run_windows_service(
        self, record: RepairRecord, target: WindowsServiceRepairTarget
    ) -> RepairRecord | tuple[RepairRecord, RepairExecution]:
        """卡住的先停、等它停下再启动；停了的直接启动。失败时返回收场后的记录。"""
        execution = record.execution
        assert execution is not None
        actions = (
            (self._windows_services.stop, self._windows_services.start)
            if target.restart
            else (self._windows_services.start,)
        )
        for index, action in enumerate(actions):
            command = await action(target.service_name)
            execution = execution.model_copy(update={"commands": (*execution.commands, command)})
            record = self._event(
                record.model_copy(update={"execution": execution}),
                RepairAuditAction.COMMAND_EXECUTED,
                " ".join(command.argv),
            )
            self._store.put(record)
            stopped = command.exit_code == 0
            if stopped and target.restart and index == 0:
                stopped = await self._wait_service_stopped(target.service_name)
            if not stopped:
                return self._rollback(
                    record,
                    RepairError(
                        code=RepairErrorCode.EXECUTION_FAILED,
                        message="Windows 没能"
                        + ("停下" if target.restart and index == 0 else "启动")
                        + "这个服务。",
                        next_step=_FAILURE_NEXT_STEP,
                    ),
                    RepairCleanupResult.NOTHING_TO_UNDO,
                    _WINDOWS_SERVICE_LEFT_ALONE,
                )
        return record, execution

    async def _wait_service_stopped(self, name: str) -> bool:
        elapsed = 0.0
        while True:
            info = self._windows_services.inspect(name)
            if info is not None and not info.running:
                return True
            if elapsed >= self._service_stop_seconds:
                return False
            await self._sleep(1)
            elapsed += 1

    async def _verify(self, record: RepairRecord) -> RepairVerification:
        target = record.plan.target
        limit = (
            self._container_verify_seconds
            if isinstance(target, ContainerRepairTarget | WindowsServiceRepairTarget)
            else self._python_verify_seconds
        )
        started = self._clock()
        elapsed = 0.0
        web_checks: dict[int, RepairCheck] = {}
        items: tuple[ContainerSnapshot, ...] = ()
        job: LaunchAgentJob | None = None
        while True:
            checks: list[RepairCheck] = []
            if isinstance(target, LaunchAgentRepairTarget):
                inspected = await self._launch_agents.inspect(target.label)
                job = inspected if isinstance(inspected, LaunchAgentJob) else None
                running = job is not None and job.pid is not None
                checks.append(
                    RepairCheck(
                        name=RepairCheckName.LAUNCH_AGENT_RUNNING,
                        passed=running,
                        detail="后台服务在运行。" if running else "后台服务没在运行。",
                    )
                )
            if isinstance(target, WindowsServiceRepairTarget):
                info = self._windows_services.inspect(target.service_name)
                running = info is not None and info.running
                checks.append(
                    RepairCheck(
                        name=RepairCheckName.WINDOWS_SERVICE_RUNNING,
                        passed=running,
                        detail="Windows 服务在运行。" if running else "Windows 服务没在运行。",
                    )
                )
            if isinstance(target, ContainerRepairTarget):
                observed = await self._containers.list_containers(
                    compose_project=target.compose_project, container_name=target.container_name
                )
                items = observed or ()
                by_id = {item.container_id: item for item in items}
                failed = [
                    by_id.get(item.container_id, item)
                    for item in target.containers
                    if item.container_id not in by_id or not by_id[item.container_id].running
                ]
                detail = "所有容器都在运行。"
                if failed:
                    detail = f"{failed[0].name} 没在运行（{failed[0].status}）。"
                checks.append(
                    RepairCheck(
                        name=RepairCheckName.CONTAINER_RUNNING,
                        passed=not failed,
                        detail=detail[:500],
                    )
                )
            port_checks: list[RepairCheck] = []
            for port in target.ports:
                listening = await self._verifier.port_listening(port)
                port_checks.append(
                    RepairCheck(
                        name=RepairCheckName.PORT_LISTENING,
                        passed=listening,
                        detail=f"端口 {port} 在听。" if listening else f"端口 {port} 没在听。",
                    )
                )
            checks.extend(port_checks)
            if all(item.passed for item in port_checks):
                for port in target.ports:
                    if port not in web_checks:
                        code = await self._verifier.web_status(port)
                        detail = (
                            "这个端口不是网页，只确认了端口在听。"
                            if code is None
                            else f"首页能打开（HTTP {code}）。"
                            if code < 500
                            else f"首页返回错误（HTTP {code}）。"
                        )
                        web_checks[port] = RepairCheck(
                            name=RepairCheckName.WEB_PAGE,
                            passed=code is None or code < 500,
                            detail=detail,
                        )
                checks.extend(web_checks.values())
            alive = True
            if isinstance(
                target, PythonRepairTarget | ProgramRepairTarget | StuckProgramRepairTarget
            ):
                assert record.execution is not None and record.execution.spawned is not None
                alive = self._launcher.is_alive(record.execution.spawned)
                if not alive:
                    checks[0] = checks[0].model_copy(
                        update={"passed": False, "detail": f"端口 {target.ports[0]} 没在听。"}
                    )
            passed = all(item.passed for item in checks)
            if passed or not alive or elapsed >= limit:
                break
            delay = min(1, limit - elapsed)
            await self._sleep(delay)
            elapsed = max(elapsed + delay, (self._clock() - started).total_seconds())
        excerpt: str | None = None
        if not passed:
            if isinstance(target, ContainerRepairTarget):
                failed_container = next(
                    (item for item in items if not item.running),
                    items[0] if items else target.containers[0],
                )
                excerpt = await self._containers.logs_tail(failed_container.container_id, lines=40)
            elif isinstance(target, LaunchAgentRepairTarget):
                parts = [self._launch_agents.log_tail(job, lines=40)] if job is not None else []
                if job is not None and job.last_exit_code is not None:
                    parts.append(f"launchd 记的上次退出码：{job.last_exit_code}")
                excerpt = "\n".join(part for part in parts if part)
            elif isinstance(target, WindowsServiceRepairTarget):
                excerpt = None
            else:
                assert record.execution is not None and record.execution.spawned is not None
                excerpt = self._launcher.log_tail(Path(record.execution.spawned.log_path), lines=40)
        return RepairVerification(
            passed=passed,
            checks=tuple(checks),
            log_excerpt=excerpt[:4_000] if excerpt is not None else None,
            verified_at=self._clock(),
        )

    def _rollback(
        self, record: RepairRecord, error: RepairError, result: RepairCleanupResult, detail: str
    ) -> RepairRecord:
        record = record.model_copy(update={"error": error})
        if record.status is not OperationStatus.ROLLING_BACK:
            record = self._transition(
                record, OperationStatus.ROLLING_BACK, RepairAuditAction.CLEANED_UP, error.message
            )
        return self._finish_cleanup(record, result, detail)

    def _finish_cleanup(
        self, record: RepairRecord, result: RepairCleanupResult, detail: str
    ) -> RepairRecord:
        record = record.model_copy(
            update={
                "cleanup": RepairCleanup(result=result, detail=detail, completed_at=self._clock())
            }
        )
        return self._transition(
            record,
            OperationStatus.CLEANUP_FAILED
            if result is RepairCleanupResult.STOP_FAILED
            else OperationStatus.ROLLED_BACK,
            RepairAuditAction.CLEANED_UP,
            detail,
        )

    def recover_interrupted(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._interrupted_after_seconds)
        for record in self._store.list_all():
            if record.status in REPAIR_ACTIVE_STATUSES and record.updated_at < cutoff:
                error = RepairError(
                    code=RepairErrorCode.INTERRUPTED,
                    message="上次修复中途被打断了，结果不确定。",
                    next_step=_UNCERTAIN_NEXT_STEP,
                )
                self._rollback(record, error, RepairCleanupResult.STOP_FAILED, error.message)
