"""批准后的本机执行、验证和收场；不经过模型。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path

from tunnelminion.domain.identifiers import OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus, transition_operation
from tunnelminion.repair.contracts import (
    REPAIR_ACTIVE_STATUSES,
    REPAIR_RATE_LIMIT,
    REPAIR_RATE_WINDOW_SECONDS,
    ContainerRepairTarget,
    ContainerRuntime,
    ContainerSnapshot,
    HostInspector,
    LocalVerifier,
    ProcessLauncher,
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
)
from tunnelminion.repair.eligibility import (
    AUTHORIZATION_EXPIRED_ERROR,
    RepairRefusal,
    check_hidden,
    check_python,
    read_containers,
)

_FAILURE_NEXT_STEP = "看看日志要点；Agent 不会自动重试。"
_UNCERTAIN_NEXT_STEP = "请检查一下这个服务现在的状态。"


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
    ) -> None:
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
                for running in (False, True):
                    ids = tuple(item.container_id for item in items if item.running is running)
                    if not ids:
                        continue
                    command = (
                        await self._containers.restart(ids)
                        if running
                        else await self._containers.start(ids)
                    )
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
                                message="Docker 没能启动这些容器。",
                                next_step=_FAILURE_NEXT_STEP,
                            ),
                            RepairCleanupResult.NOTHING_TO_UNDO,
                            "容器修复失败后不再动它。",
                        )
            else:
                try:
                    spawned = self._launcher.launch(
                        target.launch, log_path=self._log_dir / f"{operation_id}.log"
                    )
                except OSError:
                    return self._rollback(
                        record,
                        RepairError(
                            code=RepairErrorCode.EXECUTION_FAILED,
                            message="脚本没能启动。",
                            next_step=_FAILURE_NEXT_STEP,
                        ),
                        RepairCleanupResult.NOTHING_TO_UNDO,
                        "脚本没有启动，不需要收场。",
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
            error = RepairError(
                code=RepairErrorCode.VERIFICATION_FAILED,
                message="脚本拉起来了，但端口一直没起来。",
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

    async def _verify(self, record: RepairRecord) -> RepairVerification:
        target = record.plan.target
        limit = (
            self._container_verify_seconds
            if isinstance(target, ContainerRepairTarget)
            else self._python_verify_seconds
        )
        started = self._clock()
        elapsed = 0.0
        web_checks: dict[int, RepairCheck] = {}
        items: tuple[ContainerSnapshot, ...] = ()
        while True:
            checks: list[RepairCheck] = []
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
            if isinstance(target, PythonRepairTarget):
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
