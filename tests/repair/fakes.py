"""不接触真实容器、监听端口或进程的修复测试替身。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock

from tests.repair.factories import NODE, NOW, container, launch_agent_job, launch_record, plan

from tunnelminion.domain.identifiers import OperationId
from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.operation.contracts import OperationStatus, transition_operation
from tunnelminion.operation.policy import AuthorizationService, OperationPolicy
from tunnelminion.repair.contracts import (
    REPAIR_ACTIVE_STATUSES,
    REPAIR_TERMINAL_STATUSES,
    AnyLaunchRecord,
    ContainerRuntime,
    ContainerSnapshot,
    HostInspector,
    LaunchAgentJob,
    LaunchAgentProblem,
    LaunchAgentRuntime,
    LaunchRecord,
    LaunchRecordStore,
    LocalVerifier,
    PortOwner,
    ProcessLauncher,
    RepairClaimResult,
    RepairCommand,
    RepairRecord,
    RepairStore,
    SpawnedProcess,
)
from tunnelminion.repair.definitions import register_repair_operations
from tunnelminion.repair.planning import RepairPlanner
from tunnelminion.repair.service import RepairService
from tunnelminion.repair.workflow import RepairWorkflow
from tunnelminion.tools.registry import ToolRegistry


class FakeClock:
    def __init__(self) -> None:
        self.now = NOW
        self.sleeps: list[float] = []
        self.on_sleep: Callable[[], None] = lambda: None

    def __call__(self) -> datetime:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += timedelta(seconds=seconds)
        self.on_sleep()


class MemoryRepairStore(RepairStore):
    def __init__(self) -> None:
        self.records: dict[str, RepairRecord] = {}
        self.history: list[RepairRecord] = []
        self.lock = Lock()

    def put(self, record: RepairRecord) -> None:
        self.records[str(record.plan.operation_id)] = record
        self.history.append(record)

    def get(self, operation_id: OperationId) -> RepairRecord | None:
        return self.records.get(str(operation_id))

    def get_by_idempotency_key(self, key: str) -> RepairRecord | None:
        return next(
            (
                item
                for item in self.list_all()
                if item.plan.idempotency_key == key and item.status not in REPAIR_TERMINAL_STATUSES
            ),
            None,
        )

    def list_all(self) -> tuple[RepairRecord, ...]:
        return tuple(
            sorted(self.records.values(), key=lambda item: item.plan.created_at, reverse=True)
        )

    def claim_execution(
        self, executing: RepairRecord, *, rate_window_start: datetime, rate_limit: int
    ) -> RepairClaimResult:
        with self.lock:
            current = self.get(executing.plan.operation_id)
            if current is None or current.status is not OperationStatus.AUTHORIZED:
                return RepairClaimResult.STATE_CONFLICT
            if any(item.status in REPAIR_ACTIVE_STATUSES for item in self.records.values()):
                return RepairClaimResult.BUSY
            count = sum(
                item.plan.service_key == executing.plan.service_key
                and item.execution is not None
                and item.execution.started_at >= rate_window_start
                for item in self.records.values()
            )
            if count >= rate_limit:
                return RepairClaimResult.RATE_LIMITED
            self.put(executing)
            return RepairClaimResult.CLAIMED


class MemoryLaunchRecordStore(LaunchRecordStore):
    def __init__(self) -> None:
        self.records: dict[str, AnyLaunchRecord] = {}

    def put(self, record: AnyLaunchRecord) -> None:
        self.records[record.service_key] = record

    def get(self, service_key: str) -> AnyLaunchRecord | None:
        return self.records.get(service_key)

    def list_all(self) -> tuple[AnyLaunchRecord, ...]:
        return tuple(self.records.values())


class FakeLaunchAgents(LaunchAgentRuntime):
    """不碰 launchctl 的后台服务替身；kickstart 成功后服务进入运行状态。"""

    def __init__(self) -> None:
        self.reason: str | None = None
        self.job: LaunchAgentJob | LaunchAgentProblem = launch_agent_job()
        self.responses: list[LaunchAgentJob | LaunchAgentProblem] = []
        self.labels: dict[int, str] = {}
        self.kickstarts: list[str] = []
        self.exit_code: int | None = 0
        self.stay_stopped = False
        self.log = "address already in use"
        self.error_on_labels = False

    def unsupported_reason(self) -> str | None:
        return self.reason

    async def labels_for_pids(self, pids: frozenset[int]) -> dict[int, str]:
        if self.error_on_labels:
            raise RuntimeError("fake")
        return {pid: label for pid, label in self.labels.items() if pid in pids}

    async def inspect(self, label: str) -> LaunchAgentJob | LaunchAgentProblem:
        return self.responses.pop(0) if self.responses else self.job

    async def kickstart(self, label: str) -> RepairCommand:
        self.kickstarts.append(label)
        if self.exit_code == 0 and not self.stay_stopped and isinstance(self.job, LaunchAgentJob):
            self.job = self.job.model_copy(update={"pid": 777})
        return RepairCommand(
            argv=("/bin/launchctl", "kickstart", f"gui/501/{label}"),
            exit_code=self.exit_code,
            started_at=NOW,
            finished_at=NOW,
        )

    def log_tail(self, job: LaunchAgentJob, *, lines: int) -> str:
        return self.log


class FakeContainers(ContainerRuntime):
    def __init__(self) -> None:
        self.items: tuple[ContainerSnapshot, ...] | None = (container(),)
        self.responses: list[tuple[ContainerSnapshot, ...] | None] = []
        self.queries: list[tuple[str | None, str | None]] = []
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.exit_codes: list[int | None] = []
        self.stay_stopped = False
        self.log = "startup failed"
        self.log_calls: list[tuple[str, int]] = []
        self.error_on: str | None = None
        # 启动成功后容器的健康状态；None 表示保持原样。
        self.start_health: str | None = None

    async def list_containers(
        self, *, compose_project: str | None, container_name: str | None
    ) -> tuple[ContainerSnapshot, ...] | None:
        if self.error_on == "list":
            raise RuntimeError("fake")
        self.queries.append((compose_project, container_name))
        return self.responses.pop(0) if self.responses else self.items

    def _command(self, action: str, ids: tuple[str, ...]) -> RepairCommand:
        if self.error_on == "command":
            raise RuntimeError("fake")
        self.calls.append((action, ids))
        code = self.exit_codes.pop(0) if self.exit_codes else 0
        if code == 0 and action == "stop":
            self.items = tuple(
                item.model_copy(update={"running": False, "status": "exited (0)"})
                if item.container_id in ids
                else item
                for item in self.items or ()
            )
        elif code == 0 and not self.stay_stopped:
            update: dict[str, object] = {"running": True, "status": "running"}
            if self.start_health is not None:
                update["health"] = self.start_health
            self.items = tuple(
                item.model_copy(update=update) if item.container_id in ids else item
                for item in self.items or ()
            )
        return RepairCommand(
            argv=("docker", action, *ids),
            exit_code=code,
            output_excerpt="docker failed" if code != 0 else "",
            started_at=NOW,
            finished_at=NOW,
        )

    async def start(self, container_ids: tuple[str, ...]) -> RepairCommand:
        return self._command("start", container_ids)

    async def restart(self, container_ids: tuple[str, ...]) -> RepairCommand:
        return self._command("restart", container_ids)

    async def stop(self, container_ids: tuple[str, ...]) -> RepairCommand:
        return self._command("stop", container_ids)

    async def logs_tail(self, container_id: str, *, lines: int) -> str:
        if self.error_on == "logs":
            raise RuntimeError("fake")
        self.log_calls.append((container_id, lines))
        return self.log


class FakeLauncher(ProcessLauncher):
    def __init__(self) -> None:
        self.calls: list[tuple[LaunchRecord, Path]] = []
        self.stopped: list[SpawnedProcess] = []
        self.alive = True
        self.stop_result = True
        self.log = "startup failed"
        self.log_calls: list[tuple[Path, int]] = []
        self.error: Exception | None = None
        self.error_on_stop = False

    def launch(self, record: LaunchRecord, *, log_path: Path) -> SpawnedProcess:
        self.calls.append((record, log_path))
        if self.error is not None:
            raise self.error
        return SpawnedProcess(pid=1234, started_at=NOW, log_path=str(log_path))

    def is_alive(self, spawned: SpawnedProcess) -> bool:
        return self.alive

    def stop(self, spawned: SpawnedProcess) -> bool:
        self.stopped.append(spawned)
        if self.error_on_stop:
            raise RuntimeError("fake")
        return self.stop_result

    def log_tail(self, log_path: Path, *, lines: int) -> str:
        self.log_calls.append((log_path, lines))
        return self.log


class FakeHost(HostInspector):
    def __init__(self) -> None:
        self.username = "me"
        self.owners: dict[int, PortOwner] = {}
        self.calls: list[tuple[int, LaunchRecord | None]] = []

    def current_username(self) -> str:
        return self.username

    def port_owner(self, port: int, launch: LaunchRecord | None = None) -> PortOwner | None:
        self.calls.append((port, launch))
        return self.owners.get(port)


class FakeVerifier(LocalVerifier):
    def __init__(self) -> None:
        self.listening = True
        self.status: int | None = 200
        self.ports: list[int] = []
        self.web_ports: list[int] = []
        self.error = False

    async def port_listening(self, port: int) -> bool:
        self.ports.append(port)
        if self.error:
            raise RuntimeError("fake")
        return self.listening

    async def web_status(self, port: int) -> int | None:
        self.web_ports.append(port)
        return self.status


def local_launch(tmp_path: Path, *, arguments: tuple[str, ...] = ("app.py",)) -> LaunchRecord:
    interpreter = tmp_path / "python.exe"
    interpreter.touch()
    (tmp_path / "app.py").touch()
    return launch_record(service_key="python:app.py@8765", arguments=arguments).model_copy(
        update={"interpreter": str(interpreter), "working_directory": str(tmp_path)}
    )


class EmptyPreauthorizations:
    def put(self, authorization: object) -> None:
        raise AssertionError("测试不使用预授权")

    def get(self, authorization_id: object) -> None:
        return None

    def list_all(self) -> tuple[()]:
        return ()

    def list_active(self, *, at: object) -> tuple[()]:
        return ()


class RepairHarness:
    def __init__(self, tmp_path: Path) -> None:
        self.clock = FakeClock()
        self.containers = FakeContainers()
        self.launcher = FakeLauncher()
        self.host = FakeHost()
        self.verifier = FakeVerifier()
        self.store = MemoryRepairStore()
        self.launch_records = MemoryLaunchRecordStore()
        self.marks: dict[str, ServiceMark] = {}
        self.registry = ToolRegistry()
        register_repair_operations(self.registry)
        self.launch_agents = FakeLaunchAgents()
        self.planner = RepairPlanner(
            NODE,
            lambda: self.marks,
            self.launch_records,
            self.containers,
            self.host,
            self.clock,
            launch_agents=self.launch_agents,
        )
        self.workflow = RepairWorkflow(
            self.store,
            self.containers,
            self.launcher,
            self.host,
            self.verifier,
            lambda: self.marks,
            tmp_path / "repair-logs",
            self.clock,
            self.clock.sleep,
            container_verify_seconds=2,
            python_verify_seconds=2,
            launch_agents=self.launch_agents,
        )
        self.authorization = AuthorizationService(
            self.store,
            EmptyPreauthorizations(),
            OperationPolicy(self.registry, EmptyPreauthorizations()),
        )
        self.service = RepairService(
            self.planner,
            self.workflow,
            self.store,
            self.authorization,
            self.clock,
            self.containers,
            self.host,
            self.launch_agents,
        )

    def authorized(self, record: RepairRecord | None = None) -> RepairRecord:
        record = record or RepairRecord.planned(
            plan().model_copy(update={"created_at": self.clock()}), actor="local-cli"
        )
        waiting = self.authorization.submit(record, at=self.clock())
        return self.service.approve(waiting.plan.operation_id, operator="local-cli")


def at_status(record: RepairRecord, status: OperationStatus) -> RepairRecord:
    for step in (
        OperationStatus.AWAITING_AUTHORIZATION,
        OperationStatus.AUTHORIZED,
        OperationStatus.EXECUTING,
        OperationStatus.VERIFYING,
        OperationStatus.ROLLING_BACK,
        OperationStatus.CLEANUP_FAILED,
    ):
        if record.status is status:
            break
        record = transition_operation(record, step, reason="测试", occurred_at=record.updated_at)
    return record
