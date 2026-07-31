"""managed node 监督、退避、停止与恢复测试。"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion.agent.managed_runtime import (
    FileManagedRuntimeCheckpointRepository,
    ManagedLoopPhase,
    ManagedLoopStatus,
    ManagedNodeRuntime,
    ManagedNodeRuntimeCheckpoint,
    ManagedRuntimeDomain,
    ManagedRuntimePhase,
    managed_node_lifespan,
)

NOW = datetime(2026, 7, 31, tzinfo=UTC)


class LoopFailure(RuntimeError):
    """携带稳定错误码的受控循环故障。"""

    def __init__(self, code: str, message: str = "secret detail") -> None:
        super().__init__(message)
        self.code = code


class FakeLoop:
    """可控制失败、提前退出和停止响应的后台域。"""

    def __init__(
        self,
        domain: ManagedRuntimeDomain,
        *,
        failures: int = 0,
        return_early: bool = False,
        ignore_stop: bool = False,
        checkpoint_failure: bool = False,
        invalid_error_code: bool = False,
    ) -> None:
        self.domain = domain
        self.failures = failures
        self.return_early = return_early
        self.ignore_stop = ignore_stop
        self.checkpoint_failure = checkpoint_failure
        self.invalid_error_code = invalid_error_code
        self.run_count = 0
        self.active = 0
        self.max_active = 0
        self.checkpoint_count = 0
        self.started = asyncio.Event()
        self.never = asyncio.Event()

    async def run(self, stop: asyncio.Event) -> None:
        self.run_count += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            if self.run_count <= self.failures:
                code = "bad-code-secret" if self.invalid_error_code else "fake_failure"
                raise LoopFailure(code)
            if self.return_early:
                return
            if self.ignore_stop:
                await self.never.wait()
            else:
                await stop.wait()
        finally:
            self.active -= 1

    async def checkpoint(self) -> None:
        self.checkpoint_count += 1
        if self.checkpoint_failure:
            raise RuntimeError("checkpoint secret detail")


def runtime(
    tmp_path: Path,
    loops: tuple[FakeLoop, ...],
    **updates: object,
) -> ManagedNodeRuntime:
    """构造使用极短测试预算的监督器。"""
    values: dict[str, object] = {
        "max_restarts": 2,
        "base_backoff_seconds": 0.001,
        "max_backoff_seconds": 0.002,
        "stop_timeout_seconds": 0.02,
        "clock": lambda: NOW,
    }
    values.update(updates)
    return ManagedNodeRuntime(
        loops,
        FileManagedRuntimeCheckpointRepository(tmp_path / "managed-runtime.json"),
        **values,  # type: ignore[arg-type]
    )


async def wait_until(predicate: object) -> None:
    """在有界时间内等待同步测试条件成立。"""
    for _ in range(200):
        if callable(predicate) and predicate():
            return
        await asyncio.sleep(0.001)
    raise AssertionError("等待 managed runtime 条件超时")


def test_lifespan_starts_unique_domains_and_stops_without_task_leaks(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        loops = tuple(FakeLoop(domain) for domain in ManagedRuntimeDomain)
        managed = runtime(tmp_path, loops)
        async with managed_node_lifespan(managed):
            await asyncio.gather(*(loop.started.wait() for loop in loops))
            assert managed.status.phase is ManagedRuntimePhase.RUNNING
            assert all(item.phase is ManagedLoopPhase.RUNNING for item in managed.status.loops)
            with pytest.raises(RuntimeError, match="已启动"):
                await managed.start()
        assert managed.status.phase is ManagedRuntimePhase.STOPPED
        assert all(loop.checkpoint_count == 1 for loop in loops)
        assert not any(
            task.get_name().startswith("managed-node:")
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task()
        )
        await managed.stop()
        await managed.start()
        await managed.stop()
        assert all(loop.checkpoint_count == 2 for loop in loops)

    asyncio.run(scenario())


def test_loop_failures_restart_independently_with_single_concurrency(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        flaky = FakeLoop(ManagedRuntimeDomain.DIRECTORY, failures=2)
        stable = FakeLoop(ManagedRuntimeDomain.SERVICES)
        managed = runtime(tmp_path, (flaky, stable))
        await managed.start()
        await wait_until(lambda: flaky.run_count == 3 and stable.run_count == 1)
        directory = managed.status.loops[0]
        assert directory.phase is ManagedLoopPhase.RUNNING
        assert directory.restart_count == 2
        assert directory.consecutive_failures == 2
        assert directory.last_error_code == "fake_failure"
        assert flaky.max_active == 1
        assert stable.max_active == 1
        directory_task = next(
            task for task in asyncio.all_tasks() if task.get_name() == "managed-node:directory"
        )
        directory_task.cancel()
        await wait_until(directory_task.done)
        assert managed.status.loops[0].last_error_code == "loop_cancelled"
        await managed.stop()

    asyncio.run(scenario())


def test_restart_limit_degrades_only_failed_domain_and_redacts_exception(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        broken = FakeLoop(
            ManagedRuntimeDomain.DIRECTORY,
            failures=99,
            invalid_error_code=True,
        )
        stable = FakeLoop(ManagedRuntimeDomain.SERVICES)
        managed = runtime(tmp_path, (broken, stable), max_restarts=1)
        await managed.start()
        await wait_until(lambda: managed.status.loops[0].phase is ManagedLoopPhase.DEGRADED)
        assert broken.run_count == 2
        assert stable.active == 1
        assert managed.status.phase is ManagedRuntimePhase.DEGRADED
        assert managed.status.loops[0].last_error_code == "loop_crashed"
        assert "secret" not in managed.status.model_dump_json()
        await managed.stop()

    asyncio.run(scenario())


def test_unexpected_exit_checkpoint_failure_and_stop_timeout_are_stable(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        early = FakeLoop(
            ManagedRuntimeDomain.DIRECTORY,
            return_early=True,
            checkpoint_failure=True,
        )
        hanging = FakeLoop(ManagedRuntimeDomain.SERVICES, ignore_stop=True)
        managed = runtime(tmp_path, (early, hanging), max_restarts=0)
        await managed.start()
        await wait_until(lambda: managed.status.loops[0].phase is ManagedLoopPhase.DEGRADED)
        assert managed.status.loops[0].last_error_code == "unexpected_exit"
        await managed.stop()
        assert managed.status.last_error_code == "stop_timeout"
        assert managed.status.loops[0].last_error_code == "checkpoint_failed"
        assert hanging.checkpoint_count == 1

    asyncio.run(scenario())


def test_checkpoint_is_atomic_validated_and_marks_unclean_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tunnelminion.agent import managed_runtime

    path = tmp_path / "nested" / "managed-runtime.json"
    repository = FileManagedRuntimeCheckpointRepository(path)
    checkpoint = ManagedNodeRuntimeCheckpoint(
        phase=ManagedRuntimePhase.RUNNING,
        loops=(ManagedLoopStatus(domain=ManagedRuntimeDomain.DIRECTORY),),
        updated_at=NOW,
    )
    monkeypatch.setattr(managed_runtime.os, "name", "posix")
    repository.save(checkpoint)
    monkeypatch.setattr(managed_runtime.os, "name", "nt")
    repository.save(checkpoint)
    assert repository.load() == checkpoint
    assert not path.with_suffix(".json.tmp").exists()

    restored = ManagedNodeRuntime(
        (FakeLoop(ManagedRuntimeDomain.DIRECTORY),),
        repository,
        clock=lambda: NOW,
    )
    assert restored.status.loops[0].last_error_code == "unclean_shutdown"

    invalid = checkpoint.model_copy(update={"schema_version": "managed-runtime/v2"})
    path.write_text(invalid.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValidationError, match="版本"):
        repository.load()
    path.unlink()
    assert repository.load() is None
    with pytest.raises(ValidationError, match="时区"):
        ManagedNodeRuntimeCheckpoint(
            phase=ManagedRuntimePhase.STOPPED,
            loops=(),
            updated_at=datetime(2026, 7, 31),
        )


def test_constructor_and_startup_fail_closed_on_invalid_runtime_state(
    tmp_path: Path,
) -> None:
    loop = FakeLoop(ManagedRuntimeDomain.DIRECTORY)
    duplicate = FakeLoop(ManagedRuntimeDomain.DIRECTORY)
    repository = FileManagedRuntimeCheckpointRepository(tmp_path / "runtime.json")
    with pytest.raises(ValueError, match="不得重复"):
        ManagedNodeRuntime((loop, duplicate), repository)
    with pytest.raises(ValueError, match="重启次数"):
        ManagedNodeRuntime((loop,), repository, max_restarts=-1)
    with pytest.raises(ValueError, match="退避预算"):
        ManagedNodeRuntime((loop,), repository, base_backoff_seconds=0)
    with pytest.raises(ValueError, match="退避预算"):
        ManagedNodeRuntime((loop,), repository, base_backoff_seconds=2, max_backoff_seconds=1)
    with pytest.raises(ValueError, match="停止超时"):
        ManagedNodeRuntime((loop,), repository, stop_timeout_seconds=0)

    async def scenario() -> None:
        invalid_clock = ManagedNodeRuntime(
            (loop,),
            repository,
            clock=lambda: datetime(2026, 7, 31),
        )
        with pytest.raises(ValueError, match="时钟"):
            await invalid_clock.start()
        assert invalid_clock.status.phase is ManagedRuntimePhase.STOPPED
        assert invalid_clock.status.last_error_code == "startup_failed"

    asyncio.run(scenario())
