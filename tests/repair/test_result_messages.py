"""修复结果只写回一次，随对话快照恢复。"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from tests.agent.test_conversation import build_agent
from tests.agent.test_langchain_agent import SlowProvider
from tests.repair.factories import NODE, NOW, plan
from tests.repair.fakes import RepairHarness, at_status

from tunnelminion.agent.conversation import InMemoryConversationService, StartRunInput
from tunnelminion.domain.identifiers import ThreadId
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.repair.contracts import (
    RepairCheck,
    RepairCheckName,
    RepairError,
    RepairErrorCode,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
    RepairVerification,
)
from tunnelminion.repair.results import repair_result_text


def conversations(tmp_path: Path, *, preview: bool = False) -> InMemoryConversationService:
    return InMemoryConversationService(
        NODE,
        lambda: build_agent()[0],
        SQLiteStores.open(tmp_path / "threads.sqlite3").checkpoints,
        read_only_preview=preview,
    )


def terminal(
    thread_id: ThreadId, status: OperationStatus, *, verified: bool = True
) -> RepairRecord:
    record = RepairRecord.planned(
        plan().model_copy(
            update={"origin": RepairOrigin(kind=RepairOriginKind.CONVERSATION, thread_id=thread_id)}
        ),
        actor="agent",
    )
    check = RepairCheck(
        name=RepairCheckName.WEB_PAGE,
        passed=status is OperationStatus.SUCCEEDED,
        detail="不应原样回传 /private/site/app.py 或 docker start fake",
    )
    return record.model_copy(
        update={
            "status": status,
            "verification": RepairVerification(
                passed=check.passed,
                checks=(check,),
                log_excerpt=(
                    "ModuleNotFoundError: /private/site/app.py\n"
                    "python C:\\private\\app.py --secret=fake\nBearer fake"
                ),
                verified_at=NOW,
            )
            if verified
            else None,
            "error": RepairError(
                code=RepairErrorCode.EXECUTION_FAILED,
                message="docker start fake /private/site/app.py",
            ),
        }
    )


@pytest.mark.parametrize(
    ("status", "text"),
    [
        (OperationStatus.SUCCEEDED, "修好了"),
        (OperationStatus.ROLLED_BACK, "没修好"),
        (OperationStatus.CLEANUP_FAILED, "没修好"),
        (OperationStatus.REJECTED, "已取消"),
        (OperationStatus.AUTHORIZATION_EXPIRED, "已过期"),
    ],
)
def test_terminal_result_is_checked_private_idempotent_and_restored(
    tmp_path: Path, status: OperationStatus, text: str
) -> None:
    chat = conversations(tmp_path)
    thread_id = chat.create_thread().thread_id
    record = terminal(thread_id, status)
    h = RepairHarness(tmp_path)
    h.store.put(record)
    h.service.set_result_handler(chat.append_repair_result)
    h.service.list()
    h.service.get(record.plan.operation_id)
    asyncio.run(h.service.execute(record.plan.operation_id))
    messages = chat.get_thread(thread_id).messages
    assert len(messages) == 1 and messages[0].content.startswith(text)
    assert messages[0].answer_checked and messages[0].answer_basis == "checked"
    assert not any(
        value in messages[0].content
        for value in ("/private", "C:\\", "docker", "python", "Bearer", "--secret")
    )
    if status in {OperationStatus.ROLLED_BACK, OperationStatus.CLEANUP_FAILED}:
        assert "卡在首页访问检查" in messages[0].content and "缺少需要的模块" in messages[0].content
    restored = conversations(tmp_path)
    h.service.set_result_handler(restored.append_repair_result)
    assert restored.get_thread(thread_id).messages == messages


def test_results_for_active_threads_survive_new_runs_and_restart(tmp_path: Path) -> None:
    chat = conversations(tmp_path)
    thread_id = chat.create_thread().thread_id

    async def ask() -> None:
        run = await chat.start_run(
            thread_id, StartRunInput(question="看看服务", tool_names=("probe_service",))
        )
        _ = [event async for event in chat.stream_events(run.run_id)]

    asyncio.run(ask())
    record = terminal(thread_id, OperationStatus.SUCCEEDED)
    chat.append_repair_result(record)
    asyncio.run(ask())
    restored = conversations(tmp_path)
    restored.append_repair_result(record)
    assert len(restored.get_thread(thread_id).messages) == 5


def test_repair_result_waits_for_queued_and_running_run_without_persisting(tmp_path: Path) -> None:
    provider = SlowProvider()
    stores = SQLiteStores.open(tmp_path / "threads.sqlite3")
    chat = InMemoryConversationService(NODE, lambda: build_agent(provider)[0], stores.checkpoints)
    thread_id = chat.create_thread().thread_id
    h = RepairHarness(tmp_path)
    record = terminal(thread_id, OperationStatus.SUCCEEDED)
    h.store.put(record)

    async def scenario() -> None:
        run = await chat.start_run(
            thread_id, StartRunInput(question="看看服务", tool_names=("probe_service",))
        )
        queued_checkpoint = stores.checkpoints.get(run.run_id)
        queued_thread = chat.get_thread(thread_id)
        h.service.set_result_handler(chat.append_repair_result)
        assert stores.checkpoints.get(run.run_id) == queued_checkpoint
        assert chat.get_thread(thread_id) == queued_thread
        async with asyncio.timeout(2):
            while not provider.requests:
                await asyncio.sleep(0)
        running_checkpoint = stores.checkpoints.get(run.run_id)
        h.service.list()
        assert stores.checkpoints.get(run.run_id) == running_checkpoint
        assert chat.get_thread(thread_id) == queued_thread
        chat.cancel_run(run.run_id)
        _ = [event async for event in chat.stream_events(run.run_id)]
        h.service.list()
        h.service.list()
        messages = chat.get_thread(thread_id).messages
        assert sum(message.content.startswith("修好了") for message in messages) == 1
        assert conversations(tmp_path).get_thread(thread_id).messages == messages

    asyncio.run(scenario())


def test_failed_persistence_can_retry_and_concurrent_delivery_deduplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = conversations(tmp_path)
    thread_id = chat.create_thread().thread_id
    record = terminal(thread_id, OperationStatus.CLEANUP_FAILED, verified=False)
    before = chat.get_thread(thread_id)

    def fail(*_: object) -> None:
        raise OSError("fake storage failure")

    with monkeypatch.context() as patch:
        patch.setattr(chat, "_persist", fail)
        with pytest.raises(OSError):
            chat.append_repair_result(record)
    assert chat.get_thread(thread_id) == before
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(chat.append_repair_result, (record,) * 6))
    message = conversations(tmp_path).get_thread(thread_id).messages[0]
    assert message.answer_basis == "none" and "执行中途出错" in message.content


def test_missing_thread_and_preview_do_not_append(tmp_path: Path) -> None:
    chat = conversations(tmp_path)
    chat.append_repair_result(terminal(ThreadId.new(), OperationStatus.REJECTED))
    preview = conversations(tmp_path, preview=True)
    thread_id = preview.create_thread().thread_id
    preview.append_repair_result(terminal(thread_id, OperationStatus.REJECTED))
    assert preview.get_thread(thread_id).messages == ()


def test_reject_expire_execute_and_interrupted_recovery_deliver_results(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    chat = conversations(tmp_path)
    h.service.set_result_handler(chat.append_repair_result)
    for action in ("reject", "expire", "execute", "recover"):
        thread_id = chat.create_thread().thread_id
        record = RepairRecord.planned(
            plan().model_copy(
                update={
                    "origin": RepairOrigin(kind=RepairOriginKind.CONVERSATION, thread_id=thread_id),
                    "created_at": h.clock(),
                }
            ),
            actor="agent",
        )
        waiting = h.authorization.submit(record, at=h.clock())
        if action == "reject":
            h.service.reject(waiting.plan.operation_id, operator="local-web", reason=None)
        elif action == "expire":
            h.clock.now += timedelta(minutes=10)
            h.service.expire_due(h.clock())
        elif action == "execute":
            h.service.approve(waiting.plan.operation_id, operator="local-web")
            asyncio.run(h.service.execute(waiting.plan.operation_id))
        else:
            h.store.put(at_status(record, OperationStatus.EXECUTING))
            h.clock.now += timedelta(minutes=16)
            h.service.list()
        assert len(chat.get_thread(thread_id).messages) == 1


@pytest.mark.parametrize(
    ("log", "gist"),
    [
        ("permission denied", "运行权限不足"),
        ("No such file", "文件不在了"),
        ("address already in use", "端口被占用"),
        ("connection refused", "连接不上"),
        ("timed out", "超时"),
        ("MemoryError", "内存不足"),
        ("startup failed", "启动失败"),
        ("", "没修好"),
    ],
)
def test_failure_uses_log_gist_without_raw_commands(log: str, gist: str) -> None:
    record = terminal(ThreadId.new(), OperationStatus.ROLLED_BACK)
    assert record.verification is not None
    record = record.model_copy(
        update={"verification": record.verification.model_copy(update={"log_excerpt": log})}
    )
    assert gist in repair_result_text(record)
    assert "docker" not in repair_result_text(record)
    assert "没修好" in repair_result_text(
        record.model_copy(update={"error": None, "verification": None})
    )
    assert "服务状态正常" in repair_result_text(
        record.model_copy(update={"status": OperationStatus.SUCCEEDED, "verification": None})
    )
    assert record.verification is not None
    passing = record.verification.model_copy(
        update={
            "checks": (
                RepairCheck(name=RepairCheckName.PORT_LISTENING, passed=True, detail="端口在听"),
            )
        }
    )
    assert "没修好" in repair_result_text(record.model_copy(update={"verification": passing}))


def test_non_web_service_result_does_not_claim_homepage_was_verified() -> None:
    record = terminal(ThreadId.new(), OperationStatus.SUCCEEDED)
    assert record.verification is not None
    verification = record.verification.model_copy(
        update={
            "checks": (
                RepairCheck(
                    name=RepairCheckName.PORT_LISTENING, passed=True, detail="端口 8080 在听。"
                ),
                RepairCheck(
                    name=RepairCheckName.WEB_PAGE,
                    passed=True,
                    detail="这个端口不是网页，只确认了端口在听。",
                ),
            )
        }
    )
    content = repair_result_text(record.model_copy(update={"verification": verification}))
    assert content == "修好了。已确认：端口监听正常。"
