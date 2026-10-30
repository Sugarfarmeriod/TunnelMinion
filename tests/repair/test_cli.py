"""命令行通过可替换门面执行，测试不启动真实进程。"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from tests.repair.factories import plan
from tests.repair.fakes import RepairHarness, at_status

from tunnelminion import cli
from tunnelminion.domain.identifiers import OperationId
from tunnelminion.operation.contracts import OperationStatus
from tunnelminion.repair.contracts import RepairRecord
from tunnelminion.repair.service import RepairService


def install_factory(monkeypatch: pytest.MonkeyPatch, h: RepairHarness) -> list[Path | None]:
    paths: list[Path | None] = []

    def factory(data_dir: Path | None) -> RepairService:
        paths.append(data_dir)
        return h.service

    monkeypatch.setattr(cli, "_repair_service_factory", factory)
    return paths


def propose() -> int:
    return cli.main(
        [
            "repair-propose",
            "--service-key",
            "docker:compose:photos",
            "--kind",
            "restart_containers",
            "--reason",
            "容器退出了",
        ]
    )


def test_propose_list_and_approve_synchronously(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = RepairHarness(tmp_path)
    paths = install_factory(monkeypatch, h)
    assert cli.main(["repair-list", "--data-dir", str(tmp_path)]) == 0
    assert capsys.readouterr().out == "还没有修复记录。\n"
    assert paths == [tmp_path]
    assert propose() == 0
    record = h.store.list_all()[0]
    repair_id = str(record.plan.operation_id)
    assert capsys.readouterr().out.splitlines() == [
        f"已生成修复 {repair_id}：{record.plan.action_summary}",
        f"运行 tunnelminion repair-approve --repair-id {repair_id} 批准（10 分钟内有效）。",
    ]
    assert record.plan.origin.kind.value == "local_cli"
    assert record.audit[0].actor == "local-cli"
    assert paths[-1] is None
    assert cli.main(["repair-list"]) == 0
    assert (
        capsys.readouterr().out
        == f"{repair_id}  awaiting_authorization  {record.plan.service_name}  "
        f"{record.plan.action_summary}\n"
    )
    assert not h.containers.calls
    assert cli.main(["repair-approve", "--repair-id", repair_id]) == 0
    output = capsys.readouterr().out
    assert output.startswith(f"修好了：{record.plan.action_summary}\n")
    assert "- 所有容器都在运行。\n" in output
    assert "- 端口 8080 在听。\n" in output
    assert "- 首页能打开（HTTP 200）。\n" in output
    result = h.store.get(record.plan.operation_id)
    assert result is not None and result.status is OperationStatus.SUCCEEDED
    assert result.authorization is not None and result.authorization.operator == "local-cli"
    assert cli.main(["repair-approve", "--repair-id", repair_id]) == 1
    assert capsys.readouterr().out == "这个修复现在不等批准\n"
    assert len(h.containers.calls) == 1


@pytest.mark.parametrize("with_next", [False, True])
def test_propose_refusals_print_fixed_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    with_next: bool,
) -> None:
    h = RepairHarness(tmp_path)
    install_factory(monkeypatch, h)
    if with_next:
        h.containers.items = None
    key = "docker:compose:photos" if with_next else "port:tcp:8080"
    assert (
        cli.main(
            [
                "repair-propose",
                "--service-key",
                key,
                "--kind",
                "restart_containers",
                "--reason",
                "退出了",
            ]
        )
        == 1
    )
    output = capsys.readouterr().out
    assert output == (
        "修不了：Docker 没开。\n请先打开 Docker Desktop 或 OrbStack，Agent 不会替你打开。\n"
        if with_next
        else "修不了：只能修 Docker 容器、Python 脚本、普通程序、macOS 后台服务和 Windows 服务。\n"
    )
    assert not h.containers.calls


@pytest.mark.parametrize("reason", [None, "稍后再修"])
def test_reject_prints_and_never_executes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reason: str | None,
) -> None:
    h = RepairHarness(tmp_path)
    install_factory(monkeypatch, h)
    assert propose() == 0
    record = h.store.list_all()[0]
    capsys.readouterr()
    values = ["repair-reject", "--repair-id", str(record.plan.operation_id)]
    if reason is not None:
        values.extend(["--reason", reason])
    assert cli.main(values) == 0
    assert capsys.readouterr().out == f"已拒绝修复 {record.plan.operation_id}，什么都不会做。\n"
    result = h.store.get(record.plan.operation_id)
    assert result is not None and result.authorization is not None
    assert result.authorization.basis == (reason or "主人选择先不修。")
    assert not h.containers.calls and not h.launcher.calls
    assert cli.main(values) == 1
    assert capsys.readouterr().out == "这个修复现在不等批准\n"


@pytest.mark.parametrize("command", ["repair-approve", "repair-reject"])
@pytest.mark.parametrize("repair_id", ["invalid", str(OperationId.new())])
def test_missing_or_bad_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    repair_id: str,
) -> None:
    install_factory(monkeypatch, RepairHarness(tmp_path))
    assert cli.main([command, "--repair-id", repair_id]) == 1
    assert capsys.readouterr().out == "修复不存在\n"


def test_waiting_expired_cannot_be_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = RepairHarness(tmp_path)
    install_factory(monkeypatch, h)
    assert propose() == 0
    record = h.store.list_all()[0]
    capsys.readouterr()
    h.clock.now += timedelta(minutes=10)
    assert cli.main(["repair-approve", "--repair-id", str(record.plan.operation_id)]) == 1
    assert capsys.readouterr().out == "这个修复现在不等批准\n"
    assert not h.containers.calls


@pytest.mark.parametrize("log", ["startup failed", ""])
def test_failed_verification_prints_checks_and_log_excerpt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], log: str
) -> None:
    h = RepairHarness(tmp_path)
    install_factory(monkeypatch, h)
    assert propose() == 0
    record = h.store.list_all()[0]
    capsys.readouterr()
    h.containers.stay_stopped = True
    h.containers.log = log
    assert cli.main(["repair-approve", "--repair-id", str(record.plan.operation_id)]) == 1
    output = capsys.readouterr().out
    assert output.startswith(
        "没修好：容器重启了，但服务还是没起来。\n看看日志要点；Agent 不会自动重试。\n"
    )
    assert "- photos-web-1 没在运行" in output
    assert ("日志要点：\nstartup failed\n" in output) == bool(log)
    assert len(h.containers.calls) == 1


def test_command_failure_without_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = RepairHarness(tmp_path)
    install_factory(monkeypatch, h)
    assert propose() == 0
    record = h.store.list_all()[0]
    capsys.readouterr()
    h.containers.exit_codes = [1]
    assert cli.main(["repair-approve", "--repair-id", str(record.plan.operation_id)]) == 1
    assert (
        capsys.readouterr().out
        == "没修好：Docker 没能启动这些容器。\n看看日志要点；Agent 不会自动重试。\n"
    )


def test_busy_failure_without_next_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    h = RepairHarness(tmp_path)
    install_factory(monkeypatch, h)
    assert propose() == 0
    record = h.store.list_all()[0]
    capsys.readouterr()
    h.store.put(
        at_status(
            RepairRecord.planned(plan(service_key="docker:compose:other"), actor="local-cli"),
            OperationStatus.EXECUTING,
        )
    )
    assert cli.main(["repair-approve", "--repair-id", str(record.plan.operation_id)]) == 1
    assert capsys.readouterr().out == "没修好：这台电脑正在执行另一个修复，请等它结束再试。\n"
    assert not h.containers.calls
