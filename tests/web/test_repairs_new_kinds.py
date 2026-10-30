"""新修法在本机修复详情里只显示固定命令，像密钥的参数换成占位。"""

from __future__ import annotations

import asyncio
from pathlib import Path

from tests.repair.fakes import RepairHarness
from tests.repair.test_new_repair_kinds import (
    ORIGIN,
    PROGRAM,
    SERVICE,
    owner,
    program_record,
    service_record,
)
from tests.web.test_repairs import client_for

from tunnelminion.domain.service_marks import ServiceMark
from tunnelminion.repair.contracts import RepairKind


def test_program_stuck_and_windows_details(tmp_path: Path) -> None:
    h = RepairHarness(tmp_path)
    h.launch_records.put(program_record(tmp_path))
    h.launch_records.put(service_record())
    h.marks[SERVICE] = ServiceMark.MINE
    relaunch = asyncio.run(
        h.service.propose(PROGRAM, RepairKind.RELAUNCH_PROGRAM, "测试", ORIGIN, actor="t")
    )
    service = asyncio.run(
        h.service.propose(SERVICE, RepairKind.RESTART_WINDOWS_SERVICE, "测试", ORIGIN, actor="t")
    )
    h.host.owners[805] = owner()
    h.stuck.add(PROGRAM)
    stuck = asyncio.run(
        h.service.propose(PROGRAM, RepairKind.RESTART_STUCK_PROGRAM, "测试", ORIGIN, actor="t")
    )
    client = client_for(h)

    def advanced(record_id: object) -> dict[str, object]:
        return client.get(f"/api/repairs/{record_id}").json()["advanced"]

    program = advanced(relaunch.plan.operation_id)
    assert "（原来的值）" in str(program["command"]) and "s3cret-zq" not in str(program)
    assert program["end_process_id"] is None and program["ports"] == [805]
    assert advanced(stuck.plan.operation_id)["end_process_id"] == 42
    assert advanced(service.plan.operation_id) == {
        "commands": ["sc.exe start SunshineService"],
        "binary_path": "D:/Apps/Sunshine/sunshinesvc.exe",
        "ports": [47984],
    }
    assert h.windows_services.info is not None
    h.windows_services.info = h.windows_services.info.model_copy(update={"running": True})
    h.stuck.add(SERVICE)
    restart = asyncio.run(
        h.service.propose(SERVICE, RepairKind.RESTART_WINDOWS_SERVICE, "测试", ORIGIN, actor="t")
    )
    assert advanced(restart.plan.operation_id)["commands"] == [
        "sc.exe stop SunshineService",
        "sc.exe start SunshineService",
    ]
