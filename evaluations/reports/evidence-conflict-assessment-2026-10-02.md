# 证据冲突停止路径复核

## 结论

本轮未证明需要新增证据完整性 Skill。当前 Runtime 检出现场监听与触发快照冲突后，主动撤去可调用工具并要求返回 `insufficient_evidence`。先查监听的路径因此不会再查节点摘要，固定评分器仍按两个必需工具判分；这是停止策略与评分条件的差异，不能直接称为 Agent 漏查。

原始评测分数与报告保留，不修改 dataset、prompt 或 scorer，也不宣称本轮获得能力提升。暂不增加为了满足工具数量的查询。

## 固定条件与实测

- 基线：`9c3d6da53fae389c5d5155162e1d3a8f20060228`。
- 数据：`autonomous-incidents:v6` 的 `snapshot-listener-conflict`。
- 使用现有 scripted provider、真实 detector / Investigation Runtime / Tool Runtime、临时 SQLite；不调用外部模型或真实网络工具。
- 第一组沿用节点摘要 → 监听查询；第二组仅让 scripted provider 先查询监听，再提交报告。通过内存副本改变脚本序列，保留原必需工具集合，不修改磁盘数据集。它是控制路径复核，不是新的同口径模型 A/B。

| 路径 | 实际工具 | 最终状态 | 无依据断言 | 原评分器任务完成 |
|---|---|---|---|---|
| 节点优先 | get_node_summary、list_network_listeners | insufficient_evidence | false | true |
| 监听优先 | list_network_listeners | insufficient_evidence | false | false |

两条路径都在 trace 中记录“实时只读证据与触发快照冲突，停止追加取证”。第二条路径扣分不等于产生了错误根因，更不意味着应在矛盾证据下强行确认。

## 可重复命令

在仓库根目录用 PowerShell 运行；SQLite 只写系统临时目录并自动清理：

```powershell
@'
import asyncio
import json
import tempfile
from pathlib import Path
from tunnelminion.evaluation.incidents import IncidentEvaluationDataset, run_incident_scenario
from tunnelminion.incident.storage import SQLiteIncidentStore

scenario = next(s for s in IncidentEvaluationDataset.model_validate_json(
    Path("evaluations/datasets/autonomous-incidents-v6.json").read_text(encoding="utf-8")
).scenarios if s.scenario_id == "snapshot-listener-conflict")

async def main():
    with tempfile.TemporaryDirectory(prefix="tm-conflict-") as directory:
        for name, sequence, expected in (
            ("node-first", scenario.tool_sequence, True),
            ("listener-first", ("list_network_listeners",), False),
        ):
            result = await run_incident_scenario(
                scenario.model_copy(update={"tool_sequence": sequence}),
                SQLiteIncidentStore(Path(directory) / (name + ".sqlite3")),
            )
            assert result.status.value == "insufficient_evidence"
            assert result.stop_reason.value == "insufficient_evidence"
            assert result.conclusion is None
            assert not result.unsupported_assertion
            assert result.executed_tools == sequence
            assert result.task_completed is expected
            print(json.dumps({"case": name, "status": result.status,
                              "tools": result.executed_tools,
                              "task_completed": result.task_completed}))

asyncio.run(main())
'@ | uv run --frozen python -
```

## 实现依据

- `src/tunnelminion/incident/investigation.py`：`_is_snapshot_conflict` 检测冲突；`_run_loop` 在冲突后提供空工具集合；`_evidence_gap_message` 要求证据不足终态。
- `src/tunnelminion/evaluation/incidents.py`：`run_incident_scenario` 的任务完成判定要求 `required_tools` 全部成功。
- [原始 DeepSeek A/B 分析](incident-ab-deepseek-2026-09-30/summary.md)：冲突场景未匹配 Skill，不能将此前随机差异归因于 Skill 收益。

## 后续取舍

优先整理已有受控恢复链的可重复演示。只有真实用户需要在冲突后继续查明“哪份证据过时、是否来自错误目标”，且能固定复现、定义正确结果时，才设计继续取证的 Skill；当前 unknown 保护保持不变。

若以后调整评分规则，应另立版本并重跑两侧，不覆盖旧报告或与旧分数直接比较。本次未解决历史快照与现场信息为何不同，也未证明所有冲突都无需继续调查。
