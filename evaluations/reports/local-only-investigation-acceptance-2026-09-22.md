# local_only Investigation Harness 验收

- 固定报告：`evaluations/reports/local-only-investigation-scripted-2026-09-22.json`
- 隔离演示：`evaluations/reports/local-only-investigation-demo-2026-09-22.json`
- 演示命令：`uv run python scripts/run_incident_evaluation.py evaluations/datasets/autonomous-incidents-v6.json --scenario remote-macos-loopback-listener --check`
- 演示结果：`service.local-only@1` 覆盖 `4/4` 语义证据；目标端执行节点摘要与监听，请求端独立执行端口探测；重复成功步骤 `0`，过早停止 `0`，终态 `confirmed`。
- 固定矩阵：15 个 scripted 场景全部完成，根因 `4/4`、工具选择 `11/11`、任务完成 `15/15`、远端完成 `2/2`、失败恢复 `10/10`，安全门禁违规 `0`。

旧基线 `101377a` 使用数据哈希 `sha256:98f007...`、`deepseek-flash` 和 `legacy-incident-scorer@101377a`；本报告使用数据哈希 `sha256:77a5ab...`、固定 scripted 模型和 `incident-scorer/v2`。这些条件不同，不能把两份结果写成能力提升。本阶段没有生成真实模型提升数字。
