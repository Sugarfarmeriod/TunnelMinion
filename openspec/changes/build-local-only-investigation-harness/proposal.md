## Why

现有跨节点调查已经能在固定矩阵和 Windows→macOS 实证中运行，但远端 `local_only` 路径只冻结了节点摘要与监听证据，调查进度也不足以在重启后跳过已成功取证的步骤。下一阶段需要先把这一条故障链收敛为可恢复、可解释、可同口径评测的纵向样板，避免继续用无法追溯或口径不一致的简历数字描述产品能力。

## What Changes

- 冻结现有 `101377a` 评测为只读基线，记录 commit、数据集及哈希、模型、prompt、预算、评分器、运行次数和各指标分子/分母。
- 为调查循环增加可持久化的 `InvestigationState`，统一 Skill 身份、阶段、预算、已尝试/成功证据、停止原因和恢复边界；重启后复用已成功证据，不重复执行对应工具。
- 提取首个版本化 `service.local-only` Skill，由它声明语义证据、执行节点、允许工具、确认/未知判定和输出约束；Skill 不执行工具、不保存状态、不授权调用。
- 将 Windows→macOS `local_only` 调查补齐为混合位置证据链：目标节点摘要提供私网状态，目标监听提供进程与绑定地址，发起节点独立探测目标私网端口。
- 扩展固定评测，记录证据覆盖、重复调用和证据不足时过早停止，并在同一数据、模型、prompt、评分器、预算和运行次数下生成前后报告。
- 提供一个不修改 WireGuard、路由、防火墙、DNS 或生产服务的隔离演示入口，展示 facts、unknowns、证据引用、工具历史、预算、Skill 版本、停止原因和最终报告。
- 非目标：受控写操作串联、更多 Skills、MCP、LangGraph 迁移、多 Agent/A2A、packet relay、复杂 Provider、自动组网和大规模界面改造。

## Capabilities

### New Capabilities
- `investigation-harness`: 定义可恢复调查状态、版本化 Skill 契约、混合执行位置和 `service.local-only` 的确定性收敛边界。

### Modified Capabilities
- `autonomous-incident-investigation`: 远端 `local_only` 必须满足目标进程、目标监听、私网状态和发起端可达性证据，缺失或冲突时收口为 unknown/证据不足。
- `agent-evaluation`: 评测报告必须冻结全部比较条件、明确分子分母，并记录证据覆盖、重复调用和过早停止指标。

## Impact

- 影响 incident 契约、SQLite 持久化、`IncidentInvestigator`、远端工具准备与固定评测代码。
- 复用现有 Tool Registry、Tool Runtime、认证 Gateway、WireGuard 和 Conversation 的取消/checkpoint 语义；不新增运行时依赖，也不修改真实网络配置。
- 旧 incident 记录保持可读取；旧评测证据保持只读，不重写历史结果。
