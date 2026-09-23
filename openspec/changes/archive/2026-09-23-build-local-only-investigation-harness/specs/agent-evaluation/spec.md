## ADDED Requirements

### Requirement: 调查基线必须冻结比较条件和分子分母

每个用于简历、发布或前后比较的调查基线 MUST 绑定代码提交、数据集 ID/版本/内容哈希、模型、Provider、Prompt 版本/内容哈希、工具版本、预算、scorer 版本、运行次数和逐项 numerator/denominator/value。历史报告 SHALL 保持只读，scorer 口径变化 MUST NOT 被表述为 Agent 能力提升。

#### Scenario: 引用 101377a 固定结果
- **WHEN** 系统生成当前阶段基线清单
- **THEN** 清单 SHALL 把 15 场景单次结果记录为根因 `4/4`、工具选择 `10/11`、任务完成 `14/15`、远端完成 `2/2`、失败恢复 `9/10` 和安全违规 `0`，并关联原始报告路径与哈希

#### Scenario: 比较条件不一致
- **WHEN** 两份报告的数据、模型、Prompt、预算、scorer 或运行次数任一不同
- **THEN** 比较器 MUST 拒绝生成能力提升结论，并明确列出不一致字段

### Requirement: Skill 评测必须解释证据收敛质量

新 scorer SHALL 在既有指标外记录必要证据覆盖率、成功步骤重复调用率和证据不足时过早停止率，并为每个比率保存分子与分母。报告 MUST 保存 Skill ID/版本、执行位置、失败 trace 和最终 unknowns。

#### Scenario: 证据完整且无重复调用
- **WHEN** `service.local-only` 的四类语义证据均被覆盖，每个成功步骤只执行一次且最终确认
- **THEN** 场景 SHALL 记录证据覆盖 `4/4`、重复成功步骤 `0`、过早停止 `0` 和正确完成

#### Scenario: 模型在缺证据时停止
- **WHEN** 模型请求 `evidence_sufficient` 时至少一项必要语义证据仍可获取但未覆盖
- **THEN** scorer SHALL 增加过早停止分子，且程序不得把该场景计为确认成功

### Requirement: local_only 必须提供隔离可重复演示

项目 SHALL 提供不读取秘密、不调用写工具且不修改真实网络的固定演示，输出 incident 输入、每轮 facts/unknowns、证据引用、工具历史与执行位置、预算、Skill 版本、停止原因和最终报告。

#### Scenario: 运行 Windows 到 macOS 固定演示
- **WHEN** 开发者运行固定 `local_only` 演示命令
- **THEN** 演示 SHALL 使用隔离 Gateway 与固定工具结果完成同一证据链，输出可复核报告并在结束后不留下监听进程或临时网络状态
