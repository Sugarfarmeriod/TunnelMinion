# 固定口径 Investigation Harness / Skill A/B 评测

- 状态：`进行中（scripted 机制 A/B 已完成，真实模型待 endpoint 恢复）`
- 主写分支：`feature/fixed-evaluation-ab`
- 阶段起点：`e68a95bc9309b0100c1b63535a5daadcbf92722c`
- 对应总流程：`4. 固定口径评测`

## 结果与用户影响

本阶段回答一个问题：`Investigation Harness + service.local-only Skill` 是否真的让调查更完整、更少重复，
而不是只让代码结构看起来更合理。完成后，简历中的每个提升数字都能追溯到固定条件和失败样本。

## 当前证据与缺口

- 已有：历史真实模型基线冻结在
  [`../../../evaluations/baselines/local-only-investigation-101377a.json`](../../../evaluations/baselines/local-only-investigation-101377a.json)，
  包含 commit、dataset/hash、模型、prompt、工具、预算、scorer 和分子/分母。
- 已有：新 Harness 的 scripted 15 场景验收与隔离 `local_only` 演示已通过，见
  [`../../../evaluations/reports/local-only-investigation-acceptance-2026-09-22.md`](../../../evaluations/reports/local-only-investigation-acceptance-2026-09-22.md)。
- 缺口：旧基线与新验收使用了不同 dataset hash、模型方式和 scorer，不能声称形成能力提升。
- 缺口：尚无同条件多次运行、方差和逐条失败解释。

## 范围

- 本阶段完成：冻结唯一实验契约；在相同条件下运行 baseline 与 candidate；输出逐项指标、方差、失败
  分类和前后差异；把可用结果整理为可追溯简历口径。
- 本阶段不做：多 Agent/A2A 对比、scorer 重写、MCP、受控写操作、扩展新故障 Skill、页面改版。

## 实验顺序

```mermaid
flowchart LR
    A["冻结共同实验契约"] --> B["运行 baseline R 次"]
    B --> C["核对每条失败 trace"]
    C --> D["只切换 Harness + Skill"]
    D --> E["运行 candidate R 次"]
    E --> F["比较质量、调用与恢复指标"]
    F --> G["形成报告与简历可用结论"]
```

## 固定实验契约

实施开始时先生成机器可读 manifest，并同时绑定：

- baseline commit 与 candidate commit；
- 同一 dataset 文件、内容 hash 和场景分母；
- 同一 provider、model、prompt 内容 hash、工具版本和上下文预算；
- 同一 scorer 代码版本与内容 hash；
- 同一运行次数 `R`、随机性参数、超时和重试规则；
- 每次运行的原始报告、trace 索引、token、耗时和错误分类。

默认先使用最小可区分重复次数 `R=3`。只有结果方差过大、无法判断方向时才增加次数；不预先扩大成本。

## 指标

| 指标 | 目的 |
|---|---|
| 根因成功率、任务完成率 | 是否真正解决场景 |
| 证据覆盖率 | 必需证据是否取全 |
| 证据不足时过早停止率 | 是否在缺证据时误报完成 |
| 重复工具调用率 | Harness 是否避免重复取证 |
| 工具选择率、非必要调用率 | Skill 是否约束了调用范围 |
| 失败恢复率 | 超时、离线、无权限、取消后是否得到确定终态 |
| token、耗时、调用数 | 质量收益对应的成本 |
| 安全违规 | 必须保持 `0` |

## 完成标准

- [ ] baseline 和 candidate 的实验 manifest 除待验证机制与 commit 外保持一致。
- [ ] 每侧至少完成 `R=3` 次；中断或 Provider 错误按预先规则计入，不选择性丢弃。
- [ ] 每个指标包含分子、分母、均值和重复运行差异。
- [ ] 每项退化或提升能指向具体场景和 trace。
- [ ] scorer 在实验期间不变化；如果必须修 scorer，整组实验作废后重跑。
- [ ] 安全违规为 `0`，缺少必需证据时不输出 `confirmed`。
- [ ] 生成机器可读报告和一份简明 Markdown 总结。
- [ ] 只把稳定、同口径的结果写入 README、演示或简历材料。
- [ ] PR 合并后回写总路线图和本页完成结果。

## 实施记录

- 新增同提交、同数据、同 Prompt、同预算、同 scorer 的 A/B runner；唯一机制差异为
  `skills_enabled: false → true`。
- 完成 scripted baseline/candidate 各 `3` 次。baseline 每次失败同一远端 `local_only` 场景，candidate
  三次全部完成，安全违规均为 `0`。
- 当前非秘密模型配置指向现有 `8082` endpoint；健康检查连接超时。按项目边界未启动服务、未修改网络，
  真实模型运行保留为本阶段最后一步。
- 机制报告：
  [`incident-ab-scripted-2026-09-29`](../../../evaluations/reports/incident-ab-scripted-2026-09-29/summary.md)。

## 完成结果

scripted 固定响应结果为：根因成功率 `9/12 → 12/12`、工具选择 `30/33 → 33/33`、任务完成
`42/45 → 45/45`、远端完成 `3/6 → 6/6`、失败恢复两侧均 `30/30`、安全违规均为 `0`。

该结果只证明机制因果关系，不写成真实模型提升。阶段继续保持进行中，直到真实模型在同一 manifest 下完成
baseline/candidate 各 `3` 次并生成失败解释。
