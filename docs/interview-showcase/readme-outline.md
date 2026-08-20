<!--
status: planned
target: repository-root README.md
publication: false
stable-main-required: true
-->

# README 展示结构稿（不可发布）

本文件不是根 README，也不是最终展示材料。它只固定未来稳定基线上的信息顺序、证据插槽和降级边界；PR #40、PR #59、真实 A/B 和最终素材未完成前，OpenSpec 3.1 保持未完成。

## 1. 一句话定位

目标位置：根 README 标题后的第一屏。

候选结构：

> TunnelMinion 是运行在私有组网节点上的设备与服务助手：它先展示可验证的设备、服务和访问地址，再用只读 Agent 诊断问题；任何有副作用的处理都必须由目标节点本地批准，并在独立验证后才算完成。

发布门禁：最终文字只能描述稳定 `main` 已交付能力；Draft PR、fixture 和未来路线图必须分别标为 `draft-pr-verified`、`planned` 或 `prohibited-claim`。

## 2. 闭环动图

目标位置：一句话定位之后，不用架构图开场。

- 资产插槽：`recording-main-flow`，最终可导出短循环动图或同源视频预览。
- 静态兜底：`screenshot-overview` 与 `screenshot-operation`。
- 画面顺序：设备/服务与访问地址 → 只读诊断 → 候选未授权 → 目标节点本地批准 → 验证与恢复/清理。
- 每个动态资产必须绑定稳定 SHA、平台、采集时间和 [claim-to-evidence schema](evidence-manifest.schema.json)。
- 动图加载失败时显示同一提交的脱敏静态图；不得用 fixture 或历史录屏冒充本轮现场成功。

## 3. 五步主流程

目标位置：动图后的产品解释区。页面名称只作为入口，不新增展示专用领域对象。

1. **发现**：从 Overview 查看节点、服务、新鲜度和访问地址状态。
2. **诊断**：在 Thread 发问，由 Run 展示允许公开的只读工具轨迹和 Evidence。
3. **候选**：Operation 显示目标、风险、范围、TTL、验证和回滚，状态保持“尚未授权”。
4. **批准与执行**：只有目标节点本地批准后 Provider 才能执行；请求节点、Coordinator 和模型不能自批。
5. **验证与恢复**：Provider verify 与 path/service verify 分离；失败进入恢复、清理或人工处理，只处理 owned resources。

详细逐秒动作继续引用[三分钟主演示脚本](storyboard.md#三分钟主流程)，README 只保留能在一分钟内扫完的摘要。

## 4. 证据表

目标位置：五步流程之后。每行是一个声明，不是功能清单。

| 声明 | 状态 | 来源提交 / PR | 平台与环境 | 验证与采集时间 | 是否允许发布 |
| --- | --- | --- | --- | --- | --- |
| 设备/服务状态可读 | `planned` 占位 | 等稳定 `main` 重采 | Windows/macOS 待记录 | 命令、报告、时间待记录 | 否 |
| 候选在批准前无执行权 | `planned` 占位 | 等稳定 `main` 重采 | 精确测试环境待记录 | Operation/Evidence 待记录 | 否 |
| 验证失败可恢复或转人工 | `planned` 占位 | 等稳定 `main` 重采 | 精确故障注入待授权 | rollback/receipt 待记录 | 否 |

发布规则：

- 最终表格只能把通过本轮稳定基线复核的声明标为 `main-verified`。
- `draft-pr-verified` 必须显示 PR 号和精确 head，不得写成已发布。
- `planned` 与 `prohibited-claim` 不进入成果数字、成功画面或简历指标。
- 表格数据由 `claim-manifest` 生成或逐项核对，不手填无法追溯的数字。

## 5. 生命周期图

目标位置：主流程和证据之后，用于收束而非开场。

- 当前工作包图：[生命周期 SVG](diagrams/lifecycle.svg)。
- 追溯关系：[图纸 manifest](diagrams/diagram-assets.json) 中的 `diagram-lifecycle`。
- 最终发布前必须在稳定能力边界上重核标签、哈希、图源版本和导出时间。

## 6. 安全边界

目标位置：生命周期图之后，回答“为什么 Agent 不能直接改网络”。

- 深挖图：[授权边界 SVG](diagrams/security-approval.svg)。
- 追溯关系：[图纸 manifest](diagrams/diagram-assets.json) 中的 `diagram-security-approval`。
- 核心句：批准发生在目标节点，不在模型里；执行成功不等于闭环成功。
- 明确范围外资源：用户防火墙、Murus、既有 WireGuard、广泛路由、秘密和自启动保持不变。
- 未获得精确隔离资源授权时，真实 Provider 写入、故障注入和恢复均为 `prohibited-claim`。

## 7. 降级矩阵

目标位置：安全边界之后，让现场失败也有诚实说法。

| 故障 | 仍可展示 | 必须说明 | 禁止替代 |
| --- | --- | --- | --- |
| 模型不可用 | 确定性设备/服务状态与已有操作入口 | 开放式诊断当前不可用 | 不播放录屏并称为当前成功 |
| 节点离线 | 本机状态、离线 Evidence 和恢复建议 | 远端当前状态未知 | 不用缓存冒充在线 |
| Coordinator 不可用 | 本机只读入口与静态路径 | 跨节点协调降级 | 不扩大权限或改用户网络 |
| 验证失败 | Provider 与 path/service 的失败证据 | 写入不等于成功 | 不把执行完成写成任务完成 |
| 恢复失败 | receipt、所有权冲突与人工处理状态 | 自动清理已经停止 | 不删除所有权不明资源 |
| 现场演示中断 | 同一稳定提交的录屏与离线证据 | 明确标注“录屏”及来源 | 不用 fixture 计入真实 A/B 指标 |

失败场景来源与标记规则见[离线 fixture](fixtures/failure-scenarios.json)和[无模型验证记录](no-model-verification.md)。

## 8. 技术深挖链接

目标位置：README 展示段末尾，面试官按兴趣进入，不阻断三分钟主线。

- Agent 与确定性工具边界、目标节点授权、幂等恢复、跨平台降级和证据追踪：[技术深挖脚本](storyboard.md#五至十分钟技术深挖)。
- 生命周期与授权边界的离线图源：[图纸 manifest](diagrams/diagram-assets.json)。
- 指标口径、fixture 基线和真实基线门禁：[评估契约](evaluation-plan.md)。
- 最终量化插槽：`evaluation-report`，只有真实基线和独立审计通过后才能发布。
- 全部展示声明的状态规则：[证据 schema](evidence-manifest.schema.json)。

## 9. 明确未交付

以下内容只能进入路线图或追问回答，不能进入首版成功声明：

- A/B/C 三个独立 Agent 的直接通信、并发协调和矛盾证据仲裁；
- 邀请入网、n2n/relay、自动组网；
- 本地 Qwen → DeepSeek → 百炼的 fallback、权限和额度路由；
- `Mission` 领域对象或通用多 Agent 编排；
- 未经授权的真实接口、地址、路由、Provider 写入、恢复或清理；
- 尚未合并 PR 的能力被描述为稳定 `main`。

## 10. 发布前替换清单

- 把所有资产插槽替换为同一稳定提交上重新采集的文件，并更新 [素材台账](asset-inventory.md)。
- 删除所有 `planned` 占位行；不能升级为 `main-verified` 的内容直接移出成果区。
- 核对根 README 链接、动图静态兜底、SVG、manifest、量化报告和跨平台 CI 属于相同交付基线。
- 完成逐帧脱敏检查，不出现秘密、隐藏推理、未脱敏工具输出或真实内部地址。
- 由独立审计核对主叙事、数字、来源和失败边界后，才允许把结构稿写入根 README。
