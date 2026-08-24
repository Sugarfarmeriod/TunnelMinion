## Why

TunnelMinion 已具备跨节点诊断、授权操作和证据链能力，但这些能力分散在多个界面、文档和未合并变更中，面试官难以在数分钟内理解一条完整且可信的产品主线。现在需要先建立独立的展示契约，将叙事、证据和依赖边界固定下来，同时避免为展示目的改写尚未稳定的产品能力。

## What Changes

- 建立以“设备/服务与访问地址 → Agent 只读诊断 → 无权限候选处理 → 必要的目标节点本地批准 → 执行与独立验证 → 恢复/清理证据”为核心的首版面试展示。
- 使用现有 `Thread`、`Run`、`Operation`、`Evidence` 概念组织 30 秒定位、三分钟主流程和技术深挖，不新增 `Mission` 领域对象。
- 定义 README 展示结构、现场演示与录屏兜底的职责、逐秒脚本、展示素材清单和失败/降级场景。
- 建立声明到证据的 manifest，区分 `main` 已交付、Draft PR 已验证、计划中和禁止宣称，并要求记录来源提交、环境、采集时间和验证方式。
- 允许在依赖未稳定时先完成独立规划、信息架构、离线 fixture 与评估设计；最终 UI、README、截图、录屏和真实指标必须等待对应稳定基线后重新采集。
- 将 A/B/C 三个独立 Agent 的直接通信与并发协调、公网邀请入网、n2n/relay、模型 fallback/额度路由和通用多 Agent 编排明确排除在首版范围之外。

## Capabilities

### New Capabilities

- `interview-showcase`: 规定面试展示的核心叙事、可交付素材、证据真实性、依赖门禁、现场降级和验收要求。

### Modified Capabilities

无。

## Impact

- 新增独立的面试展示规划、规范和任务清单。
- 后续实现可能在依赖稳定后涉及 README、演示文档、离线素材以及最小展示信息聚合，但本 change 不改变现有 Agent、网络、授权、模型或跨节点协议语义。
- `complete-managed-path-runtime` 与 `improve-local-product-experience` 仍由各自 owner 管理；本 change 不修改它们的 artifacts、任务状态或实现分支。
- 自部署 Penpot 继续作为可编辑图源，仓库内离线 SVG 与脱敏 manifest 作为可审计发布证据；规划阶段不写入外部图纸。
