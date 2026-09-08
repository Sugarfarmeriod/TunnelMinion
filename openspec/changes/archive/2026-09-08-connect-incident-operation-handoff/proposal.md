## Why

TunnelMinion 已分别完成 Overview 主导的自主 incident 调查和经目标节点批准的临时 HTTP 共享，但两段产品链仍彼此断开：用户在 incident 详情里只能追问，默认首页也看不到等待自己处理的操作。真实 incident 评测和操作闭环均已通过，因此现在应补齐“调查结果进入人工审批”的最后一段用户路径，而不是扩建新的网络或模型能力。

## What Changes

- 在 Overview 增加只读的待处理操作队列，突出目标端待批准、请求端待执行、写结果未知和清理失败，并链接现有操作详情。
- 对已确认、目标为远端节点且仍能确定服务端口的 `local_only` incident 提供“生成候选处理计划”入口，把 incident 的目标节点和端口带到现有操作表单。
- 把 incident 上下文明确标成预填信息；用户仍须逐项确认，服务端仍须重新执行最新只读诊断、生成无权限候选计划并等待目标节点授权。
- 对本机 incident、未确认 incident、服务已消失、端口未知或目标对端不合格等情况给出稳定说明，不猜测可执行动作，也不自动创建、批准或执行 Operation。
- 增加 React 单元测试和隔离浏览器组合验收，覆盖 Incident → 预填候选计划 → 待审批队列 → 既有操作详情，不触碰真实 WireGuard、防火墙、路由、DNS、服务或生产端口。
- 不新增通用修复器、写工具、模型 Provider、relay、自动组网、Linux 支持、服务重启或 Docker 控制；不恢复暂停中的 showcase、packet relay 和手工打包 change。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `local-product-interface`: 让默认 Overview 展示需要本机用户介入的操作，并提供从可处理 incident 到现有候选计划表单的受限上下文交接。
- `autonomous-incident-investigation`: 明确 incident 处理请求只能预填并进入既有候选计划流程，且调查事实不得成为确认、授权或执行结果。
- `agent-evaluation`: 增加隔离的组合产品验收，证明 incident 入口、操作待办和既有审批链在同一用户路径中连通。

## Impact

- 主要影响 React Overview、操作列表页、前端强类型契约测试和 Playwright 验收；复用现有 `/api/resources/overview`、`/api/incidents/{id}` 与 `/api/operations`，不新增服务端写接口。
- 不改变 OperationPlan、SQLite 数据、Gateway 协议、模型配置或运行时权限，不新增第三方依赖。
- 预填参数仍是浏览器输入，现有服务端合格 peer、最新诊断、候选计划校验、目标端授权、幂等执行、验证与回滚继续是权威边界。
