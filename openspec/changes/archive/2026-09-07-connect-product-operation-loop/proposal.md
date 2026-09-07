## Why

TunnelMinion 已完成临时共享的诊断、候选计划、目标端授权、执行、请求端验证和清理底座，但请求端只能通过验收脚本发起和继续操作；实际 React 产品只能查看或批准已有记录。用户因此无法在产品内走完“发现问题到安全恢复访问”的主路径。

## What Changes

- 在请求节点的本机产品中增加临时 HTTP 共享请求入口，复用已配置的固定 peer、现有只读跨节点诊断和候选计划器；浏览器不得提交任意 endpoint、Gateway token 或未验证证据。
- 将候选计划持久化并提交到目标节点，明确显示等待目标节点本地批准、拒绝、预授权命中和结果未知等状态。
- 目标节点授权后，由请求节点对同一 `operation_id` 发起幂等执行，提供有界的一次性验证回调，并以请求节点真实访问结果决定成功或回滚。
- 为成功操作提供仅环回、同源的浏览器访问入口；临时访问凭据只保留在服务端内存，不进入 URL、浏览器存储、普通日志或持久化记录。
- React 操作页覆盖发起、等待批准、执行与验证、访问、撤销、到期和失败恢复，并在写请求结果未知时只查询原操作，不自动重放。
- 增加确定性服务测试、FastAPI/React 集成测试和隔离回环验收；本阶段不触碰真实 WireGuard、防火墙、路由、Docker、生产服务或现有端口。
- 不恢复 `prepare-interview-showcase`、`build-isolated-packet-relay`，不加入 DeepSeek 配置、复杂 Provider、自动组网、relay、通用 TCP、HTTPS 终止或服务控制。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `approved-operation-workflow`: 要求请求节点在产品内持久化候选计划、提交后恢复状态，并在目标节点批准后完成幂等执行与独立验证。
- `temporary-service-sharing`: 要求成功共享通过请求节点的同源环回入口供浏览器使用，且临时凭据仅留在服务端内存。
- `local-product-interface`: 增加用户可实际发起和继续安全操作的 React 主流程，而不再只展示外部脚本创建的记录。

## Impact

- 复用 `CandidateOperationPlanner`、`CrossNodeDiagnosticWorkflow`、`FixedGatewayClient`、现有操作状态机、SQLite store、请求节点验证器和 React 操作页面。
- 新增最小请求端编排服务及本机 API，调整 Windows/macOS 应用组装、操作页面契约与测试。
- 不新增第三方依赖，不改变模型 Provider 配置，不扩大写工具或网络权限。
