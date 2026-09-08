## Why

当前产品能从 Coordinator/聚合快照发现远端 incident，也已有受认证的远端 Tool Gateway，但 Investigation Agent 只会为 `local_observation` 接入本机工具；远端 incident 因此只能解释旧快照，不能到目标节点补齐实时证据。主线已经完成观察、调查、总览和人工操作入口，现在需要用 Windows/macOS 跨节点证据证明这条产品循环真实成立，并固定一份可重复比较的发布指标基线。

## What Changes

- 让 Windows 与 macOS 本地产品在远端 incident 指向显式授权的 static peer 时，按目标 node ID 预检其 Gateway 身份和实时只读能力，并把目标节点工具注入同一个 Investigation Agent。
- 为远端事件维护独立的目标节点证据路径；模型按剩余信息缺口逐轮选择工具，所有结果保留目标 node、`run_id` 和 `tool_run_id` 归属。
- 修正调查调用上下文中的请求节点/执行节点身份；远端准备或工具失败时诚实停在 `insufficient_evidence`，不得改用请求节点本机工具，也不得对远端执行确定性 fallback。
- 增加固定、无秘密的隔离跨节点验收，覆盖 Windows 请求 macOS、目标身份/能力冲突、远端失败和零写操作；在当前提交与固定数据集上产出 Windows/macOS 平台凭据。
- 生成版本化的最终指标冻结清单，绑定提交、数据集、Prompt、模型、工具协议、平台凭据和安全/质量门槛；只在确定性门禁通过后运行一次 Qwen 最终评测。
- 非目标：Windows Tool Gateway、Linux、复杂 Provider、自动组网、packet relay、showcase、任意网络/服务写入，以及改动现有 WireGuard、防火墙、路由、DNS、8080/8787 进程。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `autonomous-incident-investigation`: 远端 incident 从“禁止误用本机工具”扩展为“只使用已授权目标 Gateway 的动态只读证据”，并保持无证据安全停止和人工操作边界。
- `agent-evaluation`: 增加 Windows/macOS 隔离跨节点产品验收与版本化最终指标冻结门禁。

## Impact

- 影响 Incident 调查编排、static Gateway peer 解析、Windows/macOS 应用组装、固定评测与平台验收脚本。
- 复用现有 `RemoteCapabilityLoader`、`FixedGatewayClient`、Tool Runtime、Gateway 策略、incident 存储和评测报告，不新增运行时依赖或第二套远端协议。
- 不改变公开写操作 API、数据库中的操作授权语义、Coordinator 数据面职责或现有网络配置。
