## Why

归档 change `2026-07-31-integrate-managed-node-runtime` 已将 managed config 治理、Provider 执行、路径状态和常规入口标为完成，但当前生产运行时只拉取、验签并保存 pending：它不读取 L3 授权、不调用 Provider，且仓库没有生产 `PathProbe` 或 Windows/macOS 常规入口的真实 path lifecycle。现场复核还确认 `NetworkOperationPolicy` 只在进程内保存 grant，现有治理 SQLite 只保存执行记录，并不存在原提案假定的“既有本机持久化 L3 授权”。因而 `improve-local-product-experience` 只能接入 Coordinator/cache 和陈旧占位 evidence，不能真实完成任务 3.3。

## What Changes

- 为 Windows 与 macOS 提供确定性、只读的平台 `PathProbe`，从实时系统事实形成有时间边界的 endpoint、handshake、唯一 peer 路由归属和 target probe 证据；不把缺少单独 `/32` host route 作为已批准远端连通的否决条件。
- 在现有本机网络治理 SQLite 数据库内增加唯一权威的 L3 grant repository，以独立表持久化批准与撤销状态；本机控制面保留唯一写权限，managed path lifecycle 只获得只读查询端口，不新建第二套数据库或并行授权来源。
- 建立一条共享的 managed path lifecycle，把既有 signed config 同步、权威 L3 授权读取、Provider governance、Provider、`DirectPathVerifier` 和 `DirectPathController` 串成单并发生命周期，并持久化可恢复的脱敏 selection/evidence 状态。
- 未找到与 network/node/revision/Provider/资源范围/计划摘要/观察指纹精确匹配的有效本机 L3 授权时，只保存 pending 并显示 `awaiting-authorization`；普通启动、模型、对话、记忆和服务观察均不得创建授权或触发网络写入。
- 让 Windows/macOS 常规本地应用暴露真实 selection、evidence、authorization、freshness 和稳定错误；证据过期后降级，显式刷新成功后才恢复，不复用旧证据宣称当前可用。
- 将同步、授权读取、Provider、probe、控制器、状态持久化和上报划分为独立故障域；保留 last-known-good/static 行为，失败不得扩大为 Gateway、模型或本地只读功能故障。
- 真实 Provider 写操作先在隔离 fake 与受批准的独立资源上通过恢复/故障矩阵，再允许进入隔离真实 A/B 验收；fake 或历史证据不得作为生产完成证据。
- 明确非目标：不修改客户防火墙、WireGuard、路由、模型、秘密、自启动、Coordinator/Gateway 协议或 Gateway 监听边界，也不承担前端、package 或 LPE 的 Penpot 外部图纸/图纸交付。

## Capabilities

### New Capabilities

- `managed-path-runtime`: 规定平台只读 PathProbe、授权门禁、Provider/governance/controller/verifier 单一生命周期、证据新鲜度、恢复与故障隔离。

### Modified Capabilities

- `managed-node-runtime`: 将已声明的 managed config 治理与路径状态要求收紧为 Windows/macOS 常规入口必须装配真实生命周期和真实脱敏状态，而非仅保存 pending 或返回占位值。

## Impact

- 预计后续实现影响 `tunnelminion.agent` 的 managed runtime/application 装配、`tunnelminion.network` 的路径状态持久化与生命周期协调、Windows/macOS 只读系统适配，以及对应的单元、架构、恢复和隔离验收测试。
- 复用现有 `managed-network-provider`、`operation-policy`、Provider plan/apply/verify/rollback/recover、所有权账本和网络治理 SQLite；在同一治理数据库中补齐 L3 grant 持久化，不从执行记录、内存 grant、signed config 或 operation L2 preauthorization 推断授权，也不改变本机控制面的唯一写权限与资源边界。
- `improve-local-product-experience` 的 3.3 依赖本 change 提供真实后端 selection/evidence/authorization；PR #44 的 Coordinator/cache、overview 契约与 stale 展示不构成本 change 的生产 path 完成证据。
- `package-manual-node-runtime` 只在本 change 合并后消费常规入口能力，不由本 change 修改构建、安装或自启动。Gateway 继续是独立私网进程与监听器，不复用本机环回生命周期，也不因本 change 扩大监听范围。
- 真实 A/B 验收依赖先获得明确批准的隔离接口、地址、端口与本机 L3 授权；在这些前置条件满足前只能完成 fake/只读/恢复门禁，不能宣称真实 Provider 或生产路径闭环完成。
