## Why

TunnelMinion 已能在用户预先搭好的 WireGuard 上完成节点注册、目录发现、跨节点诊断和受控临时
共享，但仍要求用户手工分配地址、交换公钥、维护 peer 与解释断线。下一阶段需要把“连接本身”
纳入确定性 Harness，同时证明自动化不会接管或破坏当前 `HomeMac` 与 B 的手写配置。

## What Changes

- 增加 `NetworkProvider` 边界，明确区分 `observe-only` 与 `managed`；Windows、macOS 首版只
  允许管理具有 TunnelMinion 所有权记录的独立 WireGuard 接口、配置、peer、地址和路由。
- 扩展 Coordinator 控制面，分配受管虚拟地址、保存 WireGuard 公钥与候选 endpoint、发布有
  修订和目标绑定的配置；私钥始终在所属节点生成和保存。
- 为首次创建/导入、地址或路由变化、relay 启用和删除建立本机预览、风险分级、批准、验证和
  回滚；同一已批准策略内的幂等收敛可自动执行，模型永不持有批准或 Provider 调用权。
- 建立点对点候选探测、直连优先、明确的 `direct`/`relayed`/`degraded` 状态和 last-known-good
  降级；relay 只能由显式配置的专用节点承担，不能把普通 Coordinator API 静默变成流量中继。
- 建立所有权指纹、配置快照、崩溃恢复、卸载清理和 A/B 前后不变性门禁；任何无法证明所有权
  的资源只能报告和人工处理。
- 真实 A/B 首轮只在独立测试接口并行验收，不切换生产 Gateway `8787`、模型 `8082` 或现有
  `HomeMac` 流量；不自动修改 Murus、Windows 防火墙、用户路由、DNS 或物理局域网配置。
- 本 change 不实现 Linux Provider、n2n、公共 SaaS、企业 RBAC、通用防火墙管理、DNS 管理、
  任意子网路由、全局局域网扫描或无人确认的生产网络迁移。

## Capabilities

### New Capabilities

- `managed-network-provider`: 平台 Provider 模式、受管资源所有权、配置应用、验证、恢复与清理。
- `managed-mesh-connectivity`: 地址分配、候选交换、直连/relay 路径选择、修订收敛与控制面降级。

### Modified Capabilities

- `coordinator-node-registry`: 节点注册增加受管网络公钥、地址租约和候选 endpoint 的最小化控制面边界。
- `coordinator-client-sync`: Agent 增加受管配置修订拉取、路径状态上报、幂等应用和 last-known-good 降级。
- `operation-policy`: 增加首个受治理的 L3 网络操作，仅允许确定性 Provider 在本机批准策略内执行。
- `cross-node-diagnostics`: 目录 endpoint 选择增加受管路径状态，并保留显式 static peer 回退。

## Impact

- 影响 Coordinator 契约/SQLite、Agent 同步器、Windows/macOS 平台适配层、操作治理、资源页面、
  安全审计、卸载恢复、评估数据集和 A/B 验收脚本。
- 需要调用已安装的 WireGuard 官方工具/服务，但不在 Python 中重写 WireGuard 协议；新增依赖
  必须先通过 spike 和锁文件门禁。
- 新写路径属于 L3 高敏感操作，实施分支不得在没有独立测试接口、回滚证据和用户明确授权时
  修改真实 A/B 网络。
