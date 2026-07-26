## Why

TunnelMinion 已具备受管 Provider 和 direct 路径控制，但现有证据不足以安全实现 relay：匿名 UDP
转发会形成滥用与放大面，普通 Coordinator 或生产 A/B 也不能被静默提升为中继。需要一个独立
change，在隔离三节点环境中先固定协议、身份、隔离和容量边界，再实现并验证不透明 packet relay。

## What Changes

- 定义专用 relay 数据面协议，只转发端到端加密的 WireGuard packet，不持有节点私钥。
- 为 relay 服务、客户端与会话建立独立身份认证、network/node 隔离、反重放和过期回收。
- 建立并发、每节点/每 network、带宽、datagram 大小、超时和全局容量预算，拒绝匿名转发与放大。
- 将管理员启用/撤销的 `relay-capable`、`active` 角色绑定到路径 revision 和审计。
- 在隔离三节点环境验证 direct→relayed→direct、relay 离线、容量耗尽、撤销和恢复。
- 记录真实延迟、吞吐、切换中断与资源成本；证据完成前状态保持 `degraded`。
- 非目标：不复用普通 Coordinator API 监听，不让生产 A/B 兼任 relay，不实现通用 NAT 打洞，
  不自动修改防火墙/IP forwarding，不把受信 WireGuard hub 作为静默降级方案。

## Capabilities

### New Capabilities

- `isolated-packet-relay`: 专用不透明 packet relay 的协议、身份、隔离、容量、路径验证、撤销与恢复。

### Modified Capabilities

无。与受管网络、Coordinator 和路径控制的集成先通过当前
`manage-wireguard-connectivity` change 的显式契约衔接；如主规格同步后需要改变既有要求，再在
实现前新增对应 delta spec。

## Impact

- 新增独立 relay 客户端/服务端模块、协议契约、会话与容量存储、审计和隔离三节点测试环境。
- Coordinator 只发布经过管理员启用和能力验证的 relay 元数据，不承载 packet 数据面。
- Agent 路径控制器增加 relayed 验证适配器，但在 relay 证据不足时继续返回 `degraded`/static。
- 部署需要一个独立第三节点、单独监听端口和管理员预配防火墙；不会改变现有 A/B 生产接口、
  `HomeMac`、`utun4`、Murus、Gateway `8787` 或模型 `8082`。
