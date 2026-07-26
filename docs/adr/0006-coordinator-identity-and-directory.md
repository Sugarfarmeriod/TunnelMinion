# ADR-0006：Coordinator 身份、目录与数据面分离

## 状态

已接受，2026-07-26。

## 决策

TunnelMinion 增加一个只保存控制面元数据的 Coordinator。Agent API 只绑定显式 WireGuard
私网地址，管理员 API 只绑定环回地址。Coordinator 负责 network/node 注册、心跳、撤销、
能力与服务摘要目录，以及签发绑定 network、node、audience、协议和固定 120 秒 TTL 的
Ed25519 assertion；它不代理工具调用、操作、模型请求或业务流量。

Gateway 同时支持现有 static token 和 Coordinator-managed assertion。managed 请求必须使用
本地固定的验证公钥指纹和未过期授权缓存离线验签；目录撤销到达后立即拒绝，缓存到期后失败
关闭。不同节点最多容忍 assertion `issued_at` 和签名 key 激活时间向未来偏移 5 秒，但不会
延长 120 秒的到期时间。

动态远端工具按“稳定 node ID → 目录预筛选 → 短期 assertion → 目标 Gateway 直连能力复核
→ 固定 Tool Runtime”装配。endpoint、assertion 和 refresh 凭据均不进入模型上下文。

## 理由

- WireGuard 解决网络连接，不等于应用身份、节点撤销和工具授权。
- 中央目录可以减少手工复制 endpoint/能力配置，但数据面直连保留本地优先和故障隔离。
- static peer 与 managed peer 并存，使 Coordinator 故障不会破坏现有诊断和临时共享。
- 5 秒单向时钟容忍解决真实 A/B 约 1 秒偏差，同时保持到期边界保守。

## 后果

- Coordinator 不是公共 SaaS 控制面，不提供企业 RBAC，也不管理 WireGuard、防火墙或路由。
- 管理员必须确认验证公钥指纹，并保护 enrollment、refresh 和签名私钥。
- managed 缓存过期时必须明确显示故障，不能把旧目录伪装成实时状态。
- 自动组网、Linux Provider、公共部署和组织级权限需要独立 OpenSpec change。
