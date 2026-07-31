## Why

TunnelMinion 已分别实现 Coordinator enrollment/目录同步、确定性服务观察和受管网络同步，但常规
Windows/macOS 节点启动仍只组装本地页面与静态 Gateway；用户必须依赖专用验收脚本才能把这些
能力连成持续运行的节点。现在需要把已经验证的组件接入一个可配置、可停止、可重启恢复的默认
节点生命周期，先形成真正可日常使用的纵向闭环。

## What Changes

- 增加显式的 managed node 配置，绑定 Coordinator endpoint、network/node、固定签名指纹、
  Gateway endpoint、同步预算和服务观察策略；配置和普通导出不得包含 refresh 凭据或其他秘密。
- 提供一次性 CLI enrollment 流程：读取短期 token、确认 Coordinator 指纹、注册稳定身份并把
  refresh 凭据写入现有秘密存储；普通启动不得从命令行参数或配置文件接收完整 token。
- 在 Windows/macOS 常规本地应用的 FastAPI lifespan 中启动并停止 Coordinator 目录同步、
  确定性服务快照和受管网络配置同步；后台故障不得阻塞本地页面、只读工具、静态 peer、操作
  到期或恢复。
- 周期性使用现有监听端口、进程和可选 Docker 只读适配器生成最小服务快照；主动 HTTP/协议
  探测默认关闭，启用时仍受现有工具预算和策略约束。
- 把 enrollment、目录同步、服务观察、managed config、last-known-good 和稳定错误状态接入现有
  环回资源 API/页面，不显示 token、refresh、assertion、签名正文、完整 endpoint 或用户路由。
- 以 Windows/macOS fake/本机测试和现有 A/B 隔离验收覆盖首次加入、普通启动、重启恢复、
  Coordinator 离线、无模型、服务变化、配置待批准和安全停止。
- 非目标：不实现 Linux、packet relay、NAT 穿透、新前端框架、一键安装、公共 Coordinator，
  不扩大 L3 授权，也不迁移或接管 `HomeMac` 与 B 手写 WireGuard 配置。

## Capabilities

### New Capabilities

- `managed-node-runtime`: 常规 Windows/macOS 节点对 enrollment、后台同步、确定性服务快照、
  受管配置状态、生命周期、恢复与本地可观察性的统一运行边界。

### Modified Capabilities

无。本 change 把现有主规格要求接入常规运行时，不改变 Coordinator、Provider、目录、治理或
跨节点诊断的规范语义。

## Impact

- 影响 `app.py`、`macos_app.py`、CLI、FastAPI lifespan、Agent Coordinator/network sync、服务
  快照组装、秘密存储和资源页面。
- 复用现有协议、SQLite/keyring/受限文件存储、Provider/governance、只读工具和 Gateway；不新增
  网络协议或模型依赖。
- 默认未配置 managed node 时保持当前本地应用和 static peer 行为；显式启用后，控制面失败仍
  必须安全降级。
- 真实 A/B 验收继续使用隔离数据目录、独立端口和既有授权，不修改生产 Gateway `8787`、模型
  `8082`、`HomeMac`、B 手写配置、Murus、防火墙或用户路由。
