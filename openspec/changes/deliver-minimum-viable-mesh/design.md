## Context

旧设计声称“TunnelMinion 当前没有实现代码”，并计划一次性交付完整 mesh。该前提已经失效。
截至 `main` 的 `c0368c7`，仓库已有 Windows/macOS 本地 Agent、只读工具、跨节点 Gateway、
Coordinator 注册和目录、受管 WireGuard Provider、direct 路径控制、操作治理、评估脚本及真实
A/B 验收证据。

完成度不能只按模块数量判断。常规 `tunnelminion` 启动仍主要组装本地聊天、资源页和静态
Gateway；Coordinator 同步、自动服务快照和受管路径主要由专用脚本、测试或验收 harness 组装。
Linux Provider、packet relay、成品化目录 UI 和安装分发尚未交付。

## Goals / Non-Goals

**Goals:**

- 将旧 proposal、design、specs 和 tasks 与当前主规格、代码及归档 change 对账。
- 明确四类结论，避免把已交付工作继续显示为未开始。
- 保留可追溯的历史 requirement/scenario，同时声明其当前规范归属。
- 为下一个最小 change 划定边界。

**Non-Goals:**

- 不实现、重构或删除任何代码。
- 不修改主规格或已归档 change。
- 不把缺失的 Linux、relay、产品 UI 或打包重新合并成一个实现 change。
- 不把真实 A/B 的一次性授权扩展为新的网络写入授权。

## Decisions

### 1. 已经实现

| 旧规划内容 | 当前证据与规范归属 |
|---|---|
| Python 3.11+ 工程、类型/测试/安全门禁、平台适配边界 | `pyproject.toml`、`scripts/quality.py`、平台模块及测试 |
| enrollment token、稳定 node/network、refresh 凭据、心跳、撤销、版本拒绝 | `coordinator-node-registry`、`coordinator-client-sync`；`coordinate-agent-network` 已归档 |
| 能力/服务完整快照、修订、TTL/新鲜度、目录查询和无模型降级 | `coordinator-service-directory`、Agent Coordinator 同步器及目录测试 |
| 本机监听、进程、Docker、WireGuard 和可达性只读工具 | Windows/macOS adapters、Tool Runtime、跨节点诊断主规格 |
| Provider 契约、所有权、签名 desired config、批准、apply/verify/rollback/recover | `managed-network-provider`、`managed-mesh-connectivity`；`manage-wireguard-connectivity` 已归档 |
| Windows/macOS 独立受管接口和 direct 路径真实验证 | 平台 Provider、路径控制器、受管连接 A/B 验收证据 |
| 环回本地资源页、Coordinator/路径脱敏状态 API | `web/resources.py` 及 Web 测试 |

“已经实现”表示代码、自动测试和对应阶段证据已经存在；不等于它们全部接入默认启动命令或已
达到可分发产品体验。

### 2. 仍然缺失

- 默认节点生命周期尚未统一组装 enrollment、Coordinator 后台同步、自动服务观察快照、受管
  配置同步、恢复和本地状态页；当前主要依赖专用脚本/harness。
- 本地资源页仍是面向开发者的 JSON 聚合页，没有完成按节点组织的服务目录、打开/复制操作、
  stale/local-only 原因解释和一致的产品级交互。
- 尚未证明陌生用户可以只通过常规 CLI 在干净环境中完成“加入 → 同步 → 查看 → 重启恢复”闭环。

这些缺口应由一个小型纵向 change 验收，而不是恢复旧 change 的全部范围。建议名称：
`integrate-managed-node-runtime`。

### 3. 已被替代

- “单一长期 TLS 控制通道”已被版本化 HTTP 快照/修订同步、短期签名 assertion、目标 Gateway
  直连复核和 static 降级取代；具体传输不再承担隐含授权。
- “设备密钥注册后直接返回网络配置”已被本机稳定身份、逐节点 refresh 凭据、短期 assertion、
  独立 WireGuard 公钥生命周期和签名 desired config 分层取代。
- “导入并管理用户现有 WireGuard 配置”已被更严格的 `observed-user` / `managed-owned` /
  `ownership-conflict` 边界取代；现有 `HomeMac` 和 B 手写配置只读观察，不允许接管。
- “普通 Coordinator 作为 WireGuard 回退路由”已被显式 relay 角色和独立 packet relay 设计取代；
  没有真实 relay 证据时必须保持 `degraded`/`static`。
- “三端同时首发”已被先完成 Windows/macOS A/B，再单独验收 Linux 的顺序取代。

### 4. 应拆成独立 change

| 独立主题 | 状态或建议 |
|---|---|
| 默认受管节点运行时接线 | 建议新建 `integrate-managed-node-runtime`，作为下一项最小交付 |
| 不透明 packet relay | 已有 `build-isolated-packet-relay`，当前 0/39，需第三节点与安全/性能预算 |
| Linux 节点与 NetworkProvider | 新建 `add-linux-node-provider` |
| 成品化本地节点/服务体验 | 新建 `improve-local-product-experience`，不得与安装打包混合 |
| 一键安装、升级、卸载和部署 | 新建 `package-one-click-deployment` |
| 游戏与更多服务识别 | 按路线图新建 `add-game-and-service-intelligence` |

### 5. 下一项最小交付优先运行时接线

`integrate-managed-node-runtime` 只应完成一个纵向闭环：在 Windows/macOS 常规启动入口中，以显式
配置启用 Coordinator enrollment/同步、确定性服务快照和受管路径状态；支持停止、重启恢复、
无模型降级，并在现有环回资源页显示结果。它不新增网络协议、不创建 relay、不支持 Linux、
不重写前端，也不扩大 L3 授权。

选择它而不是先做 relay，是因为现有后端已经足以形成可用闭环，而 relay 仍依赖第三节点、协议
选择、端口/防火墙和性能预算。选择它而不是先做 Linux，是因为先固定默认生命周期能减少第三
平台重复接线。

## Risks / Trade-offs

- [把测试通过误认为产品已完成] → 明确区分核心能力、默认运行时接线和可分发体验。
- [旧 delta 被误归档并重复写入主规格] → proposal 明确禁止直接 apply/archive；spec 标注当前归属。
- [运行时接线范围再次膨胀] → 下一 change 只接现有模块，不新增 relay、Linux、前端框架或安装器。
- [真实网络写入被审计工作隐式授权] → 本次无代码和网络写入；后续继续遵守本机 L3 批准与所有权门禁。

## Migration Plan

1. 本次只完成规划对账并通过 OpenSpec 校验。
2. 不对本 change 执行 `/opsx:apply`，也不把其历史 delta 同步到主规格。
3. 用户确认下一步后，为 `integrate-managed-node-runtime` 创建独立 proposal、design、specs 和 tasks。
4. Linux、relay、产品体验和打包分别保持独立评审与验收。

## Open Questions

- 常规节点启动是否采用单进程 lifespan 后台任务，还是本地 Agent、Gateway、Coordinator client
  继续保持同包多进程？
- enrollment 入口首版只提供 CLI，还是同时在环回管理页提供？
- 自动服务快照默认包含哪些来源：监听端口、进程、Docker 是否全部默认启用，主动探测是否默认关闭？
- `integrate-managed-node-runtime` 的验收是否只要求现有 Windows/macOS A/B，还是必须增加一台干净
  环境机器？
- Linux 首版目标发行版、systemd/非 systemd 范围和可用测试机尚未确定。
- packet relay 的第三节点、操作系统、管理员、测试端口及延迟/吞吐预算尚未确定。
