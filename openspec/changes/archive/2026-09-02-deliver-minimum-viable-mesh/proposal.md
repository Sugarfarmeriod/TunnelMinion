## Why

`deliver-minimum-viable-mesh` 最初把工程基线、Coordinator、节点身份、服务目录、受管
WireGuard、relay、Linux Provider、本地面板和发布交付放在同一个 change 中。当前仓库已经通过
多个更小的 change 交付了其中大部分基础能力，继续按旧 proposal 实施会重复主规格、绕过已经
收紧的安全边界，并把仍需验证的产品接线、Linux、relay 和打包工作重新混在一起。

本次只对旧 change 做规划对账：记录已经实现、仍然缺失、已被替代以及应拆为独立 change 的
内容。它不授权实现新功能，也不再作为 `/opsx:apply` 的输入。

## What Changes

- 将节点注册、心跳、撤销、能力/服务目录和 Coordinator 客户端同步归类为已经由
  `coordinate-agent-network` 交付并同步到主规格的能力。
- 将受管 WireGuard Provider、地址租约、签名配置、所有权、直连验证、回滚和
  last-known-good 归类为已经由 `manage-wireguard-connectivity` 交付并同步到主规格的能力。
- 将旧设计中的“普通 Coordinator 兼任受信 relay”标记为已被替代；relay 必须是独立、显式、
  可验证的数据面，后续由 `build-isolated-packet-relay` 承担。
- 将 Linux Provider、默认节点运行时接线、成品化本地目录体验和安装分发分别保留为独立
  change，不在本 change 中实现。
- 用审计台账替换 50 个全部未勾选但与现有实现严重不符的旧任务。

## Capabilities

以下名称只保留为本 change 的历史审计索引，不表示仍由本 change 新增规范。

### New Capabilities

- `node-enrollment`: 已由 `coordinator-node-registry`、`coordinator-client-sync` 等主规格取代。
- `mesh-connectivity`: 已拆为受管 Provider/direct、独立 packet relay 和 Linux Provider。
- `service-catalog`: 服务观察、Coordinator 目录与同步协议已实现；默认运行时接线另建 change。
- `local-dashboard`: 环回资源页与状态 API 已实现；成品化目录体验另建 change。

### Modified Capabilities

无。本次不修改主规格，只记录旧 delta 与当前主规格的对应关系。

## Impact

- 只修改本 change 已存在的 proposal、design、specs 和 tasks；不修改实现代码。
- 不修改已经归档的 change 或当前主规格。
- 不触碰 `docs/questions/`。
- 本 change 完成审计后保持为历史拆分记录，不应直接 apply 或把旧 delta 归档进主规格。
