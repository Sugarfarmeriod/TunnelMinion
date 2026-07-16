## Why

> **实施顺序说明**：本 change 不再是第一优先级 MVP。项目先通过 `deliver-ai-agent-over-existing-mesh` 在现有 A/B WireGuard 网络上验证 AI Agent、工具调用和跨节点诊断；本 change 保留为后续自动组网与 Coordinator 基础设施工作，并在实施前再次拆分复核。

现有 Windows 节点 A 与 macOS 节点 B 已通过由 B 承担服务器角色的 WireGuard 隧道连通，因此无需先自动创建新网络即可验证 AI Agent 核心价值。在 AI-native MVP 得到真实评估后，再交付由协调节点、跨平台 Agent Runtime、受管 WireGuard 数据面和服务目录组成的纵向切片，以验证自动组网、点对点优先与必要中继等基础设施假设。

## What Changes

- 建立支持 Windows、macOS、Linux 的节点 Agent 基础运行形态。
- 提供协调服务，使节点能够注册、获得虚拟地址并接收网络配置。
- 使用 WireGuard 建立私有网络，优先使用可用的点对点路径，并在必要时经协调节点转发。
- 自动采集本机基础服务元数据，并同步形成网络内可浏览的服务目录。
- 在每个节点提供仅监听本机的 Web 面板，展示设备、连接状态和服务入口。
- 建立协议版本、错误状态和最小诊断信息，为后续演进保留兼容边界。
- 本次不包含细粒度访问控制、n2n、大模型增强、完整游戏识别、通用本地端口发布、一键安装或自动升级。

## Capabilities

### New Capabilities

- `node-enrollment`: 节点与协调服务之间的注册、身份持久化、虚拟地址分配和重新连接行为。
- `mesh-connectivity`: 基于 WireGuard 的节点连通、点对点优先策略、必要中继和连接状态报告。
- `service-catalog`: Agent 自动采集基础本机服务元数据，并在可信网络内同步和查询服务目录。
- `local-dashboard`: 每个节点通过仅监听本机的 Web 面板浏览节点、连接状态与服务入口。

### Modified Capabilities

无。

## Impact

- 新增协调服务、跨平台 Agent、共享协议模型和本地 Web UI 四个主要工程边界。
- Agent 与协调服务优先使用 Python 3.11+ 实现；Web UI 保持独立边界并优先选择低复杂度方案。
- 需要操作系统级 WireGuard 能力、受保护的节点凭据存储、网络配置权限和系统服务运行机制。
- 首轮集成测试复用现有 A/B 隧道，但自动化测试和 Agent 管理的接口必须使用独立名称与配置，不得覆盖现有 `HomeMac` 等用户配置。
- 协调服务将新增节点注册、心跳、配置分发和服务目录 API；Agent 将新增本地只读管理 API。
- 构建与测试需要覆盖 Windows、macOS、Linux，并增加至少两个节点的端到端组网环境。
- 该 change 建立后续 n2n Provider、访问策略、智能识别和临时转发所依赖的基础数据模型，但不实现这些后续能力。
