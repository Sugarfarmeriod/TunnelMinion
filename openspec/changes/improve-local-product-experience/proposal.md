## Why

TunnelMinion 已有聊天、资源、操作和记忆 API，但对应页面仍是分散嵌入 Python 的工程验收界面，
普通用户需要阅读原始 JSON 才能理解节点、服务和故障状态。现在后端安全边界与主要工作流已经
稳定，适合用独立 React 前端把现有能力组织成可日常使用、可降级且可测试的本地产品体验。

## What Changes

- 新增 React + TypeScript 本地单页应用，统一聊天、节点/服务总览、操作审批、记忆和设置入口。
- 首页以大白话区分本机运行、peer 可达、Coordinator 陈旧、模型不可用和需要人工处理等状态，
  不再把原始 JSON 当作主要交互。
- 复用现有 FastAPI、SSE、thread/run、资源、操作和记忆 API；仅在前端确实缺少稳定视图数据时
  增加最小、脱敏、可测试的本机 API，不改变 Gateway 或跨节点协议。
- 前端仍只由环回地址提供；无模型、无 Coordinator、没有 Murus 或没有防火墙日志权限时，
  确定性资源与操作控制继续可用并解释降级原因。
- 建立可访问性、键盘操作、窄窗口、加载/空/陈旧/失败状态、SSE 重连和浏览器安全门禁。
- 将 React 构建产物纳入 Python package 的可重复构建，但不在本 change 交付安装器、自动升级、
  开机自启或独立公网前端。
- 旧内嵌页面在迁移和回退验证完成前保留；切换后仍提供明确的回退路径。

## Capabilities

### New Capabilities

- `local-product-interface`: 规定仅本机 React 产品界面的统一导航、节点/服务状态、聊天、审批、
  记忆、确定性降级、可访问性、安全渲染和构建交付行为。

### Modified Capabilities

无。现有 `agent-conversation`、`approved-operation-workflow`、`context-and-memory` 和 Coordinator
相关主规格继续定义后端行为；本 change 只通过新产品界面消费这些契约，不放宽其权限和数据边界。

## Impact

- 新增独立前端源码、锁文件、构建与测试配置，以及由 FastAPI 提供的版本化静态资源。
- 调整当前 `src/tunnelminion/web/` 的页面装配和 package 构建流程；现有 API 保持兼容。
- CI 增加前端格式、类型、单元、组件、安全和生产构建门禁，并继续执行 Python 全量门禁。
- Windows 与 macOS package 需要证明离线包含相同前端资源，且配置、数据和秘密仍与程序目录分离。
- 不修改 WireGuard、客户防火墙、Gateway 认证、Coordinator 部署、模型秘密或自启动策略。
