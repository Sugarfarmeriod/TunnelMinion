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
- 新增 `GET /api/resources/overview` 强类型聚合读模型，并扩展
  `GET /api/operations/{operation_id}` 详情，使前端直接消费服务端给出的来源、新鲜度、稳定错误码、
  owned resources、verification、cleanup record 和 manual action，而不是自行拼装或猜测状态。
- 修正 Windows/macOS 应用装配，让真实 Coordinator cache/status 与 network path evidence 进入总览。
- 本机 Web 增加 Host、Origin、Fetch Metadata 和 `X-TunnelMinion-Request: same-origin` 写请求边界；
  旧页面同步遵守该边界，无 Origin/Fetch Metadata 的本机 CLI 保持兼容，且不开放跨站 CORS。
- 固定 Node.js 22.14.0、npm 10.9.2、`package-lock.json` 与 `npm ci`；采用轻量自有设计系统和少量
  无样式可访问 primitives，浏览器门禁覆盖 Chromium、WebKit、320 CSS px 与 200% zoom。
- 将 React 构建产物纳入 Python package 的可重复构建，并扩展现有运行包校验/安装流程消费 v2；
  但不在本 change 新建安装器产品，也不交付自动升级、开机自启或独立公网前端。
- React 构建物通过单一 `build/frontend-dist` 暂存区进入 wheel 与 PyInstaller package；构建器输出
  package manifest v2，记录每个资源的相对路径、摘要、大小、类型、整体摘要与文件数；现有运行包
  校验/安装流程增加 v2 支持并继续兼容已有 v1，但不在本 change 新建另一套安装器。
- React 成为默认入口后，旧内嵌页面至少保留一个完整发布周期；切换后仍提供明确的回退路径，
  删除旧页面必须另建 change。

## Capabilities

### New Capabilities

- `local-product-interface`: 规定仅本机 React 产品界面的统一导航、节点/服务状态、聊天、审批、
  记忆、确定性降级、可访问性、安全渲染和构建交付行为。

### Modified Capabilities

无。现有 `agent-conversation`、`approved-operation-workflow`、`context-and-memory` 和 Coordinator
相关主规格继续定义后端行为；本 change 只通过新产品界面消费这些契约，不放宽其权限和数据边界。
`package-manual-node-runtime` 仍为并行 active change；若它先进入主规格，本 change 在实现前必须补充
对应 MODIFIED delta，不能以“无”跳过 package v2 的规格协调。

## Impact

- 新增独立前端源码、锁文件、构建与测试配置，以及由 FastAPI 提供的版本化静态资源。
- 调整当前 `src/tunnelminion/web/` 的页面装配和 package 构建流程；`/chat`、`/resources`、
  `/operations`、`/memories` 在保留周期内继续提供原 legacy 页面，另提供 `/legacy/*` 稳定别名；
  React 使用 `/app/*`，默认 `/` 只切换入口映射。现有响应保持兼容，但所有浏览器写请求和旧页面
  须同步采用统一的本机请求门禁。
- CI 增加前端格式、类型、单元、组件、安全和生产构建门禁，并继续执行 Python 全量门禁。
- Windows 与 macOS package 需要证明离线包含相同前端资源，且配置、数据和秘密仍与程序目录分离。
- 不修改 WireGuard、客户防火墙、Gateway 认证、Coordinator 部署、模型秘密或自启动策略。
- package manifest v2 与仍在收敛的 `package-manual-node-runtime` 变更显式协调：v1 不得被静默改写，
  v2 必须记录 Python/npm lock 摘要、frontend dist 摘要、文件数和 npm/Python 许可证来源。
