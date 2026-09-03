## Context

主线已有固定 incident 数据集、离线 Investigation Agent、SQLite incident 存储、正式运行包夹具和 Playwright 产品验收。缺口是这些路径尚未在同一次 Windows 正式包验收中连起来，用户还看不到“页面真的能展示调查结果”的证据。

约束是不得读取系统密钥、调用真实模型、修改网络、占用现有产品端口或触碰 macOS。验收数据和进程必须位于自有临时目录并在结束后清理。

## Goals / Non-Goals

**Goals:**

- 复用固定离线场景向正式包夹具写入一条已收敛 incident。
- 通过正式 HTTP API 和 React Overview 验证卡片、详情、轨迹、结论及未知项。
- 在夹具回执中记录正常场景的 incident 数与模型调用数均为零。
- 保持现有密钥拒绝实现、环回监听和正式包进程清理边界。

**Non-Goals:**

- 不验证真实模型质量、真实后台自动发现、macOS 或双机 A/B。
- 不新增演示后端、模型 mock 服务、运行时开关、网络 Provider 或依赖。
- 不改变生产 incident、Overview 或 Agent 行为。

## Decisions

1. 扩展现有正式包夹具，而不是新增验收服务。夹具直接调用已有 `run_incident_scenario`，让真实 detector、Context Runtime、Tool Runtime 和 SQLite 存储产出页面数据；替代方案是手写数据库记录，但它绕过待验证链路。
2. 选择现有 `loopback-listener` 场景。它能展示两次只读工具选择、证据化结论和完整停止原因，且不触碰真实端口或远端节点。
3. 同一夹具先运行现有 `normal-refresh` 场景并把零 incident、零模型调用写入回执。Playwright 在刷新 Overview 前后校验回执和页面，不增加模型服务或网络拦截器。
4. 继续使用现有 `RejectingSecretStore`、closed-set 数据目录、独立 `127.0.0.1:4175` 正式包服务器和既有终止流程。任何密钥访问、目录越界或非环回监听均立即失败。

## Risks / Trade-offs

- [离线脚本模型不能代表真实模型质量] → 报告明确标记 `offline-script`，真实模型另行授权后再评估。
- [固定 incident 不能证明真机自动发现] → 只把结果表述为 Windows 产品体验走通，不声称发现链已在真实后台运行。
- [正式包构建耗时高于组件测试] → 本地先跑定向夹具与前端测试，正式包验收只跑 Windows/Chromium 一次；CI 复用既有矩阵。
- [固定时间导致页面显示旧时间] → 验收只断言证据和结论，不把时间新鲜度当作真实观测证明。
