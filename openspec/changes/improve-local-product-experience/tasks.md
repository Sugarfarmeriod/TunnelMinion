## 0. 基线、所有权与前置依赖

- [ ] 0.1 从最新 `origin/main` 创建 `feature/local-product-experience`，确认工作树干净且不读取或修改 `docs/questions/`
- [ ] 0.2 建立 workstream→owner→文件表；`package.json`、`package-lock.json`、共享 API client/schema、公共路由、Python 应用工厂、package manifest、OpenSpec tasks 与集成分支始终只有一个写入者
- [ ] 0.3 固定四张 legacy 页面、现有 API/OpenAPI、CSP、Windows/macOS package、关键用户流、压缩体积与加载/刷新延迟基线，fixture 不得读取秘密
- [ ] 0.4 确认 `package-manual-node-runtime` 相关运行包分支栈已进入 `main`；在此之前只允许 package 只读审计和 clean-room harness，不复制第二套 builder
- [ ] 0.5 每个阶段提交前复核 ownership、`git status`、diff、生成物和秘密范围；跨 owner 修改由 integration owner 串行合入

## 1. 契约与工具链 spike

- [ ] 1.1 固定 Node.js 22.14.0、npm 10.9.2、`packageManager`/engines、`package-lock.json` 与 `npm ci`
- [ ] 1.2 以最小 spike 验证 React + TypeScript + Vite、FastAPI 同源路径、`/app/*` 深链刷新及无 Node.js 的离线 package 加载
- [ ] 1.3 以包体积、可访问性、维护成本和许可证验证轻量自有 tokens 与少量无样式可访问 primitives；浏览器门禁固定 Chromium + WebKit
- [ ] 1.4 固定 `GET /api/resources/overview` 与 `GET /api/operations/{operation_id}` 的 Pydantic/OpenAPI schema、脱敏 fixture、未知枚举与稳定错误码矩阵
- [ ] 1.5 固定 Host authority 规范化、错误优先级、Origin/Fetch Metadata/`X-TunnelMinion-Request: same-origin` 威胁矩阵，并收集现有 CLI/测试客户端的真实方法、路径、Host 与端口作为兼容回归 corpus
- [ ] 1.6 确认节点/服务首页首版是否加入搜索与排序；未获得新产品决定时固定采用小型家庭/实验室规模的分组列表
- [ ] 1.7 运行 spike、依赖许可证/漏洞、生成物秘密、OpenSpec strict 和 Python 全量门禁，提交并推送工具链阶段

## 2. Foundation、安全与静态交付

- [ ] 2.1 建立 `frontend/`、React Router、TanStack Query、Zod、Vitest、Testing Library、MSW、Playwright、axe 与统一质量命令
- [ ] 2.2 实现同源 API client；浏览器 unsafe 请求统一发送 `X-TunnelMinion-Request: same-origin`，不在浏览器持久化秘密或完整诊断 payload
- [ ] 2.3 实现统一外壳、`/app/*` 路由、导航、design tokens、loading/empty/stale/error、Error Boundary 和非颜色状态语义
- [ ] 2.4 实现统一本机请求守卫：Host allowlist、精确同源 Origin、拒绝 cross-site Fetch Metadata、自定义请求头、稳定 403 错误码与无宽泛 CORS
- [ ] 2.5 将 legacy 页面的 unsafe 请求迁移到相同门禁，并覆盖合法同源、DNS rebinding、恶意/缺失 Origin、cross-site、缺失/错误 header、固定错误优先级与真实 CLI corpus 兼容契约测试
- [ ] 2.6 由 FastAPI 提供 `/app/*` 与 `/app-assets/*`，确保 fallback 不吞 `/api/*`/SSE；`index.html` no-store、哈希资源 immutable、生产 CSP 禁止内联和外部脚本
- [ ] 2.7 覆盖路径穿越、恶意 HTML/script、外部资源、缓存误报、CSP、浏览器存储与 320 CSS px/200% zoom 基础门禁，提交并推送 Foundation 代码检查点
- [ ] 2.8 Foundation 关闭前核对并按需更新主 FigJam 的安全边界与静态资源交付边界，同步最后核对日期、当前/历史标记和仓库主图链接；额度不足时允许后续独立切片继续，但 Foundation 阶段保持未关闭

## 3. Overview 与真实应用装配

- [ ] 3.1 由 foundation/integration 单一 owner 实现 `GET /api/resources/overview` 强类型聚合 endpoint，返回 local runtime/platform/version/package/readiness、model、Coordinator、path、节点、服务、来源、新鲜度和稳定错误码
- [ ] 3.2 由同一后端 owner 扩展 operation detail，加入脱敏 owned resources、verification、cleanup record、manual action、允许动作和 state
- [ ] 3.3 由同一应用装配 owner 抽取 Windows/macOS 共用 Coordinator/path helper，连接真实 status/cache/path/evidence/authorization，避免已配置状态误报 `unconfigured`
- [ ] 3.4 由后端 owner 为 overview/operation model、OpenAPI、应用工厂装配、配置损坏、凭据缺失、同步未开始和未知枚举补齐 100% 分支覆盖契约测试
- [ ] 3.5 仅在 `frontend/src/features/overview` 实现本机、节点、服务和关键依赖卡片，显示来源、证据时间、新鲜度和下一步动作，不把原始 JSON 当主界面
- [ ] 3.6 覆盖无模型、无 Coordinator、peer 离线、防火墙日志不可读、缓存过期和刷新恢复的组件/浏览器矩阵
- [ ] 3.7 在 Windows/macOS 开发运行中验收总览解释、加载/刷新延迟和初始 JS+CSS gzip 不超过 300 KiB，提交并推送 Overview 阶段

## 4. Chat 与公开 SSE

- [ ] 4.1 仅在 `frontend/src/features/chat` 实现 thread 新建、选择、继续、删除和消息展示，删除说明不得影响独立长期记忆
- [ ] 4.2 实现 run 发起、取消和公开工具轨迹，只展示允许的节点、工具、状态、耗时、tool run ID 与证据引用
- [ ] 4.3 以自有序号 reducer 实现 SSE `after` 恢复、去重、缺口、终态关闭、页面恢复和卸载清理，不自动重放工具或写请求
- [ ] 4.4 覆盖模型不可用、工具失败、取消竞态、重复/缺口事件、恶意文本、超长内容和未知写结果不得重放
- [ ] 4.5 运行现有 AI 评估与前后端门禁，提交并推送 Chat 阶段

## 5. Operations

- [ ] 5.1 仅在 `frontend/src/features/operations` 实现状态列表；进入 `/app/operations/:operationId` 必须按 ID 读取详情 API，不复用列表对象
- [ ] 5.2 批准、拒绝、取消和撤销前复读最新详情、允许动作与 state，使用对象明确确认、单次提交和超时后只查询不重放；复读不替代服务端状态迁移、授权与幂等冲突检查
- [ ] 5.3 展示目标证据、风险、访问者、端口、有效期、授权依据、verification、owned resources、cleanup record、manual action 与脱敏错误
- [ ] 5.4 覆盖重复点击、陈旧列表、过期批准、权限拒绝、网络超时、请求节点离线、rollback/cleanup failure 与模型/Coordinator 离线撤销
- [ ] 5.5 在隔离资源上执行 Windows/macOS 真实操作 UI 验收，确认零秘密输出，提交并推送 Operations 阶段

## 6. Memories、Settings 与 Diagnostics

- [ ] 6.1 仅在 `frontend/src/features/memories` 实现长期记忆来源、作用域、时间、原作用域内修正、删除和精确清空；首版不提供跨作用域移动
- [ ] 6.2 仅在 `frontend/src/features/settings` 实现模型、Coordinator、runtime、版本和可选诊断来源的脱敏状态；秘密只走现有受限配置流程且不得回显
- [ ] 6.3 实现诊断导出入口和大白话恢复步骤；没有 Murus、日志权限或厂商 VPN CLI 时核心功能仍可用
- [ ] 6.4 覆盖作用域隔离、删除竞态、错误修正、秘密字段、诊断脱敏、无模型清理、键盘与屏幕阅读状态提示
- [ ] 6.5 运行前后端全量门禁与 Windows/macOS 人工验收，提交并推送 Memories/Settings 阶段

## 7. 串行整合与浏览器质量门禁

- [ ] 7.1 integration owner 按 Overview → Chat → Operations → Memories/Settings 串行整合；每次整合后运行完整 Python、TypeScript、React 和浏览器门禁
- [ ] 7.2 Windows Chromium 与 macOS WebKit 覆盖 SPA 深链、CSP、缓存头、SSE、browser storage、写请求防护和关键流程
- [ ] 7.3 axe serious/critical 为 0；1280×720、320 CSS px、200% zoom 下总览、operation detail/确认框、chat、memory、settings 均可操作
- [ ] 7.4 供应链覆盖 npm/Python 全依赖漏洞与许可证，扫描 dist/source map/package staging 秘密；后续初始 JS+CSS gzip 增长超过 10% 必须说明

## 8. Package、迁移与发布验收

- [ ] 8.1 runtime 分支栈合并后，每次 clean-first 生成唯一 `build/frontend-dist`；wheel 通过 Hatch force-include、PyInstaller 通过显式 add-data 收集同一 dist
- [ ] 8.2 构建器发出 `runtime-package-manifest/v2`，记录 Python/npm lock digest、frontend dist digest、文件数、每项相对路径/摘要/大小/类型和 npm/Python 许可证来源；现有运行包校验/安装流程支持 v2 并兼容 v1，未知版本/路径穿越/损坏/遗漏/陈旧 dist fail closed，不新建第二套安装器
- [ ] 8.3 构建 Windows amd64 与 macOS arm64 package，验证相同 frontend dist 摘要及目标机无 Node、源码、网络仍可运行
- [ ] 8.4 React 默认入口发布时，以自动防删除契约保证原四页路径及 `/legacy/*` 别名在首发和紧随其后的版本继续存在，并演练只恢复默认 `/` 映射的回退；实际删除另建 change
- [ ] 8.5 执行真实 A/B：总览、聊天、peer、审批、记忆和模型/Coordinator/peer 降级；不修改客户防火墙、WireGuard、路由、模型、秘密或自启动
- [ ] 8.6 按安全 Mermaid 规则更新文档流程图并校验生成 SVG，不含 init/HTML/click/外链/脚本/事件处理器/`foreignObject`
- [ ] 8.7 最终发布前再次核对并按需更新主 FigJam，确认最后核对日期、当前/历史标记和仓库主图链接；额度不足可记录 blocker，但不得关闭 change 或合并最终发布 PR
- [ ] 8.8 运行所有质量、供应链、双平台 package、真实 A/B、文档链接、FigJam 与 OpenSpec strict 门禁，提交推送并创建最终 PR
- [ ] 8.9 合并后同步 `local-product-interface` 主规格、复核发布分支构建与回退，再归档 change
