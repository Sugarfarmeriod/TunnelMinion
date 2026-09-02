# 稳定 main 产品页面承载复核

status: main-verified
publication: false
pull-request: 40
source-head: 2e9b7957307e9fb378b8c052c4704b6dc2363cad
source-merge: aae69d4868e58f094a5ad5c002f4192afe762475
readonly-flow-pr: 66
baseline-main: 6c20fda5aa57f6f178569fc1aa1f5a34df65b3d2
task-3.2-complete: true

本记录在包含 PR #40/#59/#66 的稳定 `main` 上只读复核五个产品页面。任务 3.2 已完成；结论只裁决页面承载能力，不代表最终截图、录屏或真实 A/B 已完成。

## 主流程承载结论

现有页面能承载“资源入口 → 只读诊断 → 候选处理 → 目标节点批准 → 验证与恢复”的故事：主演示以 Overview、Chat、Operations 为主，Memories 与 Settings 用于技术深挖。PR #66 已在原页面补齐完整只读地址和 Chat 到相关 Operation 的直接链接，没有新增展示专用后端领域。

| 故事阶段 | 页面 | 稳定 main 已证明的承载能力 | 证据来源 | 结论 |
|---|---|---|---|---|
| 设备、服务与状态入口 | Overview | 分域展示 Runtime、模型、Coordinator、网络路径、节点和服务；服务项显示完整只读访问地址、节点、状态和证据 | `frontend/src/features/overview/OverviewPage.tsx`；`src/tunnelminion/web/overview.py`；`src/tunnelminion/web/application_views.py` | 地址只作不可信文本展示，不等同于探测成功 |
| 只读诊断与证据 | Chat | Thread、Run、公开事件、工具状态、tool run ID 和最终回答引用证据均有独立结构和画面；共享 tool run ID 的 Operation 可直接进入现有详情页 | `frontend/src/features/chat/ChatPage.tsx`；`frontend/src/features/chat/ChatPage.test.tsx` | 只读列表失败时保留 Chat，不猜测或创建 Operation |
| 候选、批准和执行状态 | Operations | 列表按 operation ID 进入详情；详情展示目标节点、授权依据、验证方法、状态历史和允许动作 | `frontend/src/features/operations/OperationsListPage.tsx`；`frontend/src/features/operations/OperationDetailPage.tsx` | 产品结构足够；主演示仍需同一条真实数据 |
| 验证、恢复与清理 | Operations | 详情区分请求节点验证、owned resources、清理记录和本机主动撤销；陈旧详情禁用写动作 | `frontend/src/features/operations/OperationDetailPage.tsx`；对应测试 | 产品结构足够；真实生命周期证据仍受阶段 5 门禁 |
| 记忆边界深挖 | Memories | 长期记忆按用户、网络、节点精确作用域读取；修正、删除、清空均显式确认，未知结果只重读不重放 | `frontend/src/features/memories/MemoriesPage.tsx`；`frontend/src/features/memories/MemoriesPage.test.tsx` | 不塞入三分钟主演示，作为作用域与幂等深挖入口 |
| 模型与降级深挖 | Settings | 展示脱敏模型状态、Runtime/Coordinator/网络路径和诊断包；模型不可用时确定性资源和既有控制仍可使用 | `frontend/src/features/settings/SettingsPage.tsx`；对应测试 | 足够承担深挖，不进入三分钟主线 |

## 已关闭的只读缺口

### 完整访问地址

`KnownServiceOverview.access_address` 由已有 protocol、host 和 port 确定性组成，Overview 只按文本显示。IPv4、IPv6 与 hostname 分支均有定向覆盖。

### Chat 到 Operation 的可追溯过渡

Chat 使用当前 Run 与 Operation 已有的 `tool_run_ids` 做只读交集匹配，并链接现有 `/app/operations/{operation_id}` 详情页；没有匹配或列表读取失败时不影响原 Chat。

## 最小补强结论

PR #66 已完成上述两点并通过双平台 CI。无需聚合页面、聚合后端、新路由或新依赖；最终同一条真实演示数据仍由阶段 5 的授权与素材门禁负责。
