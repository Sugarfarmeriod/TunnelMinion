# 稳定 main 产品页面承载复核

status: main-verified
publication: false
pull-request: 40
source-head: 2e9b7957307e9fb378b8c052c4704b6dc2363cad
source-merge: aae69d4868e58f094a5ad5c002f4192afe762475
baseline-main: b21b00e68e2298bb5db6a5c75d3e8629a33e4d05
task-3.2-complete: true

本记录在包含 PR #40/#59 的稳定 `main` 上只读复核五个产品页面。任务 3.2 已完成；结论只裁决页面承载能力，不代表最终截图、录屏或真实 A/B 已完成。

## 主流程承载结论

现有页面能承载“资源入口 → 只读诊断 → 候选处理 → 目标节点批准 → 验证与恢复”的大部分故事：主演示以 Overview、Chat、Operations 为主，Memories 与 Settings 用于技术深挖。稳定代码仍不公开服务 host，Chat 也没有到对应 Operation 的直接跳转，因此完整故事尚需最小只读补强；不需要新增展示专用后端领域。

| 故事阶段 | 页面 | 稳定 main 已证明的承载能力 | 证据来源 | 结论 |
|---|---|---|---|---|
| 设备、服务与状态入口 | Overview | 分域展示 Runtime、模型、Coordinator、网络路径、节点和服务；服务项显示协议、端口、节点、状态和证据 | `frontend/src/features/overview/OverviewPage.tsx`；`src/tunnelminion/web/overview.py` | 完整访问地址未被当前服务摘要公开，不能把端口冒充地址；`accessibility` 是契约字段，页面未展示 |
| 只读诊断与证据 | Chat | Thread、Run、公开事件、工具状态、tool run ID 和最终回答引用证据均有独立结构和画面；运行可取消，失败/中断不伪装成功 | `frontend/src/features/chat/ChatPage.tsx`；`frontend/src/features/chat/contracts.ts`；`frontend/src/features/chat/ChatPage.test.tsx` | 重新确认演示数据能从诊断自然过渡到精确 Operation，而不是靠讲解跳页 |
| 候选、批准和执行状态 | Operations | 列表按 operation ID 进入详情；详情展示目标节点、授权依据、验证方法、状态历史和允许动作 | `frontend/src/features/operations/OperationsListPage.tsx`；`frontend/src/features/operations/OperationDetailPage.tsx` | 产品结构足够；主演示仍需同一条真实数据 |
| 验证、恢复与清理 | Operations | 详情区分请求节点验证、owned resources、清理记录和本机主动撤销；陈旧详情禁用写动作 | `frontend/src/features/operations/OperationDetailPage.tsx`；对应测试 | 产品结构足够；真实生命周期证据仍受阶段 5 门禁 |
| 记忆边界深挖 | Memories | 长期记忆按用户、网络、节点精确作用域读取；修正、删除、清空均显式确认，未知结果只重读不重放 | `frontend/src/features/memories/MemoriesPage.tsx`；`frontend/src/features/memories/MemoriesPage.test.tsx` | 不塞入三分钟主演示，作为作用域与幂等深挖入口 |
| 模型与降级深挖 | Settings | 展示脱敏模型状态、Runtime/Coordinator/网络路径和诊断包；模型不可用时确定性资源和既有控制仍可使用 | `frontend/src/features/settings/SettingsPage.tsx`；对应测试 | 足够承担深挖，不进入三分钟主线 |

## 已确认的候选缺口

### 完整访问地址

`KnownServiceOverview` 明确不公开 host；Overview 当前只组合协议、端口和节点短 ID。因此“设备/服务与访问地址”中的完整地址尚未由稳定 `main` 证明，该缺口继续阻止任务 4.2。

### Chat 到 Operation 的可追溯过渡

Chat 已显示 tool run ID 和 Evidence 引用，Operations 已按 operation ID 提供详情，但当前没有直接产品跳转。主演示若依赖口头查找 operation ID，会削弱 `Thread → Run → Operation → Evidence` 闭环。

## 最小补强计划

不新增聚合页面。未来最小产品 change 只评估两点：在现有 Overview 中提供经过安全裁剪的可访问地址；在 Chat 的公开 Operation 引用上增加到现有详情页的链接。只有这两点仍不能承载同一条演示数据时，才重新讨论只读聚合视图。
