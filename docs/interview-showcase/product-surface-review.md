# PR #40 产品页面承载预审

status: draft-pr-verified
publication: false
pull-request: 40
source-head: 61398b76d01b3836dc6023f74b0ba3d17ef7cbb4
task-3.2-complete: false

本记录只读复核 PR #40 的精确 Draft head。它不是稳定 `main` 证据，也不表示 PR #40 已解决冲突或可以发布最终素材。任务 3.2 要求在 PR #40 合并后复核，因此本轮只建立复核清单、候选缺口和来源路径，不勾选任务。

## 主流程承载结论

现有页面已经能承载“资源入口 → 只读诊断 → 候选处理 → 目标节点批准 → 验证与恢复”的大部分故事：主演示应以 Overview、Chat、Operations 为主，Memories 与 Settings 作为技术深挖入口。当前不能裁决“无需聚合视图”，因为 Overview 明确不公开服务 host，只显示协议、端口、所属节点、状态和证据；完整访问地址仍是合并后必须复核的候选缺口。

| 故事阶段 | 页面 | Draft head 已证明的承载能力 | 证据来源 | 合并后复核 |
|---|---|---|---|---|
| 设备、服务与状态入口 | Overview | 分域展示本机 Runtime、模型、Coordinator、网络路径、已知节点和已知服务；服务项显示协议、端口、所属节点、状态、来源、证据时间与新鲜度。`accessibility` 是契约字段，页面未展示 | `frontend/src/features/overview/OverviewPage.tsx`；`frontend/src/features/overview/OverviewPage.test.tsx`；`src/tunnelminion/web/overview.py` | 完整访问地址未被当前服务摘要公开，不能把端口冒充地址；可访问性也需合并后复核 |
| 只读诊断与证据 | Chat | Thread、Run、公开事件、工具状态、tool run ID 和最终回答引用证据均有独立结构和画面；运行可取消，失败/中断不伪装成功 | `frontend/src/features/chat/ChatPage.tsx`；`frontend/src/features/chat/contracts.ts`；`frontend/src/features/chat/ChatPage.test.tsx` | 重新确认演示数据能从诊断自然过渡到精确 Operation，而不是靠讲解跳页 |
| 候选、批准和执行状态 | Operations | 列表按 operation ID 进入详情；详情展示目标节点、授权依据、验证方法、状态历史和服务端允许动作；批准前复读，未知写入不自动重放 | `frontend/src/features/operations/OperationsListPage.tsx`；`frontend/src/features/operations/OperationDetailPage.tsx`；对应测试 | 重新确认 PR #59 稳定投影与页面字段一致 |
| 验证、恢复与清理 | Operations | 详情区分请求节点验证、操作所有资源、清理记录和本机主动撤销；陈旧详情禁用写动作 | `frontend/src/features/operations/OperationDetailPage.tsx`；`frontend/src/features/operations/OperationDetailPage.test.tsx` | 用稳定基线真实 Operation 复核完整生命周期，不以 fixture 代替 |
| 记忆边界深挖 | Memories | 长期记忆按用户、网络、节点精确作用域读取；修正、删除、清空均显式确认，未知结果只重读不重放 | `frontend/src/features/memories/MemoriesPage.tsx`；`frontend/src/features/memories/MemoriesPage.test.tsx` | 不塞入三分钟主演示，作为作用域与幂等深挖入口 |
| 模型与降级深挖 | Settings | 展示脱敏模型状态、Runtime/Coordinator/网络路径和诊断包；明确模型不可用时确定性资源、记忆和既有清理仍可使用 | `frontend/src/features/settings/SettingsPage.tsx`；`frontend/src/features/settings/SettingsPage.test.tsx` | 不展示或采集秘密；用稳定基线复核无模型降级文案 |

## 已确认的候选缺口

### 完整访问地址

`KnownServiceOverview` 明确不公开 host；Overview 当前只组合协议、端口和节点短 ID。因此“设备/服务与访问地址”中的完整地址尚未由 PR #40 Draft head 证明。该缺口会继续阻止任务 4.2 完成，也必须在 PR #40 合并并与 PR #59 稳定契约对齐后重新判断。

### Chat 到 Operation 的可追溯过渡

Chat 已显示 tool run ID 和 Evidence 引用，Operations 已按 operation ID 提供详情；本次只读检查没有把二者之间的直接产品跳转视为已证明。稳定基线复核应使用同一条演示数据检查 Thread → Run → Operation → Evidence 是否无需口头拼接。

## 聚合视图决策门

当前不规划、不实现最小只读聚合视图，也不修改前端。只有同时满足以下条件后才允许作该决定：

1. PR #40 已合并到明确稳定基线，PR #59 所需状态投影也已稳定；
2. 在同一稳定提交和同一演示数据上重新执行五页复核；
3. 完整访问地址或跨对象追溯仍有可复现、可引用的产品缺口；
4. 现有页面或现有只读字段的更小调整无法承载故事。

在这些条件满足前，聚合视图仅是被门禁的候选方案，不是待实现承诺；任务 3.2 保持未完成。
