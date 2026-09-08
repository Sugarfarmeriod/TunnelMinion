## ADDED Requirements

### Requirement: 隔离产品验收必须连通 incident 与人工操作入口

评估系统 MUST 使用固定、无秘密且不触碰真实网络的 HTTP fixture，在正式 React 产品中验证 Overview 待办和 Incident → 候选计划表单 → Operation 详情的组合路径。验收 MUST 证明打开预填入口不会产生写请求、明确确认只创建一次 Operation、目标端审批边界保持不变，并 SHALL 验证 Operation API 失败不破坏 incident 与资源总览。

#### Scenario: 用户从远端 local-only incident 发起候选处理
- **WHEN** 隔离 fixture 提供已确认 incident、同一新鲜 service、合格 peer 和现有操作创建响应
- **THEN** 浏览器预填目标与端口，在用户确认前产生零 POST，并在确认后只创建一次 Operation 并进入同一 `operation_id` 详情

#### Scenario: Overview 显示待本机处理队列
- **WHEN** fixture 同时包含目标端待批准、请求端待执行、远端等待和已结束 Operation
- **THEN** Overview 只突出需要当前用户介入的记录，且每项链接到现有详情

#### Scenario: Operation 摘要读取失败
- **WHEN** fixture 使 `/api/operations` 返回失败而 `/api/resources/overview` 与 incident 详情正常
- **THEN** 浏览器仍展示资源和 incident，只把待办卡标为不可用且不发起任何写请求
