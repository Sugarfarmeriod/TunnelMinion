## MODIFIED Requirements

### Requirement: 调查不得绕过既有操作审批

Investigation Agent MUST 只观察和报告。incident、根因结论或用户追问均 MUST NOT 自动创建、批准或执行写操作；产品只能为已确认、当前快照仍可定位且由现有安全操作支持的 incident 提供不可信候选计划预填。任何处理请求 SHALL 进入既有 Plan → Confirm → Execute → Verify → Rollback/Cleanup 流程，并重新校验当前证据、合格 peer、本地策略和目标节点授权。

#### Scenario: 用户要求处理已确认的远端监听问题
- **WHEN** 用户从已确认的远端 `local_only` service incident 详情明确要求处理
- **THEN** 系统只打开符合既有操作规格的预填候选计划表单，不把调查成功当作用户确认、授权或执行结果

#### Scenario: Incident 上下文已经陈旧或被篡改
- **WHEN** service 快照不再新鲜、目标 peer 不再合格，或浏览器修改了预填目标与端口
- **THEN** 既有操作流程重新校验并拒绝不匹配的候选计划，不继承 incident 结论或 URL 参数的可信度
