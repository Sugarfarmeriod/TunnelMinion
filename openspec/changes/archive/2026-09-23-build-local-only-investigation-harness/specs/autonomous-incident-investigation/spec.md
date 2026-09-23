## ADDED Requirements

### Requirement: 跨节点 local_only 必须满足完整语义证据门

远端 `local_only` incident 只有在版本化 Skill 的目标进程、目标监听、私网状态和请求端可达性四类语义证据全部覆盖且无冲突时才 SHALL 确认为 `confirmed`。同一只读工具结果 MAY 覆盖多个语义要求；Runtime MUST 按语义覆盖而不是工具调用数量判定完整性。

#### Scenario: Windows 确认 macOS 环回监听
- **WHEN** 目标节点摘要证明私网可用，目标监听结果证明指定进程存在且端口仅绑定回环，并且 Windows 请求端对目标私网地址和端口的探测失败
- **THEN** Runtime SHALL 允许模型生成引用全部必要证据的 `local_only` 确认结论

#### Scenario: 缺少请求端可达性证据
- **WHEN** 目标进程、监听和私网状态已知，但请求端探测缺失、失败为不可用或未经执行
- **THEN** Runtime MUST 以 `insufficient_evidence` 收口并把请求端可达性列为 unknown，不得确认 `local_only`

#### Scenario: 监听证据与快照冲突
- **WHEN** 快照声明 `local_only`，但目标实时监听包含非回环绑定或没有匹配进程
- **THEN** Runtime MUST 保存冲突并禁止确认，不得用探测失败覆盖监听冲突

#### Scenario: 一个工具覆盖进程和监听
- **WHEN** 目标 `list_network_listeners` 成功结果同时包含匹配端口、回环地址、PID 和进程名
- **THEN** Runtime SHALL 同时标记目标进程与目标监听要求为已覆盖，不得为凑齐证据数量重复调用进程工具

### Requirement: 模型与程序必须保持职责分离

模型 SHALL 只在 Harness 暴露的当前允许步骤中选择下一证据、维护候选解释并生成公开报告；程序 MUST 决定 Skill 匹配、执行位置、可信参数、预算、证据覆盖、冲突检查和最终状态门禁。模型不得直接改变状态、调用写适配器或将常识视为实时事实。

#### Scenario: 模型提前确认
- **WHEN** 模型在四类语义证据未全部覆盖前返回 `evidence_sufficient`
- **THEN** 程序 MUST 拒绝确认并继续允许步骤或以证据不足结束，trace SHALL 记录被拒绝的停止尝试
