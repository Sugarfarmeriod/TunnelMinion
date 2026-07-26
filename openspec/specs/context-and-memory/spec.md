# context-and-memory Specification

## Purpose

规定短期对话、工作流状态、工具制品和长期记忆的分层存储、作用域、确认、修订、删除与检索
边界，并确保实时状态不被陈旧记忆覆盖、跨用户与跨网络数据不会混入当前上下文。

## Requirements
### Requirement: 系统分离四类状态

Runtime MUST 分别管理实时工具状态、短期对话上下文、工作流 checkpoint 和长期记忆。不同类别 SHALL 使用独立生命周期与访问接口，不得把实时快照无条件写成长久记忆。

#### Scenario: WireGuard 状态发生变化

- **WHEN** 新工具调用发现 peer 握手状态与上一轮对话不同
- **THEN** Agent 使用新工具结果作为当前事实，且旧状态不因存在于历史消息而覆盖新结果

### Requirement: 单次模型调用具有上下文预算

Context Builder MUST 对消息、工具 schema、工具结果和记忆分别应用预算，并在超出预算前执行工具过滤、结果引用、窗口裁剪或滚动摘要。Runtime MUST 记录实际上下文规模。

#### Scenario: 节点拥有大量服务

- **WHEN** 远端工具返回的服务目录超过单次模型结果预算
- **THEN** 完整结果保存为本地 artifact，模型只收到与问题相关的分页/摘要及 artifact 引用

#### Scenario: 对话历史过长

- **WHEN** 线程历史超过消息预算
- **THEN** Runtime 保留近期必要消息和经验证摘要，而不是把全部历史发送给模型

### Requirement: checkpoint 在进程重启后可恢复

工作流 checkpoint MUST 持久化 thread/run 的公开状态、工具轨迹引用、预算和完成状态。Runtime 重启后 SHALL 能读取已完成线程，并将中断 run 标记为 interrupted；MVP 不得未经用户操作自动重放远端工具。

#### Scenario: Runtime 在工具调用后重启

- **WHEN** Runtime 在 run 尚未完成时异常停止并重新启动
- **THEN** 该 run 显示为 interrupted，已有证据可查看，但系统不会自动重新调用工具

### Requirement: 长期记忆只保存允许的稳定信息

长期记忆 MAY 保存用户确认的节点别名、偏好、安全约束和稳定服务事实，但 MUST NOT 保存 API key、私钥、认证头、完整系统日志或未经确认的模型推测。每条记忆 SHALL 记录来源、作用域和更新时间。

#### Scenario: 用户确认节点别名

- **WHEN** 用户确认“B 是家里的 Mac”作为长期事实
- **THEN** Runtime 在当前用户/网络作用域保存该记忆，并可在后续相关对话检索使用

#### Scenario: 模型猜测服务类型

- **WHEN** 模型仅根据端口推测某服务是游戏服务器但用户未确认
- **THEN** 推测不会自动写入长期记忆

### Requirement: 用户可以查看、修正和删除长期记忆

本机用户 MUST 能查看长期记忆及来源、修改错误事实、删除单条记忆和清空指定作用域。删除后新上下文 MUST 不再检索已删除内容。

#### Scenario: 删除错误服务记忆

- **WHEN** 用户删除关于 B 某端口用途的长期记忆
- **THEN** 后续对话不再把该记忆作为事实，并通过实时工具重新判断

### Requirement: 不同会话和节点的记忆隔离

Memory Store MUST 使用用户、网络和节点 namespace 隔离数据。远端节点工具不得读取本机对话、模型配置或不属于共享作用域的长期记忆。

#### Scenario: A 调用 B 的工具

- **WHEN** A 请求 B 的服务状态
- **THEN** B 只返回工具 schema 允许的系统结果，不返回 B 的聊天历史或本地用户偏好
