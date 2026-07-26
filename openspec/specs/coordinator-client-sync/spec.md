# coordinator-client-sync Specification

## Purpose
TBD - created by archiving change coordinate-agent-network. Update Purpose after archive.
## Requirements
### Requirement: Agent 周期性同步心跳、能力与服务快照
已注册 Agent SHALL 使用逐节点凭据向 Coordinator 发送有界心跳，并在本地能力或服务发生变化
或刷新周期到达时发送版本化完整快照。

#### Scenario: 节点首次完成同步
- **WHEN** Agent 注册后首次连接 Coordinator
- **THEN** Agent SHALL 依次提交心跳、当前能力完整快照和服务完整快照，并保存服务器修订

#### Scenario: 本地没有配置模型
- **WHEN** Agent 未配置模型 Provider
- **THEN** 心跳、能力和服务同步仍 SHALL 正常运行

### Requirement: 每类快照必须幂等且单调
Agent MUST 为能力和服务快照分别维护本地序号、snapshot ID 和幂等键；Coordinator MUST 幂等
接受重复请求并拒绝低于当前已接受序号的乱序快照。

#### Scenario: 响应丢失后重复提交
- **WHEN** Coordinator 已提交快照但 Agent 未收到响应并使用相同幂等键重试
- **THEN** Coordinator SHALL 返回原 server revision，不重复生成目录变更

#### Scenario: 旧快照晚到
- **WHEN** 序号 8 的服务快照在序号 9 之后到达
- **THEN** Coordinator SHALL 拒绝序号 8 且保持序号 9 的活动目录

### Requirement: 同步器必须受资源与取消预算约束
同步器 MUST 对请求设置超时、取消、最大并发、快照数量和字节限制，并 SHALL 使用带抖动的指数
退避避免 Coordinator 故障时形成重试风暴。

#### Scenario: Coordinator 长时间离线
- **WHEN** 连续同步请求超时
- **THEN** Agent SHALL 在预算内停止本轮、增加退避并报告控制面离线，不阻塞本地 Agent

#### Scenario: 服务快照超过预算
- **WHEN** 本地服务记录数或序列化字节数超过协议上限
- **THEN** Agent SHALL 不发送部分完整快照，记录 `snapshot_too_large` 并保留上次服务器修订

### Requirement: 同步失败不得破坏已验证数据面
Coordinator 不可用、认证失败或目录同步失败 MUST NOT 停止本地工具、资源面板、静态 peer
直连、已有操作控制、租约到期或恢复器。

#### Scenario: Coordinator 进程停止
- **WHEN** A 与 B 的 Coordinator 客户端均无法连接
- **THEN** 两端本地资源 API 继续可用，已配置静态 peer 仍可按原策略直连

### Requirement: Agent 只能同步最小化元数据
能力快照 MUST 排除秘密示例和运行正文；服务快照 MUST 排除环境变量、完整命令行、业务响应
正文、模型配置、对话和长期记忆。

#### Scenario: Docker 元数据含敏感标签
- **WHEN** 本地 Docker 工具返回不允许进入目录的标签或环境相关字段
- **THEN** 同步器 SHALL 只保留允许的名称、镜像摘要、端口、来源和置信度

### Requirement: Agent 可以增量拉取目录修订
Agent SHALL 保存最后成功 server revision，并请求其后的有权目录变更；Coordinator MUST 在
修订不可继续时要求客户端重新获取有界完整目录。

#### Scenario: 没有新修订
- **WHEN** 客户端以当前最新 revision 请求目录
- **THEN** Coordinator SHALL 返回空变更和当前 revision，而不是重复完整目录

#### Scenario: 客户端 revision 已被压缩
- **WHEN** 客户端请求的旧 revision 不在保留窗口
- **THEN** Coordinator SHALL 返回 `full_sync_required`，客户端获取新的有界完整目录

### Requirement: 同步器必须向本地 Gateway 提供 Coordinator 授权状态
Agent SHALL 把所属 network 的节点状态、撤销修订和固定验证公钥更新到本地只读授权缓存；
Gateway MUST 对 Coordinator-managed 调用校验短期 assertion、节点状态和缓存 TTL。

#### Scenario: 收到节点撤销修订
- **WHEN** B 同步到 A 已被撤销
- **THEN** B 的 Gateway SHALL 立即拒绝 A 的 Coordinator assertion，即使 assertion 尚未到期

#### Scenario: 授权缓存超过 TTL
- **WHEN** Gateway 无法刷新 Coordinator 状态且授权缓存已过期
- **THEN** Gateway SHALL 对 Coordinator-managed peer 失败关闭，但不改变显式 static peer 策略

### Requirement: 同步状态必须可观测且脱敏
Agent SHALL 公开最近成功时间、server revision、退避状态、最近稳定错误码和快照计数，并
MUST NOT 公开完整凭据、认证头或被过滤正文。

#### Scenario: 用户查看资源面板
- **WHEN** Coordinator 同步处于退避
- **THEN** 页面 SHALL 显示目录可能陈旧、最后成功时间和错误类型，不显示认证材料

