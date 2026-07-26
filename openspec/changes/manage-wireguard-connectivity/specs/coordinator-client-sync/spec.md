## ADDED Requirements

### Requirement: Agent 必须拉取并验证受管网络配置修订
Agent SHALL 使用逐节点凭据拉取所属 network 的 desired config，并在任何本地写入前验证签名
指纹、目标 node、协议、配置/父 revision、有效期、数量和字节预算。

#### Scenario: 收到合法下一 revision
- **WHEN** desired config 的父 revision 等于本地 applied revision
- **THEN** Agent SHALL 保存 pending config 并进入 L3 policy 和 Provider plan 阶段

#### Scenario: 收到跳跃或乱序 revision
- **WHEN** desired config 的父 revision 不等于本地 applied revision
- **THEN** Agent SHALL 拒绝应用并请求有界 full sync

### Requirement: 配置应用确认必须区分阶段和真实验证
Agent MUST 分别上报 pending、awaiting-authorization、applying、applied、verified、rolled-back、
ownership-conflict 和 manual-intervention，并绑定配置 revision、幂等键和脱敏回执哈希。

#### Scenario: Provider 命令完成但验证失败
- **WHEN** apply 返回回执而独立 verify 未通过
- **THEN** Agent SHALL 上报失败/回滚状态，不得发送 verified acknowledgement

### Requirement: 网络同步必须独立于模型并受退避预算约束
受管网络同步和恢复 SHALL 在没有模型 Provider 时运行，并 MUST 使用单并发、超时、取消安全点、
快照预算和带抖动退避；失败不得阻塞本地资源、static peer 或现有操作恢复。

#### Scenario: 模型未配置且出现配置撤销
- **WHEN** Agent 同步到受管网络撤销修订
- **THEN** 确定性治理/Provider SHALL 处理本地授权与回滚，不调用模型

### Requirement: 路径状态上报不得泄露完整网络拓扑
Agent SHALL 只上报配置 revision、路径类型、候选计数、relay 身份摘要、握手/探测时间、稳定
错误码和有界指标；MUST NOT 上报私钥、完整用户路由、物理网卡清单或未经策略允许的 endpoint。

#### Scenario: 用户设备具有多个物理地址
- **WHEN** Provider 观察到不属于受管候选范围的物理接口
- **THEN** 同步请求 SHALL 排除这些地址和接口正文
