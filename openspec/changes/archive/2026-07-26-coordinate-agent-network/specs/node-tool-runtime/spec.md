## ADDED Requirements

### Requirement: Runtime 必须发布最小化能力摘要
Tool Runtime SHALL 从注册表生成版本化能力摘要，包含稳定名称、主/次版本、平台、风险等级、
可用性和 schema 哈希；摘要 MUST 排除秘密、工具正文和不允许远端使用的工具。

#### Scenario: 生成远端能力快照
- **WHEN** Agent 为 Coordinator 构建能力完整快照
- **THEN** 快照 SHALL 只包含当前平台注册且允许发布的能力摘要

### Requirement: 动态远端工具集合必须通过多维过滤
Runtime MUST 依次按 network、节点状态、endpoint 新鲜度、调用授权、平台、协议/工具版本、
风险等级和任务阶段过滤目录能力；模型 SHALL 只看到最终候选集合。

#### Scenario: 节点 stale 但能力仍在缓存
- **WHEN** 目录把 B 标记 stale
- **THEN** B 的远端工具 SHALL 不进入要求实时状态的当前模型工具集合

#### Scenario: 工具主版本不兼容
- **WHEN** B 只发布 A 不支持的工具主版本
- **THEN** Runtime SHALL 排除该工具并记录 `version_incompatible`

### Requirement: 工具选择记录必须关联目录修订
每次动态远端工具选择 SHALL 记录 network、目标 node ID、server revision、目标直连能力修订、
候选/保留/排除数量和脱敏排除原因，不记录认证材料或完整 schema。

#### Scenario: 评估错误工具选择
- **WHEN** Agent 未获得预期远端工具
- **THEN** 运行记录 SHALL 能区分目录缺失、节点状态、授权、平台、版本、任务阶段和直连冲突

### Requirement: 目录不得替代最终工具和操作策略
Coordinator 条目、在线状态或能力摘要 MUST NOT 授予执行权限；目标 Tool Gateway、Tool Runtime、
Operation Policy 和本地批准 SHALL 在每次调用继续执行最终校验。

#### Scenario: 目录包含未授权写操作
- **WHEN** 畸形或被攻破的 Coordinator 条目声称 B 支持已批准的写操作
- **THEN** A 不得因此向普通模型暴露该操作，B 的确定性策略仍 SHALL 拒绝未授权执行
