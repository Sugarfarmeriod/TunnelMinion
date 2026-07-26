# coordinator-service-directory Specification

## Purpose
TBD - created by archiving change coordinate-agent-network. Update Purpose after archive.
## Requirements
### Requirement: Coordinator 保存逐节点完整能力快照
Coordinator SHALL 按 network 和 node 保存当前能力完整快照，包括工具稳定名称、版本、平台、
风险等级、可用性、来源 snapshot 和接收时间。

#### Scenario: 节点能力发生变化
- **WHEN** 新完整快照移除 Docker 工具并提高另一工具次版本
- **THEN** 目录 SHALL 原子替换该节点能力集合并生成一个新 server revision

### Requirement: Coordinator 保存逐节点完整服务快照
Coordinator SHALL 按稳定 service ID 保存协议、地址、端口、可访问性、允许的进程/容器摘要、
来源、置信度、观测时间、接收时间和生命周期状态。

#### Scenario: 新服务出现
- **WHEN** 节点完整快照首次包含一个 TCP 服务
- **THEN** 目录 SHALL 创建活动服务记录并关联节点、snapshot 和 server revision

#### Scenario: 服务从完整快照消失
- **WHEN** 下一份已接受完整快照不再包含原服务
- **THEN** 目录 SHALL 在同一事务将原服务标记 stopped 或移出活动集合

### Requirement: 目录新鲜度必须由确定性状态计算
Coordinator MUST 根据节点状态、服务器接收时间和配置 TTL 计算节点、能力和服务的
`fresh`、`stale`、`offline` 或 `revoked`，不得由模型或客户端声明覆盖。

#### Scenario: 节点心跳过期
- **WHEN** 节点进入 offline
- **THEN** 其能力和服务 SHALL 同时标记 offline，查询不得给出当前可用操作

#### Scenario: 服务快照旧于服务 TTL
- **WHEN** 节点仍在线但服务快照超过 TTL
- **THEN** 服务 SHALL 标记 stale，不能作为实时端口结论

### Requirement: 目录查询必须有界、可过滤和稳定分页
有权客户端 SHALL 能按 node ID、在线状态、平台、工具名称/版本、服务协议、端口、可访问性和
新鲜度查询目录；响应 MUST 有数量/字节上限和稳定分页游标。

#### Scenario: 查询在线且支持指定工具的节点
- **WHEN** A 查询所属 network 内 fresh 且支持兼容 `list_docker_services` 的节点
- **THEN** Coordinator SHALL 只返回匹配的有权节点摘要和下一页游标

#### Scenario: 请求超过页面上限
- **WHEN** 客户端要求超过最大页面大小
- **THEN** Coordinator SHALL 拒绝或限制到服务器上限，不返回无界目录

### Requirement: 目录必须按 network 与调用身份隔离
节点只能读取所属 network 中策略允许的目录字段；管理员可读取本机管理范围。查询 MUST NOT
通过计数、错误差异或分页游标泄露其他 network。

#### Scenario: 跨 network 枚举
- **WHEN** 节点尝试使用另一 network 的过滤器或分页游标
- **THEN** Coordinator SHALL 返回 `forbidden` 或无效游标，不透露目标记录

### Requirement: 目录不得保存业务正文和节点秘密
Coordinator MUST NOT 保存模型密钥、Gateway token、节点凭据、WireGuard 私钥、长期记忆、
对话、完整工具结果、环境变量或服务业务响应正文。

#### Scenario: 服务快照包含未知字段
- **WHEN** Agent 提交 schema 未声明的正文或秘密字段
- **THEN** Coordinator SHALL 在持久化前拒绝整个快照并记录脱敏 schema 错误

### Requirement: 目录修订必须可审计并支持一致读取
每次注册、状态转换、能力替换、服务替换和撤销 SHALL 在同一事务生成单调 server revision；
读取指定 revision 的响应 MUST 表示一致的目录状态或明确要求 full sync。

#### Scenario: 能力和服务并发更新
- **WHEN** 同一节点的两个快照依次提交
- **THEN** 每次提交 SHALL 获得独立递增 revision，客户端不观察到半写事务

### Requirement: 基础目录不依赖模型 Provider
注册、心跳、快照收敛、新鲜度、查询和本地展示 MUST 在所有节点未配置模型时继续工作。

#### Scenario: 模型 Provider 全部不可用
- **WHEN** A、B 和 Coordinator 均没有可用模型
- **THEN** 用户仍 SHALL 能查看带新鲜度的节点、能力和服务目录

