## ADDED Requirements

### Requirement: Windows 总览必须独立展示本机服务观察

Windows Overview SHALL 在 Coordinator 未配置时继续展示最近一次完整本机只读服务快照，并 MUST 保留服务来源、状态、新鲜度和证据时间。该展示 MUST NOT 要求模型配置或远端连接。

#### Scenario: 默认本机产品发现监听服务

- **WHEN** Windows 后台观察完成一次本机服务采集且 Coordinator 未配置
- **THEN** Overview 的服务列表显示该服务及其本机观察来源，不把整个列表显示为空或控制面故障
