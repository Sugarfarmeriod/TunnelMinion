## ADDED Requirements

### Requirement: macOS 默认产品必须提供真实本机服务快照

macOS Node Runtime SHALL 在未配置 Coordinator 时复用既有确定性只读工具，按有界周期采集本机监听、进程与可选 Docker 服务并向 incident 快照提供完整结果。首份完整结果 MUST 先建立基线，MUST NOT 因应用启动时从空列表变为当前列表而创建 incident。

#### Scenario: 未配置 Coordinator 的 macOS 首次启动

- **WHEN** macOS 产品启动且本机已有监听服务，但 Coordinator 和模型均未配置
- **THEN** Runtime 保存包含当前本机服务的首份基线，不创建启动 incident，也不调用模型

#### Scenario: macOS 本机新增监听稳定出现

- **WHEN** 基线建立后新增本机监听，并在现有确认窗口内持续存在
- **THEN** Runtime 自动创建 `service_added` incident；模型未配置时保留差异证据并标记 `investigation_unavailable`
