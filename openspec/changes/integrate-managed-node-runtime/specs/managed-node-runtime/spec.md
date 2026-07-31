## ADDED Requirements

### Requirement: managed node 必须显式配置且不保存秘密

系统 SHALL 使用版本化 managed node 配置显式启用 Coordinator 运行时。普通配置和安全导出
MUST NOT 包含 enrollment token、refresh 凭据、access assertion、签名私钥或 WireGuard 私钥。
未配置 managed node 时，常规 Windows/macOS 本地应用 MUST 保持现有本地页面和 static peer 行为。

#### Scenario: 未配置 managed node 启动本地应用

- **WHEN** 数据目录没有启用的 managed node 配置
- **THEN** 本地页面、只读工具、聊天、记忆和现有操作入口按原行为启动，且不连接 Coordinator

#### Scenario: 配置文件包含秘密字段

- **WHEN** managed node 配置包含 schema 未声明的 token、refresh 或私钥字段
- **THEN** 系统拒绝加载配置，不启动后台同步，并返回不回显字段正文的稳定错误

### Requirement: enrollment 必须是显式的一次性本地流程

系统 MUST 提供本地 CLI enrollment 命令，通过标准输入接收短期 token，确认固定 Coordinator
验证指纹，幂等注册稳定 network/node 身份，并将 refresh 凭据写入现有秘密存储。普通节点启动
MUST NOT 自动 enrollment 或从命令行参数、普通配置读取完整 token。

#### Scenario: 使用有效 token 首次加入

- **WHEN** 本机管理员已保存无秘密配置并向 enrollment 命令标准输入提供有效短期 token
- **THEN** 命令确认固定指纹、注册既定 node、保存 refresh 凭据，并只输出脱敏身份摘要

#### Scenario: 普通服务重启但尚未 enrollment

- **WHEN** managed node 配置已启用但秘密存储没有 refresh 凭据
- **THEN** 应用显示 `enrollment-required`，不创建新身份、不消费 token，也不阻塞本地功能

### Requirement: 常规应用生命周期必须托管受管后台任务

启用 managed node 后，Windows/macOS 本地应用 SHALL 在受控 lifespan 中启动 Coordinator 目录
同步、服务观察/快照和 managed config 同步，并在停止时取消新轮次、等待安全点和保存 checkpoint。
同一运行时内每类同步 MUST 保持单并发。

#### Scenario: 应用正常启动和停止

- **WHEN** 已 enrollment 节点通过常规 `tunnelminion` 入口启动后收到停止信号
- **THEN** 后台任务完成或取消到安全点、保存非秘密 checkpoint 并停止，且不遗留无监督任务

#### Scenario: 重复启动同一同步轮次

- **WHEN** 前一轮目录或网络同步仍在运行时刷新定时器再次触发
- **THEN** 运行时拒绝并发轮次或合并触发，不并行修改 checkpoint 或 Provider 状态

### Requirement: 服务快照必须来自有界确定性观察

运行时 SHALL 周期性使用现有监听端口、进程和可选 Docker 只读适配器生成版本化完整服务快照。
监听和进程来源默认启用，Docker SHALL 以 best-effort 方式独立降级，主动 HTTP/协议探测 MUST
默认关闭。观察和快照 MUST 受超时、并发、记录数及字节预算约束。

#### Scenario: Docker 不可用但监听观察成功

- **WHEN** 本机监听和进程枚举成功而 Docker 未安装、未运行或无权访问
- **THEN** 运行时提交由可用来源生成的完整快照，并把 Docker 来源标记为降级而非整轮失败

#### Scenario: 完整快照生成中途失败

- **WHEN** 服务观察超时或结果超过预算，无法证明本轮完整性
- **THEN** 运行时不提交部分快照、不错误停止已有服务记录，并保留上次服务器修订与稳定错误

#### Scenario: 未显式启用主动探测

- **WHEN** 默认 managed node 配置运行服务观察
- **THEN** 系统不发起 HTTP 或协议主动请求，只使用被动系统与可选 Docker 元数据

### Requirement: managed config 必须进入既有治理而不是直接写系统

运行时 SHALL 拉取并验证属于本机的签名 desired config，将合法下一 revision 保存为 pending，并
MUST 只通过现有本机 L3 policy 和 Provider plan/apply/verify/rollback/recover 边界执行。模型、
对话、记忆、服务快照和普通启动 MUST NOT 创建授权或直接调用网络写入。

#### Scenario: 收到合法配置但没有本机授权

- **WHEN** 签名 desired config 通过目标、父 revision、指纹、协议和预算校验，但没有有效 L3 授权
- **THEN** 运行时保存 pending 并显示 `awaiting-authorization`，不调用 Provider apply

#### Scenario: Provider 验证失败

- **WHEN** 已授权配置的 apply 返回回执但独立 verify 失败
- **THEN** 既有治理执行回滚或进入人工干预，运行时不得上报 verified 或覆盖 last-known-good

### Requirement: 控制面故障不得破坏本地与已验证数据面

Coordinator、目录、服务快照或 managed config 同步失败 MUST NOT 阻塞本地页面、只读工具、
static peer、last-known-good、操作到期或恢复。模型不可用 MUST 只使 AI 对话降级。运行时 SHALL
使用有界退避并分别报告各故障域。

#### Scenario: Coordinator 离线

- **WHEN** 已运行节点连续无法连接 Coordinator
- **THEN** 目录和控制面显示 stale/backoff，本地资源与 static peer 继续可用，受管隧道不因单次失联拆除

#### Scenario: 没有模型 Provider

- **WHEN** 节点已 enrollment 但没有可用模型配置
- **THEN** 心跳、服务观察、目录和 managed config 同步继续运行，只有 AI 对话返回不可用

### Requirement: 重启必须恢复身份、修订与 last-known-good

运行时 MUST 从秘密存储恢复逐节点 refresh 凭据，并从持久化 checkpoint 恢复目录修订、服务序号、
pending/applied revision 和 last-known-good。恢复 MUST NOT 重放已完成 enrollment 或未经验证的
Provider 写步骤。

#### Scenario: 已同步节点正常重启

- **WHEN** 节点在完成目录和网络修订后停止并以同一数据目录重启
- **THEN** 节点恢复同一 network/node、序号和 applied revision，使用幂等同步收敛而不创建重复身份

#### Scenario: 上次进程在 Provider apply 中崩溃

- **WHEN** 重启发现未完成回执或 pending 配置
- **THEN** 运行时调用既有恢复器验证所有权和系统状态，不盲目重放 apply 或删除未知资源

### Requirement: 本地资源视图必须分域、脱敏且可解释

环回资源 API/页面 SHALL 分别显示 managed 配置/enrollment、目录同步、服务观察、managed config、
授权、路径与 last-known-good 状态，包括修订、最后成功、退避、计数和稳定错误。响应 MUST NOT
包含完整 token、refresh、assertion、签名、私钥、完整 endpoint、配置正文或用户路由。

#### Scenario: 本地可用但控制面离线

- **WHEN** Coordinator 不可达而本地工具与已有 static/direct 路径仍可用
- **THEN** 页面明确区分控制面离线和仍可用的数据面，不把整个节点笼统显示为 offline

#### Scenario: 读取资源 API

- **WHEN** 用户请求 managed node 状态并导出诊断
- **THEN** 响应支持按 revision 和稳定错误关联问题，但不包含任何可重放认证材料或完整配置

### Requirement: Windows 与 macOS 必须遵守同一运行契约

Windows 和 macOS 常规应用 MUST 使用相同 managed 配置、enrollment、后台生命周期、服务快照、
降级、恢复和资源状态语义。平台工具、秘密存储和 Provider 适配可以不同，但不得改变可观察结果。

#### Scenario: 两端使用相同类型配置启动

- **WHEN** 已 enrollment 的 Windows A 与 macOS B 分别通过常规入口启动
- **THEN** 两端均完成心跳、服务快照、目录拉取和 managed config 状态展示，并在无模型时继续运行
