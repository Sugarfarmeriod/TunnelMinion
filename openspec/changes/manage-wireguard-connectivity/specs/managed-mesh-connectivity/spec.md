## ADDED Requirements

### Requirement: Coordinator 必须事务分配不冲突的 host address
Coordinator SHALL 在 network 的管理员配置地址池内为节点分配稳定 host address，并 MUST 使用
事务唯一约束拒绝重复地址、保留地址、跨 network 租约和未授权地址池变更。

#### Scenario: 两个节点并发申请地址
- **WHEN** A 与 B 同时加入同一受管 network
- **THEN** Coordinator SHALL 原子分配两个不同 host address 并生成单调配置修订

#### Scenario: 本机预检发现地址冲突或未批准 route 重叠
- **WHEN** Agent 发现分配地址与本机现有接口冲突，或目标 route 命中未被双重批准的既有路由
- **THEN** Agent SHALL 拒绝应用并报告冲突，不得自行选择另一地址绕过 Coordinator

#### Scenario: 已批准精确 host route 与既有宽路由共存
- **WHEN** 分配地址不与接口冲突，且签名配置和本机 L3 授权同时绑定精确 IPv4 `/32`、原命中宽路由和观察指纹
- **THEN** Agent MAY 进入 Provider 计划，但不得扩大到子网、默认路由或修改原宽路由

### Requirement: desired config 必须签名并绑定目标与父修订
每份受管网络 desired config MUST 绑定 network、目标 node、配置 revision、父 revision、公钥、
host routes、允许覆盖的既有宽路由摘要、可选 UDP listen port、候选 endpoint、relay policy、
有效期和策略摘要，并 SHALL 使用固定指纹的 Coordinator Ed25519 key 对域分离 payload 签名。

#### Scenario: Agent 收到下一配置修订
- **WHEN** 签名、目标 node、父 revision、协议和预算均有效
- **THEN** Agent SHALL 保存 pending config 并进入本机策略与 Provider 预检

#### Scenario: 配置被重定向给另一节点
- **WHEN** B 收到目标绑定为 A 的签名 desired config
- **THEN** B SHALL 拒绝配置且不调用 Provider

### Requirement: 候选 endpoint 必须有来源、有效期和本机策略
Coordinator SHALL 只接受认证节点上报或本机管理员配置的有界 UDP endpoint 候选，并保存来源、
接收时间和有效期；Agent MUST 再按本机允许地址/端口策略过滤，模型提供的地址不得成为候选。

#### Scenario: 节点上报显式 endpoint
- **WHEN** 节点认证上报一个格式有效且数量在预算内的 UDP endpoint
- **THEN** Coordinator SHALL 将其作为有来源候选发布，而不是声明其可达

#### Scenario: 对话文本包含公网 endpoint
- **WHEN** 模型或用户消息提到未在控制面验证的任意地址
- **THEN** 系统 SHALL 不把该地址加入 desired config 或 Provider 计划

### Requirement: direct 状态必须由真实路径联合验证
Agent SHALL 对允许候选进行有界探测；只有新鲜 WireGuard handshake、期望 host route 与从请求
节点执行的目标探测均成功时，路径才能标记为 `direct`。

#### Scenario: 握手和目标探测均成功
- **WHEN** A/B 独立测试接口完成新鲜握手且 A 对 B 受管地址的验证成功
- **THEN** 两端 SHALL 报告 `direct`，并记录不含密钥/业务正文的证据时间与配置 revision

#### Scenario: 只有旧握手
- **WHEN** latest handshake 超过新鲜度阈值或目标探测失败
- **THEN** 系统 SHALL 不报告 direct，并保留具体失败维度

### Requirement: relay 必须是显式、可验证的专用角色
系统 MUST 只使用管理员启用、具有独立身份和策略的 relay；普通 Coordinator API 进程不得静默
转发数据。路径标记 `relayed` 前 MUST 沿实际 relay 验证，且页面 SHALL 显示信任、延迟和容量
边界。

#### Scenario: 直连失败且专用 relay 可用
- **WHEN** direct 在阈值内失败、双方 policy 允许同一 relay 且实际回退探测成功
- **THEN** 系统 SHALL 切换为 `relayed` 并保留 direct 失败和 relay 验证证据

#### Scenario: 只有 Coordinator 在线
- **WHEN** 没有已批准并验证的 relay
- **THEN** 系统 SHALL 报告 `degraded`，不得把 Coordinator 控制通道称为 relay

### Requirement: 路径切换必须具有阈值、稳定窗口和回退
路径控制器 MUST 采用连续失败阈值、成功稳定窗口、最小驻留时间和单并发状态机，避免 direct 与
relayed 抖动；切换失败 SHALL 恢复 last-known-good 路径。

#### Scenario: direct 出现一次短暂丢包
- **WHEN** 一次探测失败但未达到连续失败阈值
- **THEN** 控制器 SHALL 保持当前路径并记录降级样本，不立即切换或重写配置

#### Scenario: relay 期间 direct 稳定恢复
- **WHEN** direct 在完整稳定窗口内持续通过验证
- **THEN** 控制器 SHALL 应用受批准切换、验证 direct 后才释放旧 relay 路径

### Requirement: 多节点配置必须按 revision saga 收敛
Coordinator SHALL 跟踪每个必需节点的 pending/applied/verified/rolled-back acknowledgement；
共同 revision 只有在全部节点验证后才能成为 active，任一节点失败时其它已应用节点 MUST 回滚
到父 revision。

#### Scenario: A 成功而 B 应用失败
- **WHEN** A 已验证新 revision 但 B 返回 Provider 失败
- **THEN** Coordinator SHALL 将 revision 标记失败并要求 A 按其回执恢复父 revision

#### Scenario: 回滚响应丢失
- **WHEN** 节点已回滚但 Coordinator 未收到 acknowledgement
- **THEN** 相同幂等回滚重试 SHALL 返回原验证结果，不创建另一配置修订

### Requirement: 控制面离线必须保留 last-known-good
Agent MUST 缓存最近一次签名且本地验证成功的配置。Coordinator 离线时 SHALL 保留仍工作的
受管隧道并标记 control-plane stale，不得应用新配置或因单次失联拆除网络。

#### Scenario: 已连通后 Coordinator 停止
- **WHEN** Agent 无法刷新控制面但当前 direct/relayed 路径仍通过验证
- **THEN** 数据面 SHALL 继续运行，本地紧急停止与恢复仍可用

#### Scenario: 离线期间收到未验证本地文件
- **WHEN** 本地目录出现没有有效 Coordinator 签名的新 desired config
- **THEN** Agent SHALL 忽略该文件并保留 last-known-good

### Requirement: 连接状态必须可观测且脱敏
资源页和评估 SHALL 显示 network/node、Provider 模式、配置 revision、授权状态、路径类型、
握手/探测新鲜度、relay 身份摘要、last-known-good 和稳定错误码；MUST NOT 显示私钥、完整配置、
认证头、未过滤公网拓扑或用户完整路由表。

#### Scenario: managed 路径处于 degraded
- **WHEN** direct 和 relay 均未通过验证
- **THEN** 页面 SHALL 分别显示候选、握手、route、目标探测或 relay 哪个阶段失败
