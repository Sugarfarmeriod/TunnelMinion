## ADDED Requirements

### Requirement: 本机用户通过统一 React 界面访问产品能力

Node Runtime SHALL 通过环回地址提供统一 React 产品界面，并 SHALL 在同一导航结构中提供总览、
聊天、操作、记忆和设置/诊断入口。刷新或直接打开非敏感子路由时 MUST 恢复对应页面。

#### Scenario: 用户从总览切换到操作页
- **WHEN** 本机用户在统一界面选择“操作”
- **THEN** 页面在不离开本地产品外壳的情况下展示操作列表与状态，并保持可返回总览的导航

#### Scenario: 远端节点尝试打开产品界面
- **WHEN** 其他节点通过物理或私网地址访问该节点的产品界面端口
- **THEN** 连接不可用，因为界面及其管理 API 只绑定环回地址

### Requirement: 总览必须以可理解的节点和服务状态代替原始 JSON

总览 SHALL 展示本机、已知节点、服务、证据时间、新鲜度和可用动作，并 MUST 区分实时、陈旧、
离线、未配置、不可兼容和未知状态。原始 JSON MAY 作为诊断细节提供，但 MUST NOT 是主要状态表达。

#### Scenario: Coordinator 目录已经陈旧
- **WHEN** 本机仍有缓存节点但目录新鲜度已过期
- **THEN** 总览标记目录陈旧、显示最后成功时间且不得把缓存节点显示为实时在线

#### Scenario: 节点只有本机能力
- **WHEN** Coordinator 未配置且没有可用 peer
- **THEN** 总览显示 local-only 并继续展示本机资源，而不是把整个产品显示为故障

### Requirement: 界面必须保持本地、peer、模型和控制面状态分离

界面 MUST 分别表达本地 runtime readiness、peer 可达/认证结果、模型 Provider 状态和 Coordinator
同步状态，且 MUST NOT 用一个统一“在线”标志互相替代。

#### Scenario: Gateway 本机运行但 peer 不可达
- **WHEN** 本机进程与 listener ownership 验证成功但独立 peer 探测超时
- **THEN** 页面分别显示本机运行与 peer 不可达，不把 Gateway 误报为本机启动失败或跨机可用

#### Scenario: 模型不可用但确定性资源可用
- **WHEN** 模型 Provider 健康检查失败而本机资源 API 正常
- **THEN** 页面禁用新的 AI 对话并继续允许刷新确定性资源和控制已有操作

### Requirement: 聊天界面必须可靠展示公开运行事件

聊天界面 SHALL 支持 thread 创建、选择、删除、run 发起与取消，并 SHALL 按事件序号展示目标节点、
工具、公开状态、耗时和证据引用。界面 MUST NOT 展示隐藏推理、密钥或未经限制的原始工具数据。

#### Scenario: SSE 连接短暂中断
- **WHEN** 活跃 run 的事件流断开后恢复
- **THEN** 客户端从最后已应用序号继续读取、忽略重复事件且不重新发起 run 或工具调用

#### Scenario: 用户取消正在执行的 run
- **WHEN** 用户确认取消当前 run
- **THEN** 页面请求服务端取消、展示服务端返回的最终状态并关闭该 run 的事件连接

### Requirement: 有副作用操作必须经过明确且可恢复的交互

操作界面 SHALL 显示计划目标、证据、风险、访问者、端口、有效期、验证和回滚信息，并 MUST 对
批准、拒绝、取消和撤销使用对象明确的确认。浏览器状态 MUST NOT 代替服务端授权或幂等控制。

#### Scenario: 用户批准待处理操作
- **WHEN** 用户查看完整计划并确认批准
- **THEN** 页面只提交一次批准请求、禁用重复提交，并以重新读取的服务端 operation 状态显示结果

#### Scenario: 批准请求结果未知
- **WHEN** 提交批准后网络超时且客户端无法确认响应
- **THEN** 页面将结果标记为未知并重新查询相同 operation，不自行重发或显示成功

#### Scenario: 清理失败需要人工处理
- **WHEN** operation 状态为 `cleanup_failed`
- **THEN** 页面突出显示受影响资源、脱敏错误和人工处理建议，并禁止把操作显示为已完成

### Requirement: 用户必须能安全管理长期记忆

记忆界面 SHALL 展示每条长期记忆的内容、来源、作用域和更新时间，并 SHALL 支持确认、修正、删除
单条和清空指定作用域。页面 MUST 明确区分长期记忆与聊天记录。

#### Scenario: 用户修正错误记忆
- **WHEN** 用户编辑一条记忆并确认新的内容与作用域
- **THEN** 页面提交修订、重新读取服务端记录并展示新的更新时间和来源信息

#### Scenario: 用户清空一个作用域
- **WHEN** 用户选择清空指定用户、网络和节点作用域
- **THEN** 页面展示精确作用域并要求确认，且不得影响其他作用域或聊天线程

### Requirement: 远端和模型内容必须按不可信文本渲染

界面 MUST 将模型回答、节点名、服务名、工具结果、计划说明和错误正文作为不可信数据处理，
不得执行其中的 HTML、脚本、事件处理器或导航指令。生产响应 SHALL 应用严格同源 CSP。

#### Scenario: 服务名包含脚本标记
- **WHEN** 远端服务名包含 HTML 或脚本样式文本
- **THEN** 页面按字面文本显示或截断该内容，脚本不执行且安全策略不改变

#### Scenario: 页面需要访问外部脚本源
- **WHEN** 生产前端资源引用非同源脚本或样式
- **THEN** 构建或安全门禁失败，运行时 CSP 也拒绝加载该资源

### Requirement: 浏览器不得持久化秘密或把缓存当实时事实

前端 MUST NOT 在 localStorage、sessionStorage、IndexedDB、URL、普通日志或错误遥测中持久化模型
密钥、Gateway token、认证头、临时访问凭据或完整诊断 payload。服务器查询缓存 MUST 保留新鲜度
并在失效后显示陈旧或重新获取，不得冒充实时状态。

#### Scenario: 用户刷新包含临时访问入口的操作页
- **WHEN** 页面刷新或浏览器会话恢复
- **THEN** 客户端从服务端读取脱敏 operation 状态，浏览器存储与 URL 中不存在完整临时凭据

#### Scenario: 刷新资源失败但有旧缓存
- **WHEN** 最新资源请求失败且客户端仍持有上一次结果
- **THEN** 页面把结果标记为陈旧并显示上次成功时间，不把缓存显示为当前实时事实

### Requirement: 界面必须支持确定性降级和失败恢复

界面 SHALL 在模型、Coordinator、peer 或可选诊断来源不可用时保留不依赖它们的功能，并 SHALL
为失败状态提供稳定错误类型和可执行的下一步。没有 Murus 或防火墙日志权限 MUST NOT 阻止产品
界面、资源读取、runtime lifecycle 或 peer 验收结果展示。

#### Scenario: Coordinator 离线时撤销已有操作
- **WHEN** Coordinator 不可用但本机存在可撤销 operation
- **THEN** 页面继续提供本机撤销入口并显示控制面离线，不要求先恢复模型或 Coordinator

#### Scenario: 防火墙日志不可读
- **WHEN** 当前平台没有受支持的防火墙日志接口或用户未授予读取权限
- **THEN** 页面把日志标为可选诊断不可用，并继续使用真实跨机请求表达 peer 是否可达

### Requirement: 产品界面必须满足基础可访问性和窄窗口使用

界面 SHALL 使用语义化结构、关联表单标签、可见键盘焦点、非颜色状态提示和适当的 live region，
并 SHALL 在规定的桌面与窄窗口视口中保持主要流程可操作。

#### Scenario: 仅使用键盘批准操作
- **WHEN** 用户不使用鼠标浏览待批准计划
- **THEN** 用户可以按合理焦点顺序阅读计划、打开确认并选择批准或取消，焦点不会丢失

#### Scenario: 窄窗口查看节点故障
- **WHEN** 用户在验收定义的最窄视口打开节点详情
- **THEN** 状态、证据时间和主要恢复动作保持可见且页面不产生阻断操作的横向溢出

### Requirement: React 生产资源必须可重复构建并随离线运行包交付

项目 SHALL 使用锁文件从固定输入构建前端，执行格式、类型、单元、组件、安全和生产构建门禁，
并 SHALL 把带内容哈希的静态资源纳入 Windows 与 macOS 版本化 package。目标机器运行界面 MUST
NOT 依赖 Node.js、源码 checkout、开发缓存或网络下载。

#### Scenario: 在干净机器打开 package 界面
- **WHEN** 用户在没有 Node.js、源码和网络的受支持 Windows 或 macOS 环境启动版本化 package
- **THEN** React 界面及其本地 API 正常加载，静态资源摘要与 package 清单一致

#### Scenario: React 默认入口验收失败
- **WHEN** 切换后的界面出现静态资源、CSP、SSE 或操作控制回归
- **THEN** 发布流程恢复已验证的旧页面入口且不删除线程、记忆、操作记录、配置或秘密
