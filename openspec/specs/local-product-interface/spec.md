# local-product-interface Specification

## Purpose

规定仅本机 React 产品界面的统一导航、状态表达、聊天、审批、记忆、诊断、安全边界、可访问性与离线交付契约。

## Requirements

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
- **WHEN** 用户在原作用域内编辑一条记忆并确认新的内容
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
- **THEN** 页面把日志标为可选诊断不可用；没有当前真实跨机证据时明确显示 peer 未验证/local-only，不用缓存、fixture 或平台能力降级冒充 peer 可达

#### Scenario: 双平台安全诊断预览
- **WHEN** Windows 或 macOS 正常产品入口没有真实 peer 直连授权或当前路径证据
- **THEN** 总览、聊天、审批、记忆和设置继续可用并如实展示 local-only、未配置、陈旧或降级；验收不触发 managed-path 网络写入，也不把该结果声明为真实 A/B

### Requirement: 产品界面必须满足基础可访问性和窄窗口使用

界面 SHALL 使用语义化结构、关联表单标签、可见键盘焦点、非颜色状态提示和适当的 live region，
并 SHALL 在规定的桌面与窄窗口视口中保持主要流程可操作。

#### Scenario: 仅使用键盘批准操作
- **WHEN** 用户不使用鼠标浏览待批准计划
- **THEN** 用户可以按合理焦点顺序阅读计划、打开确认并选择批准或取消，焦点不会丢失

#### Scenario: 320 CSS px 窄窗口完成关键流程
- **WHEN** 用户在 320 CSS px 或桌面 200% zoom 下打开节点详情、operation 详情或确认对话框
- **THEN** 状态、证据时间、焦点和主要动作保持可达，且页面不产生阻断操作的横向溢出

### Requirement: React 生产资源必须可重复构建并随离线运行包交付

项目 SHALL 使用 Node.js 22.14.0、npm 10.9.2、提交的 `package-lock.json` 与 `npm ci` 从固定输入构建前端，执行格式、类型、单元、组件、安全和生产构建门禁，
并 SHALL 把带内容哈希的静态资源纳入 Windows 与 macOS 版本化 package。目标机器运行界面 MUST
NOT 依赖 Node.js、源码 checkout、开发缓存或网络下载。

#### Scenario: 在干净机器打开 package 界面
- **WHEN** 用户在没有 Node.js、源码和网络的受支持 Windows 或 macOS 环境启动版本化 package
- **THEN** React 界面及其本地 API 正常加载，静态资源摘要与 package 清单一致

#### Scenario: React 默认入口验收失败
- **WHEN** 切换后的界面出现静态资源、CSP、SSE 或操作控制回归
- **THEN** 发布流程恢复已验证的旧页面入口且不删除线程、记忆、操作记录、配置或秘密

### Requirement: 本机 Web 请求必须抵御 DNS rebinding 与跨站写入

Node Runtime MUST 在路由和领域服务之前校验本机 Web 请求。`Host` 仅允许当前监听端口上的
`localhost`、`127.0.0.1` 与 `[::1]`。浏览器 unsafe 请求 MUST 具有精确同源 `Origin`、不得具有
`Sec-Fetch-Site: cross-site`，并 MUST 携带 `X-TunnelMinion-Request: same-origin`。服务端 MUST NOT
开放宽泛跨站 CORS。没有 `Origin` 与 Fetch Metadata 的本机 CLI SHALL 保持兼容，并继续接受既有
认证、授权、幂等和数据校验。

#### Scenario: DNS rebinding Host 被拒绝
- **WHEN** 请求使用不在环回 allowlist 的 Host
- **THEN** 服务端在路由执行前返回 `403 invalid_host`

#### Scenario: 恶意网页向环回地址发起写请求
- **WHEN** 浏览器 unsafe 请求的 Origin 不同源、Fetch Metadata 为 cross-site，或缺少/伪造规定自定义头
- **THEN** 服务端按 `invalid_host`、`cross_site_request`、`invalid_origin`、`request_header_required`、`invalid_request_header` 的固定优先级返回最高优先级 403，且 operation、memory、conversation 领域服务未被调用

#### Scenario: 合法同源浏览器写请求
- **WHEN** React 或 legacy 页面从可信本机 origin 发起非 cross-site 写请求并携带规定自定义头
- **THEN** 请求进入既有服务端认证、授权、幂等、确认与验证流程

#### Scenario: 本机 CLI 没有浏览器元数据
- **WHEN** 现有环回 CLI/测试客户端以真实方法、路径和规范化 Host（localhost、IPv4 或带方括号 IPv6 加当前监听端口）请求，且同时没有 Origin 与 Fetch Metadata
- **THEN** 请求保持兼容，并继续由既有服务端安全边界决定结果；只有同时缺少两类浏览器元数据才进入该兼容分支

### Requirement: 总览与操作详情必须由强类型服务端契约提供

Node Runtime SHALL 提供 `GET /api/resources/overview`，统一返回本机 runtime、平台、版本、package、
readiness、模型 configured/status/error、Coordinator state/freshness/revision/last success、network
path 的 handshake/route/probe/evidence time、已知节点和服务，以及各 section 的来源、新鲜度和稳定
错误码。前端 MUST NOT 从宽泛 JSON 自行推断这些领域状态。

`GET /api/operations/{operation_id}` SHALL 返回脱敏的 owned resources、verification、cleanup record、
manual action、允许动作和当前 state。操作列表只可作为摘要；批准、拒绝、取消或撤销前 MUST
重新读取详情。该复读不形成客户端原子锁；并发正确性仍由服务端状态迁移、授权和幂等检查保证，
冲突后前端 MUST 读取最新状态且 MUST NOT 自动重放写请求。

#### Scenario: Coordinator 与 path 已配置并产生证据
- **WHEN** Windows 或 macOS 标准应用入口已经装配 Coordinator cache/status 与 network path evidence
- **THEN** overview 返回真实状态、来源与时间，不得因应用工厂漏传依赖而误报 `unconfigured`

#### Scenario: 从陈旧操作列表进入详情
- **WHEN** 用户从旧列表对象打开 operation 并准备提交动作
- **THEN** 页面按 operation ID 读取最新详情，并以最新允许动作和 state 决定是否可提交；服务端拒绝竞态冲突

### Requirement: SPA 路由、缓存与 CSP 必须保持 API 边界

React 页面 SHALL 位于 `/app/*`，内容哈希资源 SHALL 位于 `/app-assets/*`。SPA fallback MUST NOT
吞掉 `/api/*` 或 SSE 的 404。`index.html` MUST 使用 `no-store`，内容哈希资源 SHALL 使用 immutable
长缓存；生产 CSP MUST 禁止内联与外部脚本。

#### Scenario: 刷新深层页面路由
- **WHEN** 用户直接刷新 `/app/operations/{operation_id}`
- **THEN** FastAPI 返回 SPA 入口且 CSP、缓存头正确

#### Scenario: 请求不存在的 API 或 SSE 资源
- **WHEN** 客户端请求不存在的 `/api/*` 或事件流路径
- **THEN** 服务端保持 API/SSE 404，而不是返回 HTML 200

### Requirement: 运行包清单必须覆盖同一份前端构建物并保留 legacy 回退

构建流程 MUST 每次 clean-first 生成唯一 `build/frontend-dist`，wheel 与 Windows/macOS PyInstaller
package MUST 收集同一份 dist。构建器 SHALL 发出 `runtime-package-manifest/v2`，记录 Python/npm
lock digest、frontend dist digest、文件数、每项相对路径/内容摘要/大小/类型与 npm/Python 许可证
来源；现有运行包校验/安装流程 SHALL 支持 v2 并继续兼容已有 v1，但 MUST NOT 静默改写 v1 或接受
未知 schema、路径穿越、缺文件、损坏或陈旧 dist。本 change 不新建第二套安装器。

React 成为默认入口后，原 `/chat`、`/resources`、`/operations`、`/memories` 与对应 `/legacy/*`
别名 SHALL 在 React 首发版本以及至少紧随其后的一个版本继续存在，并使用相同写请求门禁；默认
`/` 只切换入口映射。自动契约 MUST 防止本 change 删除这些路由，实际删除 MUST 由后续独立 change
完成。

#### Scenario: 双平台 package 消费相同前端产物
- **WHEN** 构建 Windows amd64 与 macOS arm64 package
- **THEN** 两个 package 中的 frontend dist 摘要完全相同，目标机无 Node、源码、网络仍能运行

#### Scenario: manifest 版本或前端产物不可信
- **WHEN** 安装器遇到未知 manifest 版本、路径穿越、遗漏、摘要不符或陈旧 dist
- **THEN** 构建或安装 fail closed，且 v1 不被伪装成 v2

#### Scenario: React 默认入口发布后的回退周期
- **WHEN** React 首次成为默认入口
- **THEN** 原四页路径及其 `/legacy/*` 别名在首发和紧随其后的版本继续可用，回退只改默认 `/` 映射且不迁移或删除用户数据

### Requirement: 浏览器、可访问性与前端体积必须具有固定门禁

CI SHALL 在 Windows Chromium 与 macOS WebKit 覆盖关键流程；axe serious/critical 违规 MUST 为 0。
主要流程 SHALL 在 1280×720、320 CSS px 与 200% zoom 下可操作。初始 JS+CSS gzip 总量 MUST NOT
超过 300 KiB；后续增长超过前一已接受基线的 10% MUST 有审查说明。

#### Scenario: 前端质量或体积超出门禁
- **WHEN** 任一浏览器关键流程、可访问性级别、视口重排或体积预算失败
- **THEN** PR 门禁失败，且不得以单平台或人工截图替代

### Requirement: 服务总览必须显示确定性的完整访问地址

本机产品界面 SHALL 为已有 `protocol`、`host` 和 `port` 的服务显示完整 `access_address`，并 MUST 将该地址作为不可信只读文本呈现。系统 MUST NOT 因展示地址自动发起网络请求，也 MUST NOT 把地址存在等同于服务探测成功。

#### Scenario: 服务摘要包含完整地址来源
- **WHEN** Overview 收到包含 protocol、host 和 port 的服务摘要
- **THEN** API 与页面显示由这三个字段确定性组成的完整地址，并继续显示独立的状态与新鲜度

#### Scenario: 地址不可获得
- **WHEN** 服务摘要无法提供完整地址
- **THEN** 页面明确显示地址未知且不猜测主机或发起探测

### Requirement: 聊天运行必须链接共享证据的操作记录

Chat SHALL 使用当前 Run 和 Operation 已有的 `tool_run_ids` 建立只读关联，并 SHALL 为每个存在交集的 Operation 提供现有详情页链接。该关联 MUST NOT 创建、批准、执行或重放 Operation。

#### Scenario: 一个操作共享当前运行证据
- **WHEN** Operation 的 `tool_run_ids` 与当前 Run 的 `tool_run_ids` 至少有一个相同值
- **THEN** Chat 显示该 Operation 的只读详情链接

#### Scenario: 没有相关操作或列表读取失败
- **WHEN** 没有共享证据的 Operation，或只读操作列表暂时不可用
- **THEN** Chat 保持原运行与证据内容可用，且不猜测关联或触发写请求

### Requirement: Overview 必须作为 incident 调查主入口

Overview SHALL 展示活动与近期重要 incident 的类型、对象、严重度、首次/最后观测时间、调查状态和当前结论摘要，并 MUST 明确区分待调查、调查中、已确认、信息不足、中断和模型不可用。普通用户无需先创建聊天即可发现异常与调查结果。

#### Scenario: 后台发现服务远端不可达

- **WHEN** 确定性比较器创建 incident 且调查正在运行
- **THEN** Overview 显示对应卡片、实时公开状态和证据时间，不要求用户先输入问题

#### Scenario: 模型不可用但 incident 已产生

- **WHEN** 快照差异已确认异常而模型 Provider 不可用
- **THEN** Overview 继续显示异常事实和 `investigation_unavailable`，且节点与服务总览仍可刷新

### Requirement: Incident 详情必须展示公开调查轨迹和证据边界

Incident 详情 SHALL 展示候选根因状态、已调用只读工具、公开结果摘要、证据引用、结论、未知项和停止原因。界面 MUST NOT 展示隐藏思维链、秘密、认证材料或无界原始工具输出。

#### Scenario: 调查因信息不足停止

- **WHEN** 必要远端工具不可用且报告状态为 `insufficient_evidence`
- **THEN** 详情列出已确认事实、仍未知问题、失败工具和停止原因，不把候选解释显示为已确认根因

### Requirement: 用户可以围绕当前 incident 进行小型上下文追问

Incident 详情 SHALL 提供绑定该 incident 的对话入口和基于未知项、证据缺口与允许下一步生成的有界建议问题。追问 MUST 复用现有 conversation 与 Context Runtime，仅注入当前 incident 的脱敏公开上下文；追问不得修改原调查证据或扩大工具权限。

#### Scenario: 用户追问为什么判定为仅本机可用

- **WHEN** 用户从 incident 详情选择建议问题
- **THEN** 系统在绑定 thread 中回答并引用该 incident 的监听与可达性证据，不要求用户重新描述上下文

#### Scenario: 建议问题增强不可用

- **WHEN** 模型无法生成建议问题
- **THEN** 页面根据未知项和固定模板显示可执行的建议问题，incident 详情保持可用

### Requirement: Windows 总览必须独立展示本机服务观察

Windows Overview SHALL 在 Coordinator 未配置时继续展示最近一次完整本机只读服务快照，并 MUST 保留服务来源、状态、新鲜度和证据时间。该展示 MUST NOT 要求模型配置或远端连接。

#### Scenario: 默认本机产品发现监听服务

- **WHEN** Windows 后台观察完成一次本机服务采集且 Coordinator 未配置
- **THEN** Overview 的服务列表显示该服务及其本机观察来源，不把整个列表显示为空或控制面故障
