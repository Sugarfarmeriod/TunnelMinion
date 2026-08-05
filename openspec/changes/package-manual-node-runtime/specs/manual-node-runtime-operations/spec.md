## ADDED Requirements

### Requirement: 节点运行包必须可重复且不依赖开发环境

系统 SHALL 为 Windows 和 macOS 生成带版本、清单、固定 Python 运行时和锁定依赖的节点运行包。
运行包 MUST 在没有源码 checkout、开发 `.venv`、`PYTHONPATH` 或全局 site-packages 的当前用户环境
中启动本地应用和 Gateway，并 MUST 在关键文件或依赖损坏时拒绝启动且返回稳定错误。

#### Scenario: 在干净用户环境启动运行包

- **WHEN** 用户在没有项目源码和开发虚拟环境的受支持 Windows 或 macOS 账户安装已验证运行包
- **THEN** 本地应用和已配置 Gateway 使用包内运行时启动，状态报告相同的应用版本与清单摘要

#### Scenario: 包内依赖损坏

- **WHEN** 启动预检发现关键文件缺失、清单不匹配或必需模块无法导入
- **THEN** 系统不创建应用或 Gateway 进程，并返回不包含本机秘密或完整路径正文的稳定依赖错误

### Requirement: 程序、数据和秘密必须分离

运行包 MUST 将可替换程序文件与持久数据目录分离。模型、Gateway、managed node 普通配置、节点
身份、SQLite、checkpoint、日志和进程状态 SHALL 位于显式解析的数据目录；模型 API key、Gateway
token 和 Coordinator refresh 凭据 MUST 继续使用已配置的 `SecretStore`，不得复制到程序目录、
runtime profile、进程记录或日志。

#### Scenario: 替换运行包版本

- **WHEN** 用户停止旧版本、安装并启动一个通过清单验证的新版本
- **THEN** 新版本使用同一数据目录与既有 SecretStore 恢复节点身份、配置和状态，且程序替换不修改秘密正文

#### Scenario: 使用受限文件秘密后端

- **WHEN** 现有 Gateway 或 managed node 显式配置为 `restricted-file`
- **THEN** 运行包继续使用数据目录内现有权限受限秘密文件，不把它迁移到程序目录或默认 keyring

### Requirement: 用户必须能手动控制常驻组件

系统 MUST 提供手动 `start`、`status` 和 `stop` 操作，分别管理环回本地应用与独立私网 Gateway。
成功启动的组件 SHALL 在发起命令的终端退出后继续运行，直到用户手动停止、用户会话/系统结束或
组件故障。系统 MUST NOT 创建开机或登录自启动机制。

#### Scenario: 手动启动已配置节点

- **WHEN** 用户对有效 runtime profile 和数据目录执行 `start`
- **THEN** 系统启动已启用组件、完成逐组件健康验证后退出控制命令，并把整体状态报告为 `running`

#### Scenario: 机器重启后查看状态

- **WHEN** 机器重启且用户尚未再次执行 `start`
- **THEN** `status` 报告组件为 `stopped`，系统没有通过服务、计划任务或登录项自动创建进程

#### Scenario: 重复启动健康实例

- **WHEN** 用户对已经健康运行的同一 profile 再次执行 `start`
- **THEN** 操作幂等返回现有实例状态，不创建第二个本地应用或 Gateway 监听器

### Requirement: 组件失败必须分域报告

本地应用与 Gateway SHALL 保持独立进程、监听器、状态和日志。某一请求组件启动失败时，系统
MUST 报告该组件的稳定失败原因和整体 `degraded` 状态，不得把部分成功表示为全部成功，也不得
自动停止已经健康的另一组件。

#### Scenario: Gateway 端口被占用

- **WHEN** 本地应用成功启动但 Gateway 配置端口已由其他进程占用
- **THEN** 本地应用保持运行，Gateway 状态为 `failed`、整体状态为 `degraded`，命令以非零结果结束

#### Scenario: Gateway 尚未配置

- **WHEN** profile 未启用 Gateway 或数据目录没有有效 Gateway 配置
- **THEN** 系统不创建 Gateway 进程，并将其报告为 `disabled` 或 `unconfigured` 而非健康运行

### Requirement: 进程操作必须验证所有权并安全停止

系统 MUST 使用受限、原子写入的版本化进程记录，并把 PID、启动时间、可执行文件、组件参数和
实例身份与实时进程联合验证。`stop` MUST 只向可证明属于当前 profile 的进程发送正常终止信号，
等待应用保存 checkpoint 并验证退出；PID 复用、记录陈旧或身份不明时 MUST fail closed。

#### Scenario: PID 已被其他进程复用

- **WHEN** 进程记录中的 PID 存在但实时可执行文件、启动时间或组件身份不匹配
- **THEN** 系统报告 `ownership-conflict`，不终止实时进程，也不把陈旧记录当作健康实例

#### Scenario: 正常停止节点

- **WHEN** 用户执行 `stop` 且两个组件身份均匹配
- **THEN** 系统请求安全停止、等待进程退出并更新状态，不遗留仍被报告为运行的自有 PID 记录

#### Scenario: 组件未在预算内停止

- **WHEN** 已验证组件收到正常终止信号后未在停止预算内退出
- **THEN** 系统返回稳定超时并保留诊断状态，不默认强杀进程或删除无法证明已释放的状态

### Requirement: 状态与日志必须可诊断且不泄露秘密

`status` SHALL 返回运行包版本、数据目录摘要、逐组件生命周期、监听摘要、健康结果、模型依赖
状态、日志位置和最后稳定错误。日志和进程状态 MUST 使用当前账户受限权限和有界轮转，并 MUST
NOT 包含 token、refresh、assertion、私钥、认证 header、标准输入或完整远端响应正文。

#### Scenario: Gateway 正常鉴权

- **WHEN** Gateway 本地进程与监听器所有权已验证，且批准的 peer 发出的无 token 有界请求收到预期
  鉴权拒绝
- **THEN** 端到端状态将 Gateway 报告为可达，不需要读取、显示或发送已保存 token；PID 或监听器
  单独存在不得等同于该结论

#### Scenario: macOS 本机无法 hairpin 访问自身 WireGuard 地址

- **WHEN** macOS Gateway 进程与私网监听器所有权匹配，但 B 本机对自身 WireGuard 地址的 HTTP
  请求超时，且尚未取得 peer 证据
- **THEN** `start` 和 `status` 在真实总 deadline 内把本地生命周期报告为运行、把端到端状态报告为
  `peer_unverified`，不得误报 `startup_unstable`，也不得把监听器单独标记为生产 accepted

#### Scenario: peer 暂时离线

- **WHEN** 本地进程和监听器所有权仍匹配，但批准的 peer 当前无法完成探测
- **THEN** 系统保留可安全 `status`/`stop` 的自有进程状态并报告 `peer_unverified` 或
  `peer_unreachable`，不得因一次外部不可达强杀进程或伪造端到端成功

#### Scenario: 查看失败状态

- **WHEN** 组件因配置或依赖错误退出
- **THEN** `status` 返回稳定错误码、发生时间和受限日志路径，不回显配置正文或秘密

### Requirement: 外部模型不得被运行入口接管

运行入口 SHALL 只对已配置模型 endpoint 执行有界只读健康检查，并 MUST NOT 启动、停止、安装、
更新或定位模型进程。模型不可达 MUST 只把模型状态标记为 `unavailable`，不得阻止本地资源页、
确定性工具、Coordinator 同步或 Gateway 启动。

#### Scenario: 模型未启动

- **WHEN** 用户启动节点时已配置模型 endpoint 不可达
- **THEN** 节点确定性组件按配置启动，整体状态明确区分模型不可用与本地应用/Gateway 生命周期

#### Scenario: 模型后来恢复

- **WHEN** 外部模型在节点启动后恢复可达且用户再次请求 `status`
- **THEN** 健康结果更新为可用，运行入口没有创建或重启任何模型进程

### Requirement: 替换或移除运行包必须默认保留生产数据

系统 SHALL 支持验证新运行包后手动切换版本，并在健康验证失败时切回上一运行包。程序版本切换
MUST 复用同一数据目录且不得回滚数据库或秘密。移除运行包 MUST 默认保留数据目录和 SecretStore；
删除生产数据仍 MUST 使用现有显式确认的卸载流程。

#### Scenario: 新版本健康验证失败

- **WHEN** 新运行包启动后任一必需组件未通过稳定窗口健康验证
- **THEN** 系统允许停止新版本并切回上一已验证运行包，节点数据、身份和秘密保持原样

#### Scenario: 只移除程序

- **WHEN** 用户选择移除当前运行包但未执行带显式确认的数据卸载
- **THEN** 系统删除可证明属于运行包的程序和非秘密安装元数据，同时保留数据目录与 SecretStore
