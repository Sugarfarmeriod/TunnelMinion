## Context

`integrate-managed-node-runtime` 已把 enrollment、Coordinator/服务同步、受管配置和资源状态接入
Windows/macOS 常规应用，但进程外层仍是开发者工作流：本地应用与 Gateway 分别以前台命令启动，
运行依赖可能来自源码目录、`.venv` 或临时依赖目录。真实 B 节点已经出现“配置和秘密仍在，但旧
`.venv` 指向失效 Python 前缀，Gateway 无法启动”的故障，只能人工拼接 `PYTHONPATH` 绕过。

用户已明确：节点进程需要在人工启动后常驻，但不需要开机或登录自启动。模型服务是既有外部
进程；TunnelMinion 只能观测其健康状态，不能把模型生命周期纳入节点进程控制。程序、普通配置/
状态和秘密必须分离，升级程序不能破坏节点身份、Gateway token、refresh 凭据或运行数据库。

## Goals / Non-Goals

**Goals:**

- 为 Windows/macOS 产出不依赖源码 checkout 或开发虚拟环境的可重复节点运行目录。
- 提供一组手动命令，可靠启动、查看和停止本地应用与独立 Gateway，并在终端退出后继续运行。
- 固定程序、数据、秘密、进程状态和日志的边界，支持安全替换程序和保留数据的移除。
- 对依赖、配置、端口、进程身份和 HTTP 健康状态做确定性预检与执行后验证。
- 保持无模型降级、Gateway 私网监听、现有 graceful shutdown 和零秘密输出契约。

**Non-Goals:**

- 不创建 Windows Service、Scheduled Task、macOS LaunchAgent/Daemon 或任何开机/登录自启动项。
- 不启动、停止、安装或更新模型服务，也不把模型不可达视为节点确定性能力无法启动。
- 不合并本地应用与 Gateway，不改变监听地址、认证、Coordinator、Provider 或 L3 治理。
- 不交付 Linux 包、packet relay、自动升级器、公开签名/公证安装器或新 Web 前端。
- 不迁移、修改或接管 `HomeMac`、B 手写 WireGuard、Murus 和用户路由；本 change 不自动写入
  Application Firewall，只接受用户通过系统 UI 对精确已验证 executable 完成的当前机器人工授权。

## Decisions

### 1. 运行包是可替换程序，不是数据容器

每个平台使用锁定的 PyInstaller 6.21.0 生成版本化 one-folder 运行目录，包含固定版本的
TunnelMinion、Python 运行时和锁定依赖。构建环境先执行 `uv sync --frozen --group package`，后端
版本进入 `uv.lock`；联网预取完成后，候选必须能在禁网模式重新构建。清单固定为
`runtime-package-manifest/v1`，记录源提交、源输入摘要、`uv.lock` 摘要、构建器、入口、逐文件
SHA-256/大小和当前平台实际依赖的许可清单。这里的“可重复”指锁定输入与可复核输出，不承诺不同
机器构建出的 Mach-O/PE 字节完全相同。

正式构建器会把 PyInstaller `base_library.zip` 的成员顺序、时间和权限元数据规范化；同一平台两次
独立构建因此可得到相同逐文件清单。2026-08-01 验收中，Windows amd64 两次 manifest SHA-256
均为 `1e0d3b264228458bd2d02f93d552793571c027fcd6fde419b4a5c9dfa10a4120`，macOS arm64
两次均为 `740b266a550e06dab4ce5ebf0c47fee42a49cb72490c0f5cc07ee8fed13da471`；两平台的
源输入摘要共同为 `cee836fea82b64ad90ad89700165a4f8babc524aca13dd64f903ad38cc13c0c6`。

Windows 与 macOS arm64 spike 均证明 one-folder 在搬离源码、开发 `.venv` 和构建用基础 Python 后，
仍可启动真实本地应用与 Gateway，加载系统原生 keyring 和 5 个代表性原生扩展。Windows 包约
63.9 MB/206 个文件，macOS 包约 62.6 MB/136 个文件；独立 CPython+wheel 候选分别约
101.3 MB/6166 个文件和 95.0 MB/5132 个文件，且本地应用冷启动更慢。首版因此固定 one-folder，
独立 CPython+wheel 仅保留为已否决的 spike 候选。

程序目录不得保存 `model.json`、`gateway.json`、`managed-node.json`、SQLite、PID、日志或秘密。
默认数据目录继续使用平台标准用户数据目录；自定义目录通过平台标准用户配置位置中的非秘密
runtime profile 记录绝对路径。profile 只允许数据目录、启用组件和本地端口等非秘密字段。

否决方案一：继续把 `.venv` 和 `data/` 一起放在源码 checkout 中。它把可替换依赖、用户数据和
版本控制混为一体，无法安全升级或判断依赖是否完整。

否决方案二：复制完整 CPython 前缀后按 `uv.lock` 安装 wheel。它也通过了双平台隔离、keyring、
原生扩展和终端脱离验收，但文件数、体积和 Windows 冷启动成本都显著更高；复制 uv 管理的 Python
还需要只针对候选目录显式处理 `EXTERNALLY-MANAGED` 标记，首版没有足够收益承担这层复杂度。

### 2. 秘密继续由现有 SecretStore 管理

模型 API key、Gateway token 和 Coordinator refresh 默认保存在 Windows Credential Manager 或
macOS Keychain。只有用户已显式选择 `restricted-file` 时才继续使用数据目录内权限受限的秘密
文件；打包、状态、日志和支持信息不得读取或复制秘密正文。运行包替换不迁移 keyring 条目，也不
改变既有 secret-store marker。

否决方案：为了“便携”把秘密复制进运行包或 profile。这会让程序更新、备份和故障日志扩大秘密
暴露面。

### 3. 一个手动控制入口管理两个独立组件

新增进程外层的 runtime 操作入口，至少提供 `start`、`status`、`stop`。`start` 根据 profile 和
现有配置分别生成本地应用与 Gateway 子进程；两个组件保持独立监听器、独立 PID 记录和独立日志。
控制命令退出后，已验证启动的子进程继续常驻，直到人工停止、用户会话/系统结束或进程故障。

默认启动已配置的本地应用；只有存在有效 Gateway 配置且 profile 启用 Gateway 时才启动 Gateway。
某一组件失败不会伪装为整体成功，也不会自动杀死已经健康的另一组件；总体状态为 `degraded`，
命令以非零退出并返回逐组件原因。重复 `start` 对健康实例幂等。

否决方案：把 Gateway 合并进 FastAPI lifespan。它会重新混合环回管理面与私网远端调用攻击面，
违背已归档运行时 change 的边界。

公开 CLI 固定为 `runtime configure/start/status/stop`：`configure` 只写版本化非秘密 profile，
其余操作只读取 profile 并输出结构化脱敏状态。组件由隐藏的 `runtime-child` 入口启动；其命令行只
包含组件、随机实例 ID、数据/日志路径和本地端口，不包含 token、refresh、API key 或模型 endpoint。
内部入口捕获启动异常时只记录稳定错误码，不把异常正文写入父进程输出或运行日志。

### 4. PID 不是所有权证据

每个进程记录包含 schema/version、组件、PID、启动时间、运行包版本、数据目录摘要和随机实例 ID。
`status`/`stop` 必须把记录与实时进程的可执行文件、启动时间、组件参数和健康探测联合匹配；PID 已
复用、记录陈旧或身份不明时只能报告 `stale`/`ownership-conflict`，不得终止该进程。状态文件以
当前账户权限和原子替换写入。

`stop` 先发送平台正常终止信号，等待现有应用安全点和 checkpoint；超时后报告稳定错误。首版
不得默认强杀身份不明或未完成安全停止的进程，强制终止需后续独立授权设计。

### 5. 预检与健康验证分层

启动前检查运行包清单/关键导入、profile/data-dir schema、数据目录可写性、组件配置、目标端口和
现有实例。启动后分别验证：本地应用仅环回响应；Gateway 在配置的私网地址监听且无 token 请求
得到预期鉴权拒绝；进程在稳定窗口内仍存活。预检和状态只输出稳定错误、端口和摘要，不输出完整
endpoint、token、命令行秘密或配置正文。

macOS Gateway 的本地生命周期验证与 peer 端到端验收必须分开：B 本机对自身 WireGuard 地址没有
可用 HTTP hairpin，因此本机探针失败不得把已验证所有权且正在服务 peer 的进程误报为
`startup_unstable`；反过来，PID 或监听器存在也不得单独映射为生产可用。`runtime start` 必须在
真实总 deadline 内基于进程/监听器所有权收敛，并把尚无 peer 证据表达为 `peer_unverified`；生产
accepted 仍由独立 A 端无 token 请求得到 `401` 收口。该语义由独立
`fix-macos-gateway-runtime-health` change 实现，本 change 不用弱探针临时绕过。

模型 endpoint 只做有界只读健康检查。不可达时模型状态为 `unavailable`，但本地工具、资源页、
Coordinator 同步和 Gateway 可以正常启动；运行入口不尝试寻找或启动模型程序。

### 6. 日志和状态属于数据目录

每个组件写入数据目录下受限的 runtime 日志与状态目录，使用有界轮转和固定允许字段。日志捕获
启动、退出、稳定错误、版本和健康状态，不记录标准输入、认证 header、token/refresh、私钥、
完整远端响应或配置正文。`status` 可以返回日志路径与最后错误摘要，但不回显日志正文中的不可信
远端内容。

首版每个组件使用 5 MB、3 个备份的 `RotatingFileHandler` 持续轮转；stdout/stderr 不直接追加到
无界文件，Uvicorn access log 关闭。启动前仍轮转旧格式日志，组件启动失败只追加
`component_start_failed` 等稳定允许字段。

### 7. 替换与移除默认保留数据

运行包替换采用新版本并行落地、清单验证、手动停止、切换当前版本、手动启动和健康验证顺序。
失败时切回上一运行包并以同一数据目录启动；不得回滚或覆盖运行数据库和秘密。移除运行包默认只
删除可证明属于该版本的程序文件和非秘密安装元数据；runtime profile 作为普通配置与生产数据、
keyring 一并保留，方便重新安装后恢复。现有
`tunnelminion uninstall` 仍是需要显式确认的数据删除入口。

公开安装入口固定为 `runtime-package stage/activate/status/remove`。安装状态保存完整 package ID、
当前/上一版本指针和数据目录摘要，不保存数据路径或秘密；磁盘版本目录使用 package ID 的固定长度
SHA-256 前缀，避免 Windows 深层依赖超过传统路径长度。切换和移除前只要任一进程记录不可读或
对应 PID 仍存在就 fail closed。Windows 的程序移除从安装目录外的已验证运行包执行，避免运行中
`.exe` 自删除。

### 8. 不注册任何自启动机制

构建、安装和 runtime 命令不得创建或修改系统服务、计划任务、LaunchAgent/Daemon、登录项或
第三方守护配置。验收必须保存相应系统状态的前后摘要，证明人工启动只创建本次自有进程、PID 和
日志。机器重启后状态应为 `stopped`，由用户再次手动执行 `start`。

用户已明确不需要开机自启动。生产节点不为该验收执行重启；验收以 Windows 服务/计划任务/启动
目录和 macOS launchctl/LaunchAgent 均无 TunnelMinion 注册、人工停止后后续独立会话保持
`stopped` 作为安全等价证据。真实重启后的预期仍是 `stopped`，且没有任何恢复入口会自动运行。

## Risks / Trade-offs

- [冻结包对 keyring 或原生扩展收集不完整] → 先做双平台干净环境 spike、清单和启动自检，未通过
  时停止实现，不回退到隐式全局依赖。
- [后台进程因 PID 复用误杀用户程序] → PID 与可执行文件、启动时间、组件和实例记录联合验证，
  不确定时 fail closed。
- [两个组件产生部分启动状态] → 逐组件结果、整体 `degraded`、幂等重试和显式停止，不假装原子成功。
- [日志或状态泄露秘密] → 固定允许字段、受限权限、轮转、秘密扫描和异常正文清洗。
- [无自启动导致重启后节点离线] → `status` 明确显示 `stopped`，文档提供一个手动入口；这是用户
  已选择的可控性取舍。
- [macOS 首次运行的冻结程序被应用防火墙挂起入站连接] → 首版已选择当前机器人工授权，用户只对
  清单中的精确 executable 通过系统 UI 放行，并由 A 端 `401` 复核；Developer ID/公证留给未来
  对外分发 change。每个新 artifact 仍需重新核对授权，不把路径或监听器当作稳定信任身份。
- [旧开发 Gateway 无法作为可靠回退] → 切换前先验证并记录当前可用入口，失败时恢复该入口，而不
  假设源码 checkout、`.venv` 或 `PYTHONPATH` 仍可复现。2026-08-01 复验后的安全入口是正式候选包
  direct `gateway --data-dir data`，它当前可服务 peer，但尚未由 runtime 管理。
- [本 change 演变成完整安装器] → 首版只做可重复运行目录与手动 lifecycle；签名、公证、GUI、
  自动更新和系统服务继续留在后续 change。

## Migration Plan

1. 用相同 fixture 比较两种可离线运行的打包布局，选定 Windows/macOS 首版后端和清单格式。
2. 实现 runtime profile、目录边界和只读预检，不启动或停止任何生产进程。
3. 实现进程记录、`start/status/stop` 与 fake 组件测试，再接入本地应用和独立 Gateway。
4. 在临时数据目录验证依赖损坏、重复启动、PID 复用、端口占用、部分失败和正常停止。
5. 构建双平台运行包，在干净用户环境完成安装、手动常驻、重启后手动恢复、替换和保留数据移除。
6. 最后在现有 A/B 上仅替换启动方式，保存 `HomeMac`、WireGuard、路由、Murus、8082、8787、
   配置和秘密存储摘要的前后不变性；Application Firewall 只允许用户已明确批准的精确 executable
   条目发生预期变化，未经另行授权不修改其他网络状态。
7. 回滚时停止可证明自有的打包进程，恢复切换前已验证可用的程序入口并复用同一数据目录；不得
   假设旧开发环境可重建，身份不明或停止失败时保持现场并进入人工处理。

### 2026-08-01 真实 A/B 首次替换结论

- A 的打包本地应用完成安装、切换、手动启动、终端脱离常驻和状态检查，模型仍是外部进程。
- B 的打包本地应用正常，但 ad-hoc 签名的冻结 Gateway 虽拥有 `10.77.0.1:8787` 监听器，A 发出的
  HTTP 请求只进入内核连接队列而没有到达应用。macOS Application Firewall 日志明确记录该签名
  标识的入站 flow 被 `Enqueuing flow without processing queue`；同地址恢复既有 `python3.12`
  Gateway 后立即重新得到 `401`。
- 验收没有修改 Murus、Application Firewall、WireGuard 或 route。打包进程已安全停止，B 恢复为
  原开发命令提供 Gateway；运行包当前指针切回已提交的 `cee836…` 候选，生产配置和 SecretStore
  摘要保持不变。
- 因此真实 B 替换尚未通过。公开签名/公证和首次入站许可不再只是“未来有分发需求时再做”的可选
  包装，而是 macOS Gateway 生产替换的前置独立 change；该 change 完成或用户明确批准防火墙变更
  前，不继续把打包 Gateway 留在生产监听地址上。

### 2026-08-01 当前机器人工授权后复验结论

- 用户选择 `local-firewall-authorization` 作为个人 A/B 首发路线，并通过 macOS 系统 UI 允许精确
  `cee836…` 正式候选 executable；Developer ID/公证不属于当前交付，未来对外分发时另开 change。
- Windows A 首次等待许可后得到 `401`，后续稳定约 85–100 ms，证明 Application Firewall 与 peer
  端到端前置条件已通过；Murus、WireGuard、稳定 route、配置、SecretStore、8082 和零自启动边界
  保持不变，只有获明确授权的防火墙条目发生预期变化。
- macOS 本机访问自身 `10.77.0.1:8787` 仍超时，导致 `runtime start` 约 185 秒后把实际可服务 peer
  的 Gateway 误报为 `startup_unstable`。运行包生命周期尚未通过，必须等待独立
  `fix-macos-gateway-runtime-health` 后重跑，不能把防火墙通过等同于 task 6.3 全部完成。
- 旧 Python 开发环境已无法重新导入 `tunnelminion`/`uvicorn`。当前安全可用状态改为正式候选包
  direct Gateway，PID 脱离终端且 A 持续得到 `401`；后续切换必须以该“切换前已验证入口”为回退
  基线，不能再假设旧 `.venv` 可用。

## Resolved Decisions

- 当前机器人工防火墙授权足以满足个人 A/B；Developer ID/公证延期到未来对外分发 change。
- 模型关闭只在临时数据目录和临时 profile 中模拟，不停止或改写生产模型。
- 真实 Coordinator enrollment/sync 因 A/B 当前未配置而明确延期，不阻塞手动运行包收尾；现有
  fake/集成测试继续覆盖“模型离线不阻止 Coordinator 代码路径”的产品契约。
- 本地生命周期与 peer 可达性的分层实现属于独立 health fix，不再塞入包信任 change。
