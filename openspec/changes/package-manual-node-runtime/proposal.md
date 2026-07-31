## Why

TunnelMinion 的受管节点运行时已经接入常规 Windows/macOS 应用，但真实 B 节点仍依赖开发目录、
易失效的虚拟环境和人工记忆来分别启动本地应用与 Gateway。生产配置和秘密仍然完好时，运行环境
或终端退出就可能让节点表面上“配置好了”却没有实际服务，因此现在需要一个可重复、可检查、
明确不做开机自启的手动生产运行边界。

## What Changes

- 产出带固定版本和锁定依赖的 Windows/macOS 节点运行包；运行时不依赖源码 checkout、环境变量
  拼接或某个开发者虚拟环境仍然有效。
- 规定安装目录、持久数据目录与秘密存储三者分离：可替换的程序文件不得承载生产配置、运行状态
  或秘密；普通配置/状态使用显式数据目录，秘密默认进入操作系统 keyring。
- 提供统一的手动 `start`、`status`、`stop` 入口，分别监督环回本地应用和私网 Gateway 两个进程；
  启动后进程可在发起终端退出后继续常驻，停止时执行现有安全关闭语义。
- 增加重复启动、陈旧 PID、端口占用、依赖损坏、配置缺失、模型不可达和 Gateway 鉴权探测的
  确定性预检与脱敏状态；日志、PID 和退出信息不得包含 token、refresh 或密钥正文。
- 把模型服务明确视为外部依赖：运行入口只检查并报告配置的模型 endpoint，不负责启动、停止或
  安装模型。
- 为升级和移除运行包建立最小安全边界：替换程序不得覆盖数据目录；移除程序默认保留生产数据和
  keyring 秘密，删除数据仍沿用显式确认的现有卸载流程。
- 非目标：不注册开机/登录自启动项，不实现系统服务或管理员守护进程，不合并本地应用与 Gateway
  监听器，不实现 Linux、relay、新前端、模型安装或自动升级。

## Capabilities

### New Capabilities

- `manual-node-runtime-operations`: Windows/macOS 可重复运行包、安装/数据/秘密分离、手动常驻进程
  生命周期、预检、状态、日志以及安全替换/移除边界。

### Modified Capabilities

无。本 change 在现有 `managed-node-runtime`、`model-provider-configuration` 和 Gateway 契约之外
增加操作与打包边界，不改变它们的协议、安全或应用内生命周期语义。

## Impact

- 影响 Python 打包配置、平台启动器/进程控制、CLI、数据目录解析、日志与运维文档。
- 复用现有 `tunnelminion` 本地应用、独立 `gateway` 命令、配置仓储、keyring/受限文件秘密存储和
  graceful shutdown；不新增网络协议或 L3 写入权限。
- 需要 Windows/macOS 的构建与干净环境验收，证明没有源码 checkout 或开发虚拟环境也能启动，
  并证明运行包替换前后生产数据、秘密和既有 A/B 网络不变。
