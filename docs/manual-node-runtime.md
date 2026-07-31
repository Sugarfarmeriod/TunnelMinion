# 手工节点运行包

TunnelMinion 节点运行包面向当前用户安装，不创建 Windows Service、计划任务、启动文件夹项、
macOS LaunchAgent 或 LaunchDaemon。执行 `runtime start` 后进程会脱离当前终端常驻；注销、关机或
重启后不会自动恢复，需要用户再次手工执行 `runtime start`。

## 文件放在哪里

程序、普通配置、运行数据和秘密彼此分离：

- 版本化程序由 `runtime-package` 放在当前用户的 `TunnelMinionRuntime` 标准应用数据目录；
- `runtime-profile.json` 放在当前用户的 TunnelMinion 标准配置目录，只记录数据目录、启用组件和
  本地端口等非秘密字段；
- SQLite、节点身份、组件状态和日志放在 profile 指向的 TunnelMinion 数据目录；
- 模型 API key、Gateway token 和 Coordinator refresh 默认保存在 Windows Credential Manager
  或 macOS Keychain。只有用户已经显式选择 `restricted-file` 后端时，秘密才会进入数据目录内的
  权限受限文件；它们不会进入程序目录、profile、命令输出或构建清单。

程序升级和只移除程序都复用并保留同一数据目录和 SecretStore。真正删除数据仍使用现有的
`tunnelminion uninstall`，并要求显式确认。

当前 A/B 生产布局的例子如下，路径只用于说明边界，不应写入构建清单：

- Windows A 的程序版本位于当前用户 `%LOCALAPPDATA%\TunnelMinion\TunnelMinionRuntime\versions`，
  profile 和默认数据位于 `%LOCALAPPDATA%\TunnelMinion\TunnelMinion`；
- macOS B 的程序版本位于 `~/Library/Application Support/TunnelMinionRuntime/versions`，profile 位于
  `~/Library/Application Support/TunnelMinion/runtime-profile.json`；
- macOS B 继续复用既有 `~/Working-Env/tunnelminion-mvp/data` 作为生产数据目录，其中的
  `restricted-file` SecretStore 不会被复制进 `Application Support` 下的程序目录。

## 第一次配置与手工启停

仅运行本地应用：

```text
tunnelminion runtime configure
tunnelminion runtime start
tunnelminion runtime status
tunnelminion runtime stop
```

要让同一节点同时运行独立 Gateway，先确保既有数据目录中已有有效 `gateway.json` 和对应
SecretStore，再把 Gateway 加入非秘密 runtime profile：

```text
tunnelminion runtime configure --enable-gateway
tunnelminion runtime start
tunnelminion runtime status
```

`runtime configure --enable-gateway` 不会生成 token，也不会改防火墙、WireGuard、route 或 Murus；
它只声明“手工 start 时也启动已经配置好的 Gateway”。如果 `gateway.json` 不存在，状态会明确显示
`gateway_unconfigured`，本地应用仍可独立运行。

## 安装和切换版本

先从发布位置校验并并行放置新包，不改变当前版本：

```text
tunnelminion runtime-package stage --package-root <包目录> --manifest <manifest.json>
```

然后按顺序手工停止、切换、启动并检查：

```text
tunnelminion runtime stop
tunnelminion runtime-package activate --package-id <package-id>
tunnelminion runtime-package status
<status 中 current_program_directory 里的 tunnelminion> runtime start
<status 中 current_program_directory 里的 tunnelminion> runtime status
```

新版本健康失败时，先用新版本执行 `runtime stop`，再对上一 package ID 执行
`runtime-package activate`，随后用上一程序目录启动。切换只改变程序指针，不回滚 SQLite、checkpoint、
节点身份、Gateway token 或 Coordinator refresh。

## 只移除程序

先停止所有受管组件，再从安装目录之外的一份已验证运行包执行：

```text
tunnelminion runtime stop
tunnelminion runtime-package remove
```

Windows 不允许正在执行的 `.exe` 删除自身，因此 `remove` 应从发布包或另一份外部运行包调用。
成功输出会明确标记 `data_preserved` 和 `secret_store_preserved`。如果进程状态无法确认，切换和移除
都会 fail closed，不会猜测进程归属或强杀。

## macOS Gateway 首次入站信任

macOS Application Firewall 与 Murus 是两套独立控制。冻结运行包第一次在 WireGuard 地址监听时，
系统可能允许 TCP 握手却把入站 flow 留在许可队列；此时 `lsof` 会显示 `10.77.0.1:8787` 正在监听，
但 peer 的 HTTP 请求会超时。不能仅凭 PID 或监听器把这种状态报告为 Gateway 可用，正式验收必须
从已授权 peer 发起无 token 请求并得到 `401`。

`runtime-package` 不会自动添加应用防火墙例外，也不会修改 Murus、WireGuard 或 route。2026-08-01
真实 A/B 首次替换遇到该限制后，打包 Gateway 已安全停止，B 恢复为原有 `python3.12` Gateway；A
重新得到 `401`。在稳定签名/公证或当前机器的显式防火墙授权方案通过独立 change 评审前，不应把
冻结 Gateway 留在生产监听地址上。

排查时先区分三层结果：

1. `runtime status` 证明受管进程身份和本地生命周期；
2. `lsof -nP -iTCP:8787 -sTCP:LISTEN` 只证明进程拥有监听器；
3. A 端访问 `/v1/capabilities` 得到 `401` 才证明 WireGuard、系统防火墙和 Gateway 端到端可达。
