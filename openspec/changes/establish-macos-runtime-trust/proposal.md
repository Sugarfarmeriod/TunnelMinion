## Why

真实 A/B 替换证明，ad-hoc 签名的 macOS 冻结 Gateway 即使拥有 WireGuard 监听器，入站 HTTP flow
仍可能被 macOS Application Firewall 挂起，导致运行时把“进程存在”误认为“peer 可用”。在让
`package-manual-node-runtime` 接管生产 B 前，必须建立明确、可复核且不静默放宽防火墙的包信任与
端到端健康边界。

## What Changes

- 为 macOS 运行包建立显式信任决策门：比较“当前机器人工授权”和“Developer ID 签名、公证”两条
  路线，在用户确认前只做只读预检和证据采集，不修改防火墙或 Keychain。
- 固定所选路线的构建身份、安装路径、升级行为、失败诊断和回滚契约；任何需要管理员权限、Apple
  开发者身份或外部凭据的步骤必须由用户明确授权并在日志中保持零秘密。
- 区分本机进程/监听健康与 WireGuard peer 端到端可达性；Gateway 只有在授权 peer 的无 token
  请求得到 `401` 后才能通过生产替换验收，禁止用 PID 或监听器存在替代。
- 在真实 A/B 上重跑首次启动、后续版本替换、终端脱离常驻、停止/恢复和防火墙前后不变量验收；
  失败时恢复既有 Python Gateway，不覆盖配置、SecretStore、WireGuard、route 或 Murus。
- 非目标：不实现开机自启、系统守护进程、自动关闭防火墙、Murus 管理、WireGuard/route 写入、
  Windows 代码签名、公共安装 GUI 或 Apple 开发者账户采购。

## Capabilities

### New Capabilities

- `macos-runtime-package-trust`: macOS 运行包的显式信任决策、签名/授权证据、首次入站许可、升级身份
  稳定性、peer 端到端健康验证和安全回退边界。

### Modified Capabilities

无。本 change 为仍在进行的 `manual-node-runtime-operations` 增加 macOS 部署前置能力，不降低其
Gateway 健康与生产数据保护要求。

## Impact

- 影响 macOS PyInstaller 构建/签名流水线、运行包清单、安装与预检 CLI、Gateway 健康状态、A/B
  验收脚本和运维文档。
- 当前 Mac 没有可用 codesigning identity，`notarytool` 可用但无法在没有 Developer ID 的情况下
  完成公证；当前机器防火墙授权需要管理员交互。因此实现阶段以用户选择和外部凭据可用性为硬门禁。
- 不改变 Gateway HTTP 协议、token、SecretStore、Coordinator、模型生命周期或既有网络治理权限。
