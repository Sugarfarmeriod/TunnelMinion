## Why

真实 A/B 替换证明，ad-hoc 签名的 macOS 冻结 Gateway 即使拥有 WireGuard 监听器，入站 HTTP flow
仍可能被 macOS Application Firewall 挂起。用户随后选择当前机器人工授权，并通过系统 UI 允许
精确 `cee836…` 正式 executable；Windows A 已稳定得到无 token `401`。因此当前 change 不再并行
设计两套分发路线，而是固化这条个人 A/B 所需的最小信任、证据和升级边界。

## What Changes

- 首发 trust mode 固定为 `local-firewall-authorization`：只允许用户通过 macOS 系统 UI 对清单中
  精确匹配的已验证 executable 人工授权；TunnelMinion 不自动添加、删除或扩大防火墙规则。
- 把授权证据绑定 package ID、manifest/入口摘要、防火墙可观察状态和 A peer 无 token `401`；不把
  PID、进程名、目录或监听器单独当作信任证据，也不读取 Gateway token。
- 每个新 artifact/路径在生产切换前重新核对授权状态和 peer `401`；失败时恢复切换前已验证可用
  的程序入口，不假设旧 Python checkout、`.venv` 或 `PYTHONPATH` 仍可复现。
- Developer ID、hardened runtime、公证 ticket 和签名后分发清单延期到未来“对外分发”独立 change。
- macOS 本机 hairpin 与 runtime 生命周期误判移交 `fix-macos-gateway-runtime-health`，本 change 只
  保留防火墙信任及 peer 验收证据，不重复设计运行状态机。
- 非目标：不实现开机自启、系统守护进程、自动关闭防火墙、Murus 管理、WireGuard/route 写入、
  Windows 代码签名、公共安装 GUI 或 Apple 开发者账户采购。

## Capabilities

### New Capabilities

- `macos-runtime-package-trust`: 当前机器对精确 macOS 运行包的人工入站许可、artifact/peer 验收
  证据、新版本重新核对和安全回退边界。

### Modified Capabilities

无。本 change 只记录当前机器部署前置和证据，不修改 `manual-node-runtime-operations` 的运行状态
语义；本地生命周期与 peer 可达性分层由独立 health fix 修改。

## Impact

- 影响 macOS 运行包验收证据、升级检查、人工许可与撤销文档；不新增自动防火墙写入或签名 CLI。
- 当前 Mac 没有可用 codesigning identity；该事实只说明 Developer ID/公证不属于本次个人 A/B
  交付，不再阻塞当前机器人工授权路线。
- 不改变 Gateway HTTP 协议、token、SecretStore、Coordinator、模型生命周期或既有网络治理权限。
