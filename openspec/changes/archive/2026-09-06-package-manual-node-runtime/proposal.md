## Why

TunnelMinion 已有手动 runtime、版本切换和双平台冻结构建，但它还没有形成普通用户能直接使用的
交付物。2026-09-06 对正式 CI artifact 的现场复核证明：下载归档没有
`runtime-package-manifest.json`，所以 `runtime start` 会在预检阶段以 `package_invalid` 失败；现有
干净环境验收会临时补入该文件并直接调用内部 `runtime-child`，因而没有发现真实用户路径已经断裂。

incident 能力已经在真实产品评估中闭环，下一步最值得做的是把现有能力交付成无需 Python、uv、
源码 checkout 或开发虚拟环境的 Windows/macOS 手动运行包，而不是继续追加 incident 小修补或恢复
packet relay、复杂 Provider、自动组网和 showcase。

## What Changes

- 让 Windows/macOS 下载归档自带与构建证据逐字节一致的安装清单，保持严格文件闭合校验，损坏或
  被替换的清单仍须拒绝启动。
- 从无源码的无关工作目录解包正式 artifact，只通过用户公开命令完成 `configure → start → status →
  stop`，覆盖环回本地应用、已配置私网 Gateway、重复启动和终端退出后常驻。
- 通过公开 `runtime-package stage/activate/status/remove` 验证版本落地、切换和默认保留数据/
  SecretStore；不引入自动更新器。
- 修正顶层 `--help` 展开全部端口值的问题，并补齐面向下载包的最短使用说明和稳定故障提示。
- 让 Windows amd64 与 macOS arm64 CI 从同一提交构建、封装并验收实际上传归档，保存可复核且不含
  秘密的证据。
- 非目标：不实现系统服务、开机自启、管理员安装器、代码签名/公证、Linux、模型进程管理、复杂
  Provider、packet relay、自动组网、新前端或生产 A/B 替换。

## Capabilities

### New Capabilities

- `manual-node-runtime-operations`: Windows/macOS 自包含运行包、程序/数据/秘密分离、公开手动生命周期、
  严格预检、版本切换与保留数据移除。

### Modified Capabilities

无。本 change 只完成现有 runtime 的交付边界，不改变 incident、Gateway、Provider、WireGuard、
防火墙、路由或 DNS 契约。

## Impact

- 影响运行包暂存/封装、清单闭合校验、公开 CLI 验收、少量 CLI 帮助文本、CI 和运行说明。
- 复用现有 PyInstaller 构建、runtime 控制、安装仓储、SecretStore 与 graceful shutdown；不新增依赖
  或后台管理机制。
- 验收仅使用当前用户权限、临时数据目录和临时高端口；不触碰生产服务、8080/8787 或真实网络配置。
