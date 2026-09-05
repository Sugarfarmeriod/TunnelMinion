# TunnelMinion

TunnelMinion 是一个面向私有网络的跨平台分布式 AI Agent 平台。每个节点运行一个本地
Agent，通过受控工具发现和诊断本机及已授权对等节点上的服务，并利用现有 WireGuard
隧道完成跨节点通信。

项目已经交付并归档首个只读 Windows/macOS Agent MVP、人工审批的临时服务共享，以及统一
Prompt/Context Runtime。稳定需求位于 [`openspec/specs`](openspec/specs)，下一阶段按
[`openspec/ROADMAP.md`](openspec/ROADMAP.md) 规划 Coordinator、节点身份和服务目录，不直接
实施范围过大的旧自动组网 change。

如果希望先用非框架术语理解产品、当前进度以及 FastAPI、LangChain、LangGraph 的分工，
请阅读[《从零理解 TunnelMinion》](docs/guide/从零理解-tunnelminion.md)。
实现边界、跨节点调用链和全部架构决策入口见[《TunnelMinion MVP 架构》](docs/architecture.md)。
实际启动、Qwen 配置、A/B peer、排错、脱敏导出和完整卸载见
[《A/B 开发启动与运维》](docs/guide/开发启动与运维.md)。

## 直接使用 Windows/macOS 运行包

从成功 CI 的对应平台任务下载 `runtime-package-windows-amd64` 或
`runtime-package-macos-arm64`，先解开 artifact 外层压缩包，再解开其中的
`runtime-package.tar`。得到的 `package/` 必须同时包含可执行文件和
`runtime-package-manifest.json`；运行时不需要安装 Python、uv、Node.js，也不需要源码目录。

Windows PowerShell：

```powershell
tar -xf .\runtime-package.tar
$Profile = Join-Path $HOME ".tunnelminion\runtime-profile.json"
$Data = Join-Path $HOME ".tunnelminion\data"
$Exe = ".\package\tunnelminion.exe"

& $Exe runtime configure --profile $Profile --data-dir $Data --local-port 8765
& $Exe runtime start --profile $Profile
& $Exe runtime status --profile $Profile
```

macOS：

```bash
tar -xf ./runtime-package.tar
PROFILE="$HOME/.tunnelminion/runtime-profile.json"
DATA="$HOME/.tunnelminion/data"
EXE="./package/tunnelminion"

"$EXE" runtime configure --profile "$PROFILE" --data-dir "$DATA" --local-port 8765
"$EXE" runtime start --profile "$PROFILE"
"$EXE" runtime status --profile "$PROFILE"
```

`start` 返回后，本地组件仍在后台运行；浏览器打开
`http://127.0.0.1:8765/app/overview`。需要停止时执行：

```text
<包内可执行文件> runtime stop --profile <PROFILE>
```

首版不会注册开机或登录自启动，机器重启后需要再次手动执行 `start`。模型服务仍是外部进程；
`model_unconfigured` 或 `model unavailable` 不会阻止本地确定性功能启动。若返回
`package_invalid`，不要手工生成或从别处拼接清单，应重新下载同一 CI 任务的完整运行包。

启用私网 Gateway 前，先按[开发启动与运维指南](docs/guide/开发启动与运维.md)完成地址、peer 和
SecretStore 配置，把其中的 `uv run tunnelminion` 替换为包内可执行文件，再在 `runtime configure`
后加 `--enable-gateway`。这不会修改 WireGuard、防火墙、路由或 DNS。

## 开发环境

依赖条件：

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

安装锁定后的开发依赖：

```shell
uv sync --locked --all-groups
```

运行全部本地质量门禁：

```shell
uv run python scripts/quality.py all
```

也可以分别执行 `format`、`lint`、`typecheck` 和 `test`：

```shell
uv run python scripts/quality.py format
uv run python scripts/quality.py test
```

## 启动当前 Windows 资源页

```shell
uv run tunnelminion --data-dir .data/a --port 8765
```

浏览器打开 `http://127.0.0.1:8765/chat` 使用本地聊天页，打开
`http://127.0.0.1:8765/resources` 查看本机只读资源，打开
`http://127.0.0.1:8765/memories` 管理长期记忆，或打开
`http://127.0.0.1:8765/api/docs` 查看模型配置、thread/run、记忆与资源 API。服务固定绑定环回
地址，不会直接暴露到局域网或 WireGuard 网络。

默认运行仍将现有 WireGuard 网络视为用户基础设施。仓库包含受管网络 Provider、离线 fake
门禁和一次隔离的真实 A/B 验收证据，但每次真实写入仍必须使用独立接口、完整回滚计划并获得
单独明确授权；普通开发命令和测试不得创建、修改或删除现有 WireGuard 配置。
