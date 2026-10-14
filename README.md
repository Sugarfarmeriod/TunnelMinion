# TunnelMinion

TunnelMinion 是一个面向私有网络的跨平台分布式 AI Agent 平台。每个节点运行一个本地
Agent，通过受控工具发现和诊断本机及已授权对等节点上的服务，并利用现有 WireGuard
隧道完成跨节点通信。

项目已经交付只读 Windows/macOS Agent MVP、人工审批的临时服务共享、统一 Prompt/Context
Runtime，以及可恢复的 `local_only` 跨节点调查纵切。当前总流程、阶段状态和下一步统一维护在
[《产品路线图》](docs/project/roadmap.md)，项目推进方法见
[《项目推进方式》](docs/project/README.md)。历史 `openspec/` 内容完整保留，但不再创建新的
OpenSpec change。

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

程序、聊天、调查和访问请求在同一个工作台处理；原来的聊天、操作网址仍可使用，不需要重新找记录。
点开程序后选择“帮我看看”，提问会带上所选程序的连接记录。调查旁的追问沿用原调查线程，
查看请求不丢对话草稿；只有主动发送问题才调用模型，批准和执行仍须在原请求中明确确认。

启用私网 Gateway 前，先按[开发启动与运维指南](docs/guide/开发启动与运维.md)完成地址、peer 和
SecretStore 配置，把其中的 `uv run tunnelminion` 替换为包内可执行文件，再在 `runtime configure`
后加 `--enable-gateway`。这不会修改 WireGuard、防火墙、路由或 DNS。

首页会按需为 Python 服务显示启动入口，例如 `相册.py` 或 `http.server`。VS Code 等软件的终端
直接启动脚本时也适用；文件名只说明入口，不代表已经识别业务用途。服务所在电脑临时读取启动参数，
只返回最多 80 字符的脚本 basename 或模块名，完整参数和路径不保存、不外传、不交给模型；不读取
环境变量或文件内容。普通监听查询不读取启动参数，旧版电脑、无权读取、内联代码和不支持的调试包装
仍显示原来的 Python 归属，不影响服务记录及访问状态。

首页按已确认的同一进程或 Docker 容器收拢多个连接入口，程序名称优先，端口与地址展开查看。
同名但归属不同、归属冲突或记录过期时保持分开；每个入口的状态和调查链接仍绑定原服务。
完整检测清单保留未知及后台项目，不增加模型调用、服务访问权限或额外采集。
自行安装目录中的普通监听程序也可自动显示名称，TCP/UDP 入口分别保留；系统目录和桌面应用包
不因此全部进入首页。可执行路径只在本机临时用于筛选，只留下程序名；无法读取或不满足精选条件时
仍保留技术清单中的原记录。Docker 连续发布端口与单端口使用相同的容器归属判断。
调查、访问申请和批准确认沿用首页的程序名，具体连接入口单独标明，不因名称相同改变操作对象。

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
