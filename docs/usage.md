# 使用说明

安装、配置模型、加入第二台电脑、MCP、链路追踪和安全边界的完整说明。项目简介见 [README](../README.md)。

## 安装和运行

### 1. 安装和运行

**方式一：直接用运行包（不用装 Python 和 Node.js）**

在 GitHub Actions 里找一次成功的 CI，下载对应平台的产物：`runtime-package-windows-amd64` 或
`runtime-package-macos-arm64`。先解开下载的压缩包，再解开里面的 `runtime-package.tar`，会得到一个
`package/` 目录，里面有可执行文件和 `runtime-package-manifest.json`。

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

`start` 返回以后，程序会继续在后台运行。用浏览器打开 `http://127.0.0.1:8765/` 就是服务地图。
停止用 `runtime stop --profile <同一个 profile>`。目前不会开机自启，电脑重启后要再运行一次 `start`。
如果提示 `package_invalid`，请重新下载同一次 CI 的完整运行包，不要手工拼文件。

`start` 要在这台电脑自己的桌面上运行（Windows 的 PowerShell 窗口、Mac 的"终端"App）。通过 ssh
远程启动的进程用不了系统钥匙串（Windows 凭据管理器、macOS 登录钥匙串），建机主身份、保存模型密钥时
会提示"系统钥匙串打不开"；这时回到那台电脑的桌面上 `stop` 再 `start` 一次即可。

Mac 上每换一次运行包，第一次 `start` 时屏幕上会弹出"tunnelminion 想使用钥匙串中的机密信息"。运行包没有
固定的代码签名，钥匙串把新版本当成一个新程序。输入登录密码并点"始终允许"以后，这个版本就不会再问。没点之前
程序一直等在读钥匙串这一步，`start` 会报 `startup_timeout`，输出最前面的 `hint` 也会提醒去看授权框；点完允许
再运行一次 `start` 即可。

要和别的电脑互相查、互相委派，需要同时运行网关。先按第 3 步生成或使用邀请码，然后在 `configure`
时加上 `--enable-gateway`，再运行 `start`。

只想看看、不想让它做任何改动时，可以在 `start`、`status`、`stop` 后面都加 `--read-only-preview`。
这个预览模式只支持本机组件：不会自动调查，也不能批准或执行任何操作，页面顶部会标着"预览模式"。

**方式二：从源码运行（开发用）**

需要 Python 3.11+、[uv](https://docs.astral.sh/uv/)，以及 Node.js 22.14.0（用来构建网页）。

```shell
uv sync --locked --all-groups
uv run python scripts/prepare_frontend_dist.py --root .
uv run tunnelminion --data-dir .data/a --port 8765
```

第二条命令会安装前端依赖、构建网页，并把结果放到 `build/frontend-dist/`。
打开 `http://127.0.0.1:8765/` 即可，按 `Ctrl+C` 停止。网关要另开一个终端运行：

```shell
uv run tunnelminion gateway --data-dir .data/a
```

本机网页只监听 `127.0.0.1`，局域网和组网里的其他电脑都访问不到。网关只监听你配置的组网地址。

下面的命令统一写成 `tunnelminion ...`：用运行包时换成包里的可执行文件，从源码运行时换成
`uv run tunnelminion ...`。数据目录不是默认位置时，记得加上同一个 `--data-dir`。

### 2. 配置模型

打开网页右上角"更多"里的"设置"（`/app/settings`），填写一个兼容 OpenAI 接口的模型：

- **DeepSeek**：endpoint 填 `https://api.deepseek.com/v1`，模型名称填 `deepseek-chat`，再填上 API 密钥。
- **本机模型**（例如用 llama.cpp 跑的 Qwen）：endpoint 填它的地址，例如 `http://127.0.0.1:8080/v1`。
  没有密钥就留空。建议勾选"关闭思考模式"：实测同一个问题，本机 Qwen 从约 30 秒缩短到约 1 秒。

保存前会先试调一次模型，确认它支持工具调用和结构化输出，试通过了才保存。API 密钥只存在系统钥匙串里
（Windows 凭据管理器 / macOS 钥匙串），不会写进配置文件，也不会出现在日志里。

不配模型也能看服务地图，只是不能问 Agent。

### 3. 把第二台电脑加进来

两台电脑之间要先能通过组网互相访问。

**发邀请的电脑**（通常是配好模型的那台）：

```shell
tunnelminion invite --bind-host <本机组网地址> --allow-delegation --allow-model-borrowing
```

- `--bind-host` 只在第一次需要，告诉网关监听哪个组网地址。
- `--allow-delegation` 允许对方把问题委派过来；`--allow-model-borrowing` 允许对方借用本机的模型。
  两个开关默认都是关的，按需要打开。
- `--daily-quota` 设置对方每天最多能用多少 token，默认 200000。

命令会打印一行以 `tmi1_` 开头的邀请码。这个码 24 小时内有效、只能用一次，相当于一把钥匙，只发给要加入的人。
然后启动网关，并让它一直开着。

**要加入的电脑**：

```shell
tunnelminion join <邀请码>
```

它会自动找到本机的组网地址，向对方报到，然后把对方登记为配对电脑。如果对方允许借用模型、本机又还没配过模型，
它会自动改用对方的模型并测试一次。想保留本机原来的模型，就加 `--keep-model`。加入以后，这台电脑也启动网关，
对方就能在地图上看到它的服务。

其他常用命令：

| 命令 | 作用 |
|---|---|
| `tunnelminion node-name <名字>` | 给本机起个显示名 |
| `tunnelminion peer-rename <节点 ID> <名字>` | 给配对的电脑改显示名 |
| `tunnelminion model-usage` | 提供模型的一方查看今天每台电脑用了多少次、多少 token |
| `tunnelminion repair-list` / `repair-approve --repair-id <ID>` | 在命令行查看和批准修复（备用方式，平时点地图上的感叹号就行） |

### 4. 接到 Claude Code 等外部 Agent（MCP）

在外部 Agent 里加一个 MCP 服务端，命令写：

```shell
tunnelminion mcp --data-dir <数据目录>
```

这个命令只通过标准输入输出通信，不会打开网络端口。只开放只读工具，比如本机服务清单、监听端口、进程、
Docker 容器、端口探测和组网状态。委派和修复都不开放。详见 [`mcp.md`](design/mcp.md)。

### 5. 打开链路追踪

用环境变量 `TUNNELMINION_TRACE` 控制，默认关闭：

| 取值 | 效果 |
|---|---|
| `console` | 打印到标准错误 |
| `file` | 写入数据目录下的 `traces.jsonl`，可以用 `TUNNELMINION_TRACE_FILE` 换一个文件 |
| `otlp` | 发给 Jaeger 这类收集器，地址用 `OTEL_EXPORTER_OTLP_ENDPOINT` 设置 |

追踪记录不包含消息内容、提示词、工具参数和输出、令牌或文件路径。详见 [`tracing.md`](design/tracing.md)。

### 导出与卸载

- `tunnelminion export --output <文件>`：导出一份脱敏后的数据，排查问题时用。
- `tunnelminion uninstall --confirm DELETE-TUNNELMINION-DATA`：删除 TunnelMinion 自己的数据和保存的密钥。

## 安全边界

- **Agent 只能用只读工具查问题。** 能看端口、进程、容器、日志和启动记录，不能执行任意命令。
- **修复要批准。** 修法只有三种：重启容器、重新拉起脚本、在 Mac 上重新启动你自己的后台服务（不碰系统和别的用户的服务）。实际执行的命令由本机代码根据服务身份拼出来，
  模型写的文字不会进入命令。每次动手前都要有人点批准，默认只能在服务所在电脑的本机网页上批准。一次批准只修一次，10 分钟内有效；
  动手前还会再核对一遍情况有没有变。同一个服务 1 小时内最多修 3 次，验证没通过也不会自动重试。
- **别的电脑默认不能替你批准。** 另一台电脑提出的修复，默认要到那台电脑的地图上批准。服务所在电脑的主人可以为
  信任的电脑单独打开"允许替我批准修复"（默认关闭）：生成邀请码时加 `invite --allow-proxy-approval`，
  手动配置对端时加 `gateway-configure --allow-proxy-approval`，已经配对的电脑运行
  `tunnelminion peer-proxy-approval <对端编号> on`（`off` 关闭，改完重启 TunnelMinion 生效）。
  打开后，那台电脑在自己的地图上点感叹号就能批准；批准只能针对已经提出、仍在等待的修复，不能新建或修改修法，
  动手的仍是服务所在的电脑，动手前照样再核对一遍。
- **只修用户自己的服务。** 系统进程和系统自带服务、桌面应用、TunnelMinion 自己、Docker 本身、组网、防火墙和系统设置，
  一律不碰。也不会删数据、改文件、装软件或提权。
- **令牌只存摘要。** 网关和发邀请的电脑只保存配对令牌的摘要；本机要用的令牌和模型 API 密钥存在系统钥匙串里；没有图形界面的会话可以用 `--secret-store restricted-file` 改存到只有本人可读的文件。
- **委派和借用模型都要对方明确允许**，而且两个开关默认都是关的。借用模型有每日额度，提供方只记用量，不存内容。
- **网络边界。** 本机网页只监听 `127.0.0.1`。网关只监听配置好的组网地址，必须是私有网段地址，
  不能是环回地址、`0.0.0.0` 或公网地址。

更完整的威胁分析见 [`docs/security/`](security)。

## 开发

### 质量门禁

```shell
uv run python scripts/quality.py all
```

这条命令依次做格式、lint、类型检查和测试；也可以单独跑其中一项：`format`、`lint`、`typecheck`、`test`。
前端在 `frontend/` 目录下：

```shell
npm --prefix frontend ci
npm --prefix frontend run typecheck
npm --prefix frontend test
```

### 目录结构

| 目录 | 内容 |
|---|---|
| `src/tunnelminion/agent/` | Agent 循环、委派、邀请与加入、服务识别 |
| `src/tunnelminion/tools/`、`platforms/` | 工具注册与执行通道；Windows / macOS 只读适配器 |
| `src/tunnelminion/gateway/` | 电脑之间的网关：认证、服务清单、委派、模型借用 |
| `src/tunnelminion/repair/` | 修复：提出、批准、执行、验证 |
| `src/tunnelminion/model/` | 模型配置、OpenAI 兼容接口、借用的远端模型 |
| `src/tunnelminion/web/` | 本机网页的后端接口 |
| `src/tunnelminion/mcp_server.py`、`telemetry.py` | MCP 服务端、链路追踪 |
| `frontend/` | 网页（React），服务地图在 `src/features/service-map/` |
| `tests/` | 自动测试 |
| `evaluations/` | 固定口径的评测数据和报告 |

### 文档

- [`docs/project/roadmap.md`](project/roadmap.md)：路线图，包括现在做到哪、下一步做什么。
- [`docs/design/`](design)：每项能力的设计和真机验收记录。
- [`docs/architecture.md`](architecture.md)：整体架构和各部分的边界。
- [`docs/adr/`](adr)：重要技术决策。
- [`docs/project/README.md`](project/README.md)：项目推进方式，以及两台电脑通过 GitHub 协作的方法。
- 协作约定（分支命名、提交格式等）见 [`AGENTS.md`](../AGENTS.md)。
