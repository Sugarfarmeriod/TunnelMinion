# 第三种修法：重新启动 macOS 用户级后台服务（LaunchAgent）

> 状态：设计已确认，待实现（分支 `feature/launchagent-repair`）。
> 相关设计：修复的提出、批准、执行前核对和验证见 [`agent-fix.md`](agent-fix.md)；巡检和"挂了可以自动修"见
> [`proactive-patrol.md`](proactive-patrol.md)；服务分档见 [`node-agents.md`](node-agents.md)。

## 一句话

Mac 上很多常驻服务不是从终端启动的，而是主人自己装进 `~/Library/LaunchAgents` 的后台服务，例如
`brew services start postgresql` 装的数据库、自己写的定时网页小服务。它们退出以后，现在 Agent 只能说
"请你自己重启"。有了这种修法，Agent 能提出"重新启动后台服务 homebrew.mxcl.postgresql@16"，主人点批准
（或按"挂了可以自动修"由巡检代批准），本机用一条固定的 `launchctl kickstart` 把它重新拉起来，然后自己
确认进程起来了、端口在听、首页能打开。

## 用户影响

| 现在 | 有了这种修法以后 |
|---|---|
| 地图上看不出某个服务是 macOS 后台服务，显示成普通程序 `program:postgres@5432` | 认出来以后显示"后台服务 homebrew.mxcl.postgresql@16"，身份按后台服务的标签记，换端口、换进程号都不变 |
| 后台服务退出后，它从地图上消失，或者只在标过"是我的服务"时显示"已停止" | 见过它正常运行以后，退出了照样显示"已停止"，巡检照样会提醒 |
| Agent 查明是后台服务退出了，只能建议你手动 `launchctl kickstart` | Agent 提出修法，你点批准就修；打开过"挂了可以自动修"的，巡检直接修 |
| — | 你用 `brew services stop` 或 `launchctl bootout` 有意卸载的服务，Agent 认得出来，**不会替你重新加载** |

只在 macOS 上有这种修法；Windows 上没有对应的东西，资格检查直接说明"只有 macOS 才有"。

## 现在已经有什么（以代码为准）

| 现有部分 | 在哪 | 这次怎么用 |
|---|---|---|
| 两种修法、资格检查、计划、执行前核对、执行、验证、收场、限次、审计 | `repair/` | **原样复用框架**，加第三种修法 |
| 修法登记为 L2，模型拿不到执行入口 | `repair/definitions.py`、`tools/registry.py` | 新修法同样登记为 L2 |
| `propose_repair`：模型只填服务身份、修法种类、理由 | `repair/agent_tools.py` | 修法种类多一个枚举值，说明里写清何时用 |
| 巡检按服务种类补提固定修法、"挂了可以自动修" | `patrol/` 的 `repair_kind_for` | 认识新身份，对应新修法 |
| 进程来历判断（终端、用户目录、系统、桌面应用……） | `platforms/process_origin.py` | 不改分档规则；只在 macOS 上额外认出"这个进程属于哪个用户后台服务" |
| 服务身份 `docker:`、`python:`、`program:`、`port:` | `agent/service_marks.py`、`domain/service_marks.py` | 新增 `launchd:<标签>` |
| 启动记录：脚本活着时记下怎么启动，退出后地图显示"已停止" | `repair/launch_records.py` | 照同样思路新增"后台服务记录"，只记标签和端口，不记命令和路径 |

## 规则

### 1. 怎么认出一个服务来自用户 LaunchAgent

全部是本机只读事实，只在 macOS 上做，读不到任何一项就当它不是后台服务，按原来的身份显示。

1. **plist 在哪**：只看当前用户的 `~/Library/LaunchAgents/*.plist`（用户主目录取当前账户在系统里登记的主目录）。
   只认直接放在这个目录下的普通文件：不是符号链接、属于当前用户、别人不能写（组和其他人都没有写权限），
   用 `plistlib` 能读出字符串 `Label`。`/Library/LaunchAgents`、`/Library/LaunchDaemons`、`/System/...`、
   别的用户的目录一概不看。
2. **谁在跑**：读一次 `launchctl print gui/<uid>`，取里面"服务列表"那一段的"进程号 → 标签"。只保留第 1 步
   找到的那些标签。
3. **进程归属**：监听端口的进程本身，或者它往上最多 8 层的父进程，进程号等于某个标签的进程号，就认定这个
   端口属于这个后台服务。这样后台服务先起一个 shell、再由 shell 拉起 Python 的情况也认得出来。
4. **身份**：`launchd:<标签>`。标签只允许字母、数字和 `._@-`，最长 128 个字符，例如
   `launchd:homebrew.mxcl.postgresql@16`。同一个后台服务开了几个端口，合成一项。

认出来以后，命令行、plist 内容、plist 路径和程序路径**只在本机用于判断**，不进入工具输出、不给模型、
不发给别的电脑。

### 2. 地图上怎么显示

- 服务行写"后台服务 <标签>"，图标和普通程序一样。分档**沿用现有规则**（看程序从哪来：用户目录、Homebrew
  装的程序直接显示；装在 `.app` 包里或 `~/Library` 里的归桌面应用，不显示），主人可以照常标"是我的服务"。
- 见过它正常运行、并且它是直接显示或标过"是我的服务"时，本机记一条**后台服务记录**：标签、当时监听的
  端口、当时是否按规则直接显示、记下的时间。记录和 Python 脚本的启动记录放在一起，只在本机数据库里；
  plist 的位置和内容不记，每次生成计划和执行前都现读。
- 后台服务退出以后，凭这条记录在地图上显示"已停止"，端口照记录显示；巡检据此判定"后台服务已退出"。
- 别的电脑看到的清单里，这一项的 `kind` 仍是 `program`（旧版本照常能读），多一个可选字段
  `launch_agent: true`，新版本据此显示"后台服务"。

### 3. 资格检查（生成计划时做一遍，执行前再做一遍）

| 检查 | 不满足时 Agent 怎么说 |
|---|---|
| 这台电脑是 macOS，TunnelMinion 不是以 root 运行 | "只有 macOS 上才有这种修法" / "TunnelMinion 以管理员身份运行时不修后台服务" |
| 身份是 `launchd:<标签>`，修法是"重新启动后台服务" | "这种修法不适用于这个服务" |
| 没被标成"隐藏"；标过"是我的服务"，或者后台服务记录里写着按规则直接显示 | 同现有两种修法 |
| 标签不在保护名单里：`com.apple.`、`com.openssh.`、`org.cups.`、`org.openbsd.`、`org.ntp.`、`org.postfix.`、Docker 和 OrbStack（`com.docker.`、`com.orbstack.`、`dev.orbstack.`）、组网（`com.wireguard.`、`com.tailscale.`、`io.tailscale.`、`com.zerotier.`），以及任何含 `tunnelminion` 的标签 | "这是系统 / 组网 / Docker / TunnelMinion 自己的后台服务，Agent 不会动它" |
| 第 1 条的 plist 检查都通过，`Label` 和身份一致 | "找不到它在你用户目录里的配置" / "它的配置文件别人也能改，Agent 不会动它" |
| plist 里要运行的程序（`Program` 或 `ProgramArguments` 的第一项）不在 `.app` 包里 | "这是某个应用自带的后台服务，Agent 不会动它" |
| 它已经加载在当前用户的 `gui/<uid>` 域里，并且 launchd 记的配置文件就是这个 plist | "这个后台服务已经被卸载了（例如用 `brew services stop` 停掉的），Agent 不会替你重新加载" |
| 它现在没在运行 | "它还在运行。第一版只重新启动已经退出的后台服务" |
| 后台服务记录里的端口没被别的程序占着 | "原来的端口 N 现在被 X 占了"，不去停别人 |
| 有后台服务记录 | "我还没见过它正常运行，不知道修好以后该检查哪些端口" |

计划里记下：标签、`uid`、plist 位置、plist 内容的 SHA-256、要验证的端口。批准框里的五件事：

- **要做什么**："重新启动后台服务 homebrew.mxcl.postgresql@16（端口 5432）"
- **会有什么影响**："由 macOS 按它自己的配置重新启动，和你在终端里运行 `launchctl kickstart` 一样；不改配置文件。"
- **怎么确认修好**："启动后我会确认它在运行、端口 5432 在听，有网页的再打开一次首页。"
- **没修好怎么办**："没修好我会停下来，告诉你卡在哪；后台服务归 macOS 管，我不会再动它，也不会反复重启。"

### 4. 执行：`launchctl kickstart gui/<uid>/<标签>`，不加 `-k`

命令完全由本机代码拼出：`launchctl` 固定用 `/bin/launchctl`，域固定是 `gui/<当前 uid>`，标签来自计划并再
校验一遍格式。模型的任何文字都不进入命令。

**为什么不加 `-k`**：`-k` 的意思是"如果正在运行，先杀掉再启动"。这种修法只修已经退出的后台服务，执行前
核对也要求它没在运行，所以 `-k` 帮不上忙；反而在"核对完、动手前"这一两秒里，launchd 按 `KeepAlive` 自己
把它拉起来时，`-k` 会把刚起来的进程杀掉。不加 `-k` 时，服务已经在跑就什么都不做，后面的验证照样通过。

**为什么不用别的办法**：

- 不用 `launchctl bootstrap` / `load`：那等于重新加载主人可能有意卸载的服务，第 3 条已经拒绝这种情况。
- 不用 `launchctl start`：旧接口，在 `gui` 域上的行为不如 `kickstart` 明确，失败时也不给可靠的退出码。
- 不改 plist、不 `enable`/`disable`、不 `bootout`，不用 `sudo`。

**执行前核对**（批准后、动手前）：重新走一遍第 3 条的全部检查，并且确认 plist 内容的 SHA-256 和计划里一样、
launchd 记的配置文件位置没变。任何一项变了就不动手，告诉用户"情况变了，让 Agent 重新看一下"。

### 5. 修后验证

最多等 30 秒，每秒看一次：

| 检查项 | 怎么判断 |
|---|---|
| 后台服务在运行 | `launchctl print gui/<uid>/<标签>` 里有进程号 |
| 端口在听 | 记录里的每个端口在本机能连上 |
| 首页能打开 | 端口说 HTTP 的，本机读首页状态码，小于 500 算通过；不说 HTTP 的只确认端口 |

没修好时：不再动它，状态记为"已回到动手前的样子（没有需要撤销的）"；如果 plist 里配了
`StandardErrorPath` 或 `StandardOutPath`，并且那是当前用户自己的普通文件，读最后 40 行、去掉密码和令牌，
作为日志要点附上；同时附上 launchd 记的"上次退出码"。

### 6. 风险等级和批准

- 登记为 L2（工具名 `repair_restart_launch_agent`），和现有两种一样：默认要服务所在电脑本机逐次批准，
  10 分钟内有效；信任的电脑可以按"允许替我批准修复"代批准。
- 主人在本机为这个服务打开"挂了可以自动修"后，巡检确认它挂了（新原因"后台服务已退出"）就代主人批准一次，
  其余步骤一步不少；限次、失败暂停都沿用巡检的规则。
- 同一台电脑同时只修一个，同一个服务 1 小时最多修 3 次，验证失败不自动重试。

### 7. 审计

和现有两种一样，全部留在本机修复记录里：谁提出的、谁批准的（`patrol` 时写明依据日期）、执行前核对结果、
实际执行的那一条 `launchctl kickstart gui/<uid>/<标签>` 及其退出码、验证结果、收场。给模型和别的电脑的
摘要里只有服务名、修法、状态和结论，没有 plist 路径和程序路径。

## 安全边界

1. **只碰当前登录用户自己的后台服务**：只在 `gui/<当前 uid>` 域里操作，只认 `~/Library/LaunchAgents`
   下属于当前用户、别人改不了的 plist。系统级（`/Library/LaunchDaemons`、`/Library/LaunchAgents`、
   `/System/...`）和别的用户的服务永远不碰；TunnelMinion 以 root 运行时整个修法不可用。
2. **保护名单**：苹果、常见系统组件、Docker / OrbStack、组网工具、TunnelMinion 自己、`.app` 里的应用
   后台服务一律不修，即使被标成"是我的服务"。
3. **不改任何配置**：不改 plist，不加载、卸载、启用、禁用任何服务，不提权。主人有意卸载的服务不会被救回来。
4. **没有"执行任意命令"**：命令只有固定的一条 `launchctl kickstart gui/<uid>/<标签>`。
5. **只修已经退出的**：在跑但卡住的后台服务第一版不修（需要 `-k` 强行杀掉，风险不同，以后单独评估）。
6. **plist 没变才动手**：批准后 plist 内容哪怕改了一个字节也不执行。
7. 其余边界（每次批准、执行前再核对、限次、失败不重试、全程留痕）与 [`agent-fix.md`](agent-fix.md) 一致。

## 不在这个修法范围内

- 系统级 LaunchDaemon、别的用户的 LaunchAgent、`/Library/LaunchAgents` 下由安装包放的全局 Agent。
- 在跑但不响应的后台服务（`kickstart -k`）。
- 重新加载被卸载的服务、修改 plist、调整 `KeepAlive` 等配置。
- Windows 上的服务（归系统服务管理器管，需要管理员权限）。

## 自动测试

全部用假的 `launchctl`、假的 plist 目录、假的进程和假的端口探测，不碰任何真实机器的 launchd：

- **识别**：plist 在用户目录、属于当前用户、标签一致时认得出；符号链接、别人的文件、组或其他人可写、
  读不出 `Label`、放在子目录里的都不认；监听进程本身或父进程是后台服务的进程都能归到它；`launchctl print`
  输出读不懂时退回原来的身份；Windows 上完全不做。
- **身份与地图**：`launchd:<标签>` 能标记；地图显示"后台服务"；退出后凭记录显示"已停止"；别的电脑的清单
  里 `kind` 仍是 `program` 并带 `launch_agent`。
- **资格**：非 macOS、root、隐藏、不是"是我的服务"且规则不显示、保护名单、`.app` 里的程序、plist 不合格、
  没加载（被卸载）、加载的配置文件不是这个 plist、正在运行、端口被别人占、没有记录，全部拒绝并给出正确说明。
- **命令**：执行的就是 `/bin/launchctl kickstart gui/<uid>/<标签>`，不带 `-k`；理由里写了命令也不会进入命令。
- **执行前核对**：plist 内容变了、加载的配置文件位置变了、服务已经自己起来、被卸载了，都不动手。
- **验证**：进程起来、端口在听、首页 200 时通过；`kickstart` 退出码非 0、超时、进程没起来、端口不听、
  首页 5xx 时失败，不重试，附上日志要点和上次退出码；日志文件不是自己的普通文件时不读。
- **接入**：修法注册表里是 L2，模型拿不到执行入口；`propose_repair` 接受新修法；巡检 `repair_kind_for`
  认识新身份，"后台服务已退出"能确认挂了、补提固定修法、自动修；批准框文案和地图开关认识新修法。
- **前端**：服务行"后台服务"标签、批准框文案、"挂了可以自动修"开关的说明文字。

## 真机验收步骤

由协调会话在 Mac mini 上做，用一个临时安装的测试 LaunchAgent，测完卸载。用全新的数据目录，网页只绑
本机环回地址。下面的 `<端口>` 选一个空闲的高端口，标签用 `local.repair-test.web`（不含 `tunnelminion`，
否则会被保护名单拒绝）。

> 注意：测试服务要用 Homebrew 或 uv 装的 Python（例如 `/opt/homebrew/bin/python3`）。系统自带的
> `/usr/bin/python3` 实际运行在 `.app` 包里，会被现有分档规则归为桌面应用而不显示在地图上。

1. **安装测试服务**：在临时目录建 `index.html`，写 `~/Library/LaunchAgents/local.repair-test.web.plist`：
   `ProgramArguments` 为 `[<python 路径>, -m, http.server, <端口>, --bind, 127.0.0.1]`，`WorkingDirectory`
   为临时目录，`RunAtLoad` 为 true，`KeepAlive` 为 false，`StandardErrorPath` 指向临时目录里的日志文件。
   运行 `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.repair-test.web.plist`。
2. **认出来**：地图上出现"后台服务 local.repair-test.web"，直接显示，端口正确。等巡检至少跑完一轮。
3. **人工批准修复**：`launchctl kill TERM gui/$(id -u)/local.repair-test.web` 让它退出（`KeepAlive` 为 false，
   不会自己回来）。约 1～1.5 分钟后地图标红"挂了 · 后台服务已退出"，Agent 提出"重新启动后台服务"，
   头上冒感叹号。点批准，结果"修好了：后台服务在运行，端口在听，首页能打开（HTTP 200）"。修复记录里执行的
   命令是 `launchctl kickstart gui/<uid>/local.repair-test.web`。
4. **预先允许的自动修**：在服务框里为它打开"挂了可以自动修"，再让它退出一次。不点任何东西，几分钟内自动
   修好；批准人是 `patrol`，依据写着打开开关的日期。
5. **反面：有意卸载**：运行 `launchctl bootout gui/$(id -u)/local.repair-test.web`。对它要求修复，Agent 拒绝，
   说明"已经被卸载，Agent 不会替你重新加载"；巡检也不会自动重新加载它。
6. **反面：系统服务**：问 Agent "把 com.apple 开头的某个后台服务重启一下"，Agent 拒绝。
7. **收尾**：`launchctl bootout gui/$(id -u)/local.repair-test.web`（如果还加载着），删除 plist、临时目录和
   验收数据目录，确认 `launchctl print gui/$(id -u)/local.repair-test.web` 已找不到这个服务。

## 拆分

一个实现 PR（分支 `feature/launchagent-repair`）：

1. macOS 后台服务识别、`launchd:` 身份、后台服务记录、地图"后台服务"和"已停止"。
2. 新修法：资格检查、计划、执行前核对、`launchctl kickstart`、验证、日志要点；登记为 L2。
3. 接入：`propose_repair`、巡检 `repair_kind_for` 和"后台服务已退出"、批准框文案、地图开关；OpenAPI 基线。
4. 前端：服务行标签、批准框、开关说明。
