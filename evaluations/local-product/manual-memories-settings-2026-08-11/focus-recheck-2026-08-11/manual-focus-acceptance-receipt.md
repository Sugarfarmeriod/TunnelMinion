# Memories/Settings 6.5 焦点与人工视觉复验收据

收据 schema：`manual-memories-settings-focus-acceptance/v1`

验收基线为 `origin/feature/local-product-experience` 的精确提交
`b8b9766e6f5f1c2ba00a733735ed63c3eb8e2da6`。本轮分支为
`test/memories-settings-focus-acceptance`，只写入本目录证据；没有修改产品代码、测试、CI、锁文件、OpenSpec artifact 或 `docs/questions/`。

## 结论

Windows Chromium 与 macOS B WebKit 26.5 均通过正式离线包验收。Memories 的修正、精确作用域清空、删除，以及 Settings 保存确认框都完成了初始焦点、正向 Tab、反向 Shift+Tab、Escape 关闭和关闭后恢复触发按钮的复验；焦点状态全程位于 dialog 内，未落到 `BODY`/`HTML` 或背景。

真实 Safari GUI、VoiceOver/其他人工屏幕阅读器没有执行；本收据只声称 Chromium/WebKit 浏览器自动化、ARIA 角色/标签和实际截图证据。

## 精确运行与包收据

两平台使用同一源 revision、同一 staged frontend digest 和各平台本机 PyInstaller 正式包。fixture 每次从全新的独立父目录调用既有 `prepare_local_product_package_fixture.py` 生成；正式包启动和 E2E 会改变 SQLite 状态，因此没有复用旧 fixture/data/receipt。

| 平台 | 浏览器 | 包 ID | manifest SHA256 | frontend SHA256 | clean acceptance |
| --- | --- | --- | --- | --- | --- |
| Windows | Chromium 151.0.7922.34 | `tunnelminion-0-1-0-win32-amd64-51feef70609e-9a8a05a5d56d` | `169f8c59e53cf9023f5037daa30b4dcc355f4566dd1ef050685b3f4f7ea76001` | `9a8a05a5d56d54e0ed64cda16a51d4cc81526d67a766e8d46a5423d961c06b22` | health/app 200，passed |
| macOS B | WebKit 26.5 | `tunnelminion-0-1-0-darwin-arm64-51feef70609e-9a8a05a5d56d` | `de5a6229c1c5ab8c9ced4f2a9c9ccca57acc3046cef65c3a3a3cf52c34eeada8` | `9a8a05a5d56d54e0ed64cda16a51d4cc81526d67a766e8d46a5423d961c06b22` | health/app 200，passed |

- Windows 包：213 files，63,786,371 bytes，Python 3.11.15，289 licenses，unknown license 0。
- macOS B 包：143 files，60,166,956 bytes，Python 3.12.11，284 licenses，unknown license 0。
- 两平台 manifest schema 均为 `runtime-package-manifest/v2`；clean acceptance 均报告 `node_available=false`、`source_environment_present=false`、外部 HTTP 代理已阻断、无 `program_data_entries`/`source_entries`。
- 两平台 fixture receipt 均为 `contains_secrets=false`，只包含合成 `node-id` 与 `runtime.sqlite3` closed set。

完整机器收据：

- [Windows automation JSON](windows/chromium-focus-automation.json)
- [Windows package summary](windows/runtime-package-summary.json)
- [Windows clean acceptance](windows/runtime-package-clean-acceptance.json)
- [macOS B automation JSON](macos/webkit-focus-automation.json)
- [macOS B package summary](macos/runtime-package-summary.json)
- [macOS B clean acceptance](macos/runtime-package-clean-acceptance.json)

## 焦点矩阵结果

以下四个矩阵在两个浏览器都得到相同结果：初始焦点是 `取消` 按钮；Tab 到确认按钮，再 Tab 环回取消；Shift+Tab 到确认按钮，再 Shift+Tab 环回取消；Escape 关闭；`restored.sameElement=true` 且恢复元素为 `BUTTON`。每个状态 `insideDialog=true`、`isBodyOrHtml=false`。

| dialog | 初始 | 正向 Tab | 反向 Shift+Tab | Escape/恢复 |
| --- | --- | --- | --- | --- |
| 修正 | 取消 | 确认修正一次 → 取消 | 取消 → 确认修正一次 → 取消 | 关闭并回到检查并确认修正 |
| 精确清空 | 取消 | 确认清空一次 → 取消 | 取消 → 确认清空一次 → 取消 | 关闭并回到清空这个精确作用域 |
| 删除 | 取消 | 确认删除一次 → 取消 | 取消 → 确认删除一次 → 取消 | 关闭并回到删除这条记忆 |
| Settings 保存 | 取消 | 确认保存一次 → 取消 | 取消 → 确认保存一次 → 取消 | 关闭并回到检查并确认保存 |

每个平台的 JSON 都保存了五个焦点阶段的 active element 文本、dialog 内状态和恢复结果；自动化只输出 API status/稳定错误码，不输出诊断正文或响应正文。

## Windows Chromium 截图人工观察

以下结论来自逐张实际打开并查看 PNG；自动化 JSON 只用于复核尺寸、哈希和焦点状态，未把自动断言冒充人工视觉验收。

| 文件 | SHA256 | 人工观察 |
| --- | --- | --- |
| `chromium-focus-memories-home.png` | `37a2267af0404b2fdcc7d4988eade2239aaffe65476d48c3ab5e5d5608f04ce1` | 作用域表单显示 `acceptance-user/home` 和合成节点 ID；卡片显示“总览优先显示家庭网络中的本机服务”，家庭作用域文字清晰，布局无明显横向截断。 |
| `chromium-focus-memories-lab.png` | `6102c54249b6a6a7de45b1134f72a1fb90968c85942ed5f821dce7e4f2805dd7` | 作用域切换为 `lab`；卡片显示“实验网络只允许只读诊断”，未看到 home 卡片内容，作用域文字和安全约束清楚。 |
| `chromium-focus-memories-revise-dialog.png` | `7b2890943620cea584087da03d09fdd1c78daa18e26ff04c94919b9af59b900c` | 深色 backdrop 和居中白色确认框可辨；原作用域、修正后内容/来源、取消与确认修正一次均完整可见。 |
| `chromium-focus-memories-clear-dialog.png` | `d562d4105f9b20e0bda66e6501d55d7f3fdb1a49ec3a369075756c5622833081` | 清空确认框明确展示 `lab` 精确作用域，并写明其他作用域和聊天线程不会被删除；按钮层次清楚。 |
| `chromium-focus-memories-delete-dialog.png` | `77e9eabc873aaa6b6ee4d21c6810edd16828e8ebf5a4f4945fb858a17d5348a3` | 删除确认框展示已修正的 home 内容和完整作用域，取消/确认删除一次清楚，没有秘密或绝对路径。 |
| `chromium-focus-settings-unconfigured.png` | `a69e4f36ad6d65791e13772bb06224093ca852a540408f43b0f5c7cb69eb67ab` | Settings 显示“尚未配置”、无模型时聊天不可用但长期记忆/确定性资源可管理的降级说明；没有显示 API key 值。 |
| `chromium-focus-settings-save-dialog.png` | `ff5f23e87d928245c86480a7984b03765ba7baa365192510141792451bfe5f65` | 保存确认框显示 loopback endpoint、模型名、30 秒超时和“保留当前已保存的密钥”，未显示秘密正文；背景 Runtime/Coordinator 状态仍清楚。 |
| `chromium-focus-settings-320.png` | `18860a6c3bc8a9d4e4e0ca79f334cd305a53245ad98f22680af2c969b78b20f9` | 320 CSS px 下导航换行、状态卡和文字仍落在视口内；未见横向滚动阻断。 |
| `chromium-focus-memories-200pct-equivalent.png` | `08867e6498925735ee5a816f4de149da2b2dcc01cf4a184672d9fa4857dfb824` | 640×360 的 200%-equivalent Memories 视图中表单字段、home 作用域和操作入口保持可读；未见横向阻断。 |

## macOS B WebKit 截图人工观察

以下 9 张 PNG 也已逐张实际打开查看。WebKit 画面保留同样的作用域、确认框、无模型降级和窄视口行为；没有把 WebKit 结论扩展成真实 Safari GUI 结论。

| 文件 | SHA256 | 人工观察 |
| --- | --- | --- |
| `webkit-focus-memories-home.png` | `7e0dda18288ce0d59381a11934db8295f00e86dae4d2998c135f478f6dc66532` | home 作用域、合成节点 ID、家庭本机服务记忆和“已由用户确认”状态清楚，卡片布局完整。 |
| `webkit-focus-memories-lab.png` | `0ff6d28f2a9ef4cc4a4c05186acb4fbdad0e8264f9c49c05c3449c085b91eda9` | lab 作用域和“实验网络只允许只读诊断”清楚，home 内容未显示，作用域隔离可见。 |
| `webkit-focus-memories-revise-dialog.png` | `d7ad360a2b455f42d628f12979a93ae2a982bf02b14ad5b1363513f43caa4bc1` | 修正确认框居中、backdrop 清楚，原作用域、修正内容/来源和两个按钮完整可读。 |
| `webkit-focus-memories-clear-dialog.png` | `9c4f573775886096b72ab164841b0e365e4aae41bca2f6035777819dc041764c` | 清空框明确标出 lab 作用域及不会误删其他作用域/聊天线程，红色确认动作与取消动作清楚。 |
| `webkit-focus-memories-delete-dialog.png` | `341802213d40b31ceb9431b892957aebe1d76df3c888e823bad844adfe65f270` | 删除框展示修正后的 home 内容和完整作用域，信息层次与按钮均可辨，无秘密/绝对路径。 |
| `webkit-focus-settings-unconfigured.png` | `e94a2304980bf11997991e245f2d31b571d461c9c311e4dfc6408fc021ffc0ae` | “尚未配置”状态、无模型降级说明和可继续管理长期记忆的文字清楚，未显示 key 内容。 |
| `webkit-focus-settings-save-dialog.png` | `486c4d0e115ab3ed4a01c0b8530428974b2494faf8492b0e7d5bdadbf18ed384` | 保存确认框显示 endpoint、模型、超时和秘密处理说明，未显示秘密正文；macOS runtime 状态可读。 |
| `webkit-focus-settings-320.png` | `a561496da9b95c1a3214c936001e58a4088e04a15e8dfd153e671df6e4d92f54` | 320 CSS px 下导航和设置卡片纵向排列，文字未横向溢出，页面仍可继续滚动阅读。 |
| `webkit-focus-memories-200pct-equivalent.png` | `35082ed9e1bd68c7c2c7254cf03a2e6902ee26f8a2faeea2997e0eb7cd5e80e2` | 640×360 WebKit Memories 视图中 home 作用域和输入/操作区域可读，未见横向阻断。 |

## 脱敏、隔离与空状态

- 两个平台均设置隔离的 null keyring backend；没有读取 Windows Credential Manager、macOS Keychain、真实用户数据目录或模型密钥，没有发起模型调用。
- Settings 只填写 `http://127.0.0.1:8080/v1` 和合成模型名，停留在保存确认框并用 Escape 关闭，没有保存或联系模型服务。
- 诊断 endpoint 返回 200；两个 automation JSON 均记录 `forbidden_pattern_findings=0`、`console_forbidden_pattern_findings=0`。扫描范围仅为本目录 evidence 文件。
- 两平台浏览器 storage 均为 `local=[]`、`session=[]`、`databases=[]`。
- 每个平台先完成 home/lab 作用域隔离，再实际确认 lab 精确清空和 home 记忆删除；确认后对 home 空状态重新读取，automation 等待“这个精确作用域还没有长期记忆”。
- 截图只使用 fixture 的 `acceptance-user`、`home/lab`、合成 node ID、合成 endpoint/model；没有主机用户名、绝对路径、令牌或真实客户数据。
- 限定 evidence 完整性扫描仅覆盖本目录：18 张 PNG 逐一重算 SHA256、10 个 JSON/Markdown 文本文件扫描秘密与绝对路径模式，哈希不匹配 0、秘密/路径 findings 0。

## 失败记录与修复重跑

- Windows 早期自定义运行曾因复用已有正式包父目录而被 `program` closed-set 检查拒绝；后续每次都改用新父目录并重新生成 fixture/data/receipt。
- Windows 早期 harness 曾使用不一致的字段定位/缺少 base URL，导致 API 200 但没有可接受的记忆卡；随后完全复用 `package-product.spec.ts` 的 `getByLabel`、按钮、home→修正→lab 顺序和期望文案，在 `focus-windows-8` 全新 fixture 上通过。
- Windows 完整流程第一次成功走到诊断后，临时脚本错误使用 Fetch 风格的 `headers.get`；改为 Playwright `headers()` 映射后，以新 fixture 重跑通过。
- macOS B 第一次 Python harness 漏注入 axe，第二次被正式前端 CSP 拒绝 inline script；两次都只停止了对应隔离父目录的精确正式包进程。改用 `BrowserContext.add_init_script`，在全新 `focus-macos-4` fixture 上用 WebKit 26.5 重跑并通过。以上均未修改产品代码或公共测试。

## 质量门禁

| 门禁 | 结果 |
| --- | --- |
| `npm run format:check` | passed |
| `npm run typecheck` | passed |
| `npm test` | 15 files / 89 tests passed |
| `npm run test:supply-chain` | 5 passed |
| `npm run size:check` | passed，142.04 KiB gzip，低于 300 KiB budget |
| `uv run --project . ruff format --check src tests scripts spikes` | passed，316 files |
| `uv run --project . ruff check src tests scripts spikes` | passed |
| `uv run --project . pyright` | passed，0 errors/warnings/information |
| 相关 evaluation/package tests | 35 passed / 1 skipped |
| 完整 `uv run --group package pytest --no-cov` | 1036 passed / 6 skipped |
| Windows official `npm run test:e2e:package` | 1 Chromium test passed |
| Windows/macOS formal clean acceptance | 两平台 passed，health/app 200 |
| Windows/macOS focus automation | 两平台各 9 screenshots、4 dialogs、5 axe checks passed |

## 执行命令与未覆盖项

命令中的 `<repo>`、`<isolated-temp>`、`<mac-B-temp>` 是脱敏占位符；实际运行只使用本机 loopback 和 macOS B 的隔离 `/tmp` 父目录。

- Windows：`npm ci`、`npm run build`、`uv run --project . python scripts/prepare_frontend_dist.py --skip-install`，再由 `uv run --group package python scripts/build_runtime_package.py ... --source-revision b8b9766e6f5f1c2ba00a733735ed63c3eb8e2da6` 构建；每次截图前重新运行既有 fixture 准备入口；通过正式 `package-product.spec.ts` 和一次性 Chromium focus harness。
- macOS B：受限源码归档只包含构建所需的 `src/`、`scripts/`、`schemas/`、frontend staged inputs 和锁文件，没有 `docs/questions/`；使用官方 `build_runtime_package.py` 在 Darwin arm64 构建。由于归档不携带 Git object，一次性 shim 仅为显式 source revision 提供该提交的 `git show --format=%ct` 时间值，source tree/package/frontend/lock hashes 仍由正式 builder 计算并记录；shim 不进入包或提交。
- macOS B 使用隔离 `PYTHONPATH`、`PLAYWRIGHT_BROWSERS_PATH=<mac-B-temp>/browsers` 和 Python Playwright 1.62.0 的 WebKit 26.5；没有 Node，因此没有声称运行 macOS Safari。
- 真实 Safari GUI、VoiceOver/屏幕阅读器、系统缩放设置、硬件键盘和客户网络/模型尚未由人工执行；这些是提交前仍需用户亲手确认的项目。
