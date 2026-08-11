# Memories / Settings 人工视觉验收收据

## 收据范围

- 验收项：OpenSpec `improve-local-product-experience` 的 6.5；本收据是独立验收证据，不修改或勾选 OpenSpec `tasks.md`。
- 权威源码基线：`feature/local-product-experience@d5eee8a4628214fa3ce1a58c937f69b7dc741e0e`。
- 验收分支：`test/memories-settings-manual-acceptance`。
- 运行模式：源码 FastAPI + `build/frontend-dist` staged production frontend，仅绑定 loopback `127.0.0.1:4174`。
- 数据：每个平台都使用 clean-first 隔离临时目录和合成 scope fixture（`acceptance-user/home`、`acceptance-user/lab`）；fixture 报告无秘密。未读取真实用户数据目录、Keychain、Credential Manager、模型或 Gateway。
- 视觉复核：下列 28 张 PNG 均由验收者逐张实际打开查看；自动化结果仅用于定位、导航、状态和哈希复核，不替代人工观察。

## 平台、浏览器和命令

| 平台 | 浏览器 | 视口 | 脱敏命令记录 |
| --- | --- | --- | --- |
| Windows | Chromium `151.0.7922.34` | `1280x720`、`320x720`、`640x360` | `npm ci`; `npm run build`; `python scripts/prepare_frontend_dist.py --skip-install`; `python build/<temporary-source-server>.py`; `node build/<temporary-playwright-capture>.mjs`; `uv run --group package pytest --no-cov` |
| macOS B | WebKit `26.5`（Playwright；不是 Safari GUI） | `1280x720`、`320x720`、`640x360` | `ssh <configured-macOS-B> 'python3.12 --target build/<temporary-target> -m pip ...'`; `python -m playwright install webkit`; `python build/<temporary-source-server>.py`; `python build/<temporary-playwright-capture>.py` |

一次性 server/capture 文件只放在 `build/`，验收后已删除；远端 checkout、构建临时目录、loopback 服务、截图和临时数据也已删除。所有命令中的用户目录、主机名、远端路径和凭据均已脱敏。

macOS 的一次性环境准备中，`python3.12 -m venv` 只尝试一次并以 `ensurepip` 非零退出；未重复扩大权限，随后在同一隔离 build 目录使用 `pip --target` 完成依赖安装。该连接随后成功完成 WebKit 验收，服务使用精确 PID 停止并确认端口已释放。

## 人工观察和结果

### Windows / Chromium

**结果：本轮 Windows 视觉范围通过。**

- Memories 正常态显示合成 scope、source、时间和稳定事实；切换 `home` / `lab` 后 scope 隔离可见，另一 scope 的内容不显示。
- 修正流程展示明确的 revise dialog、对象和 scope，确认后显示更新结果。
- 单条删除先确认再变为空态；精确清空 dialog 明确写出目标 scope，并说明其他 scope 和 chat 不会被删除；确认后显示 `204` 成功状态和精确 scope 已空状态。
- Memories 读取错误显示可读的红色 alert 和 `memory_store_unavailable`，保留重试路径；空态和错误态都没有把错误当成成功。
- Settings 无模型配置时显示降级状态：AI run 暂不可用，但 Memories 和确定性资源仍可管理。模拟模型配置错误显示红色 alert 和 `model_configuration_unavailable`。
- Diagnostics 页面显示 runtime/source/platform、Coordinator 和配置状态、脱敏说明及恢复步骤；JSON export 返回 HTTP 200，`containsForbiddenTokenPattern=false`、`containsFullChatMarker=false`，无浏览器 storage 数据。
- Chromium dialog 焦点序列为 `Cancel -> Confirm revise -> Cancel`（Tab wrap），反向 Tab 回到 `Confirm revise`；可见焦点、dialog role、`aria-modal`、label/description 和 status/alert 语义均可定位。
- `320x720` 无水平溢出；`640x360` 作为 200% 等效 CSS 视口无水平溢出。这里是等效 CSS viewport 验证，不声称真实显示器 DPI 缩放验收。

### macOS B / WebKit

**结果：视觉内容和数据状态通过；完整 macOS 6.5 保持未完成。**

- Memories 的正常、scope 隔离、修正、单条删除、精确 scope 清空、空态和错误态均可见且与 Windows 语义一致。
- Settings 的无模型降级、模型配置错误和诊断脱敏/恢复说明均可见；JSON export HTTP 200，`containsForbiddenTokenPattern=false`、`containsFullChatMarker=false`，无浏览器 storage 数据。
- `320x720` 和 `640x360` 等效 CSS viewport 均无水平溢出；scope、source、时间、红色错误提示和确认文字在截图中可读。
- WebKit dialog 语义属性可定位（`role=dialog`、`aria-modal=true`、`aria-labelledby`/`aria-describedby`）；clear 后 status 区域可定位。
- **未通过的真实缺口：** WebKit 自动化焦点序列为初始 `BUTTON Cancel -> BODY -> INPUT -> BODY`，没有证明 dialog 焦点 trap。该结果按失败记录，未修改产品代码，也未声称 macOS 键盘验收通过。

### Safari / 屏幕阅读器边界

未安全执行真实 Safari GUI，也未启动真实屏幕阅读器。当前证据是 macOS WebKit 引擎截图和浏览器 accessibility/ARIA 树观察；因此不能把它表述为真实 Safari 或 VoiceOver/Narrator 的人工通过。后续需在允许的真实 macOS UI 环境中亲手确认 Safari 键盘焦点与屏幕阅读器朗读顺序。

## 截图 SHA-256

### Windows / Chromium

| 文件 | SHA-256 |
| --- | --- |
| `windows-memories-home.png` | `d9eeeba58c6de74ce466e5769b11f0aa18a8531a30398c49ab2d8493022119d1` |
| `windows-memories-lab.png` | `ebfcd1d554565e73cef86a6713f36bcf6ae5f1abf5842d2d8afa2387642b4dfc` |
| `windows-memories-revise-dialog.png` | `3694b69f1b9bf1936987793afdf4a647efb69101cca1e5ce450a098f7de5723b` |
| `windows-memories-home-revised.png` | `40ba520a6bfac68e53d2ba2191bb78bdf8cdba0222b1643075d7db86530e8322` |
| `windows-memories-delete-dialog.png` | `afc877f098d89a45370557f6506dac6727a0f8e2b1bc172d4502f3cf343146ed` |
| `windows-memories-lab-empty.png` | `2ea196659ab4fee98ee6a1cfb2304b9d3337ce3d361f69b1337b9354334bfcb3` |
| `windows-memories-clear-dialog.png` | `401a322b13e89bf9c54f784c15e8b4e7ec948cc06847c855fa6f0115aa36b1fa` |
| `windows-memories-home-empty.png` | `902db46229ea7fd63d148339832ed5c0f33801db608b0f01f5eb532808c10037` |
| `windows-memories-error.png` | `e67cf00cc30ed184f5985e8b0a2edac44678a035aa6e9a0fe6d3cb08c1670324` |
| `windows-settings-unconfigured.png` | `f397027d885d31681603294e290a8ec1548f632d9804547763533b744550b8ce` |
| `windows-settings-error.png` | `8a068b88f0dd22b4f486af89df6354f736e7c61c793db14e857355345225435f` |
| `windows-settings-320.png` | `6bc06e842c97e483cfd7775643a176a54f8d325344b1d9635d9336496e73e5eb` |
| `windows-memories-200pct-equivalent.png` | `af141b734a718ba0c9073af1f1bc3b1c07c87fe14cd27e6bf1aca68f3e135d16` |
| `windows-settings-diagnostics.png` | `bf3e888ae7656be4a59ad7e352e95b17d542c4229fa2c8ef2a9ffe7f02571ce7` |

### macOS B / WebKit

| 文件 | SHA-256 |
| --- | --- |
| `macos-memories-home.png` | `8f3061617a085a54b5f6344323b5d654f4af834824e40c75bb5ae2686c0f3097` |
| `macos-memories-lab.png` | `f7419b1ec6ea364ab5c0648a1695f4a8d7708f1b57d5ea215f90ad0026c728ad` |
| `macos-memories-revise-dialog.png` | `8ddac204ecad0569db10c3216e62d316f0919075eeb9f931e4a25a50d4ed7ac9` |
| `macos-memories-home-revised.png` | `b5c79e70bac634797cac4e1e6f4e0006672ddd78ed57717ed0728db42f177a31` |
| `macos-memories-delete-dialog.png` | `4fb5dfc6206c6515f0be57ece72541c8b8e5b2f6d8705c3334b04f2d9b0cde4e` |
| `macos-memories-lab-empty.png` | `0b76e0b8dec7900467d5069cafcab641d36aff72760382016fb687b841a9ea36` |
| `macos-memories-clear-dialog.png` | `67ab4eaf9bb9a6dc06bcae37e12dc78f5ae938ce8f83cc2cbf2c9bea7291515c` |
| `macos-memories-home-empty.png` | `9de8df26a996e377167c1ab96c1354b21d3630eb66bc6fab8fe819feaeee66cd` |
| `macos-memories-error.png` | `9bc6ae0212936479561a63a820a637be8f5043504e7b2e931d4a26c2d419951d` |
| `macos-settings-unconfigured.png` | `e94a2304980bf11997991e245f2d31b571d461c9c311e4dfc6408fc021ffc0ae` |
| `macos-settings-diagnostics.png` | `7adc9165492d1279436f83a61a56fdc67e44dd344b2a2717ca32e26b89460b92` |
| `macos-settings-error.png` | `bbfc855f2af839e10a93157f855074322937fe31d9f959d89a4135825000a76d` |
| `macos-settings-320.png` | `a561496da9b95c1a3214c936001e58a4088e04a15e8dfd153e671df6e4d92f54` |
| `macos-memories-200pct-equivalent.png` | `3a8ddfb11db3adac39bc4a10a036566c0260048220efc0c5f57103ce6bef324a` |

## 自动化收据和完整性

- Windows 详细收据：[windows-automation.json](windows/windows-automation.json)；诊断截图收据：[windows-settings-diagnostics.json](windows/windows-settings-diagnostics.json)。
- macOS 详细收据：[macos-automation.json](macos/macos-automation.json)。
- 重新计算并核对授权目录内全部 PNG：Windows 14、macOS 14，共 28 张，全部 SHA-256 匹配；Windows automation JSON 的 13 项另加独立诊断截图收据 1 项。
- 仅扫描本授权证据目录中的文本/JSON：0 个秘密模式发现；未进行全仓库秘密扫描，未读取、列出或接触 `docs/questions/`。
- 截图不含真实秘密、令牌、主机用户名或绝对路径；fixture 中的 scope/node 值是合成验收数据。

## 质量门禁

| 门禁 | 结果 |
| --- | --- |
| `npm run format:check` | 通过 |
| `npm run typecheck` | 通过 |
| `npm test -- --runInBand` | 通过，14 files / 85 tests |
| `npm run test:supply-chain` | 通过，5/5 |
| `npm run size:check` | 通过，initial JS+CSS gzip `141.67 KiB / 300.00 KiB` |
| `uv run --project . ruff format --check src tests scripts spikes` | 通过，316 files |
| `uv run --project . ruff check src tests scripts spikes` | 通过 |
| `uv run --project . pyright` | 通过，0 errors / 0 warnings |
| 证据相关 pytest | 通过，23 passed / 1 skipped |
| 首次完整 Python pytest | 3 个测试因 `.venv` 缺少现有 package 组的 PyInstaller metadata 失败 |
| 补齐锁定 `PyInstaller 6.21.0` 后完整 Python pytest | 通过，1036 passed / 6 skipped / 1 warning |

首次完整运行的 3 个失败均为 `tests/evaluation/test_runtime_package_build.py` 在 `importlib.metadata.version("pyinstaller")` 处找不到发行版；没有修改产品代码。使用已有 `package` dependency group 补齐环境后，针对测试先得到 6 passed，再完整套件重跑通过。警告是现有 FastAPI/Starlette TestClient 关于 httpx 的弃用提示。

官方 `npm run test:e2e` 默认 server 会触及真实 platform KeyringSecretStore；本轮没有运行该默认路径，而是复用同一 FastAPI-backed Playwright harness，在进程内注入不访问真实密钥的空配置 store，并分别在 Windows Chromium、macOS WebKit 上完成上述源服务 + staged frontend 验收。该边界已在本收据中明确，不把它表述为正式打包应用或真实 Safari 通过。

## 最终结论和待确认项

- Windows：本轮 Memories/Settings 人工视觉与可复核 harness 证据通过。
- macOS：正常/空/错误/无模型、scope 操作、诊断脱敏和窄视口视觉证据通过；WebKit 键盘焦点 trap 未通过，故 macOS 6.5 整体保持未完成。
- 待用户在真实 macOS UI 上亲手确认：Safari GUI 键盘焦点 trap、VoiceOver/真实屏幕阅读器状态与朗读顺序，以及修正 WebKit 观察到的 `BODY/INPUT` 焦点逃逸。
- 本验收未调用任何模型、未使用用户提供的 API key、未启动或接触已关闭的模型进程，未修改产品代码、CI、公共配置或任何 OpenSpec artifact。
