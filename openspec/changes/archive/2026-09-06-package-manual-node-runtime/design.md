## Context

### 2026-09-06 现场重定基线

`main` 已包含 runtime profile、预检、进程所有权、`start/status/stop`、版本 stage/activate/remove、
PyInstaller 双平台构建和配套单元测试。本阶段不重写这些能力。

对成功 CI run `33977734625` 的 Windows 正式 artifact 做无源码实测时发现：归档只有 `package/`，
外部证据 artifact 才有 `manifest.json`。直接执行公开用户流程时，`configure` 成功而 `start` 以
`package_invalid` 失败；把证据清单逐字节复制为包根的 `runtime-package-manifest.json` 后，同一个包
可以启动、返回 React 页面、停止，也可以完成 stage/activate/status/remove 并保留数据。

现有验收没有暴露问题，因为它在临时目录补入清单并直接运行内部 `runtime-child`。这说明缺口位于
交付和验收边界，不是 runtime 内核缺失。

## Goals / Non-Goals

**Goals:**

- 交付下载后即可运行的 Windows amd64 与 macOS arm64 当前用户包。
- 让归档内安装清单与外部构建证据一致，并保持严格完整性校验。
- 用公开 CLI 从实际归档验证配置、常驻启动、状态、停止、Gateway 和版本切换。
- 保持程序、数据、秘密分离，模型不可用只作为警告。
- 给用户一条不依赖 Python、uv 或源码的最短操作路径。

**Non-Goals:**

- 不重写现有 runtime/installer，也不新增抽象、依赖或安装器框架。
- 不创建 Windows Service、Scheduled Task、macOS LaunchAgent/Daemon 或开机自启。
- 不管理模型进程，不扩展 Provider、relay、自动组网、WireGuard、防火墙、路由或 DNS。
- 不接管生产 A/B，不触碰现有 8080/8787 进程；生产采用需用户另行明确授权。

## Decisions

### 1. 修交付边界，不重做运行时

现有 runtime 与安装仓储已经覆盖进程所有权、幂等启动、安全停止和保留数据移除。本阶段只修阻断
用户下载使用的根因，并把已有能力接入真实 artifact 验收。历史任务按现场代码和可运行测试重新
记账，不复制实现。

### 2. 清单既随包交付，也作为外部证据保存

CI 暂存时把同一份构建清单复制到：

- `package/runtime-package-manifest.json`，供下载后的启动预检使用；
- `manifest.json`，供 CI 汇总和审计使用。

清单本身是安装元数据，不参与自身哈希，避免递归摘要。闭合文件校验只允许这一个额外文件，并且
当校验使用外部清单时，包内副本必须与其逐字节一致；任意其他额外文件或不一致清单继续失败。

### 3. 验收只能走用户公开入口

CI 先封装上传用 tar，再把该 tar 解压到无关临时目录。验收隐藏开发解释器、Node、`PYTHONPATH`、
虚拟环境和外部 HTTP，使用临时数据目录及动态高端口，只调用包内可执行文件的公开命令：

1. `runtime configure` 配置本地应用和可选 Gateway；
2. `runtime start` 后控制命令退出，随后 `runtime status` 和 HTTP 探测证明进程仍在；
3. 再次 `runtime start` 证明幂等；
4. `runtime stop` 并确认端口和进程释放；
5. `runtime-package stage/activate/status/remove` 证明程序可替换且数据/秘密默认保留。

Gateway 配置也只通过包内公开 `gateway-configure` 写入临时目录，使用临时私网地址、高端口和
`restricted-file` 测试秘密；测试结束必须停止自有进程并删除临时目录。内部 `runtime-child` 仍是
runtime 的实现细节，不可作为交付验收入口。

### 4. 双平台同提交、同门禁

Windows amd64 与 macOS arm64 各自产生正式归档和脱敏验收 JSON，矩阵汇总必须确认源码修订、锁文件、
前端摘要、清单摘要和验收结果一致。某一平台未从实际归档走通公开流程时，阶段失败，不用源码模式
或手工补文件降级为成功。

### 5. 生产采用不是本阶段门禁

本阶段证明运行包机制在两个受支持平台的隔离当前用户环境可用。对真实 A/B 替换启动方式会改变
生产进程，超出当前授权，也不是修复 artifact 根因所必需；它只在用户明确授权、先保存只读基线并
给出回滚窗口后执行。

## Risks / Trade-offs

- [包内清单成为未覆盖额外文件] → 只豁免固定文件名且要求与外部证据逐字节一致。
- [验收再次绕开用户入口] → CI 对实际 tar 解包后只调用公开命令，并在证据中记录各步骤退出码。
- [Gateway 验收误碰真实服务] → 只使用临时目录、动态高端口和测试秘密，禁止 8080/8787。
- [后台进程残留] → `finally` 始终调用公开 stop；失败时仅终止可证明由测试启动的进程。
- [范围膨胀成安装器] → 首版仍是手动解包与 CLI；签名、公证、GUI 和自动更新另行评估。

## Migration Plan

1. 嵌入清单并增加闭合校验回归测试。
2. 把干净验收切换为实际归档和公开 CLI 生命周期。
3. 更新下载包使用说明，运行定向与全量质量门禁。
4. 由同一提交生成 Windows/macOS artifact，独立只读审计通过后以一个 PR squash 合并。
5. 合并后同步主规格并归档 change；生产采用等待用户单独授权。

## Open Questions

无。本阶段不需要新的产品或网络决策。
