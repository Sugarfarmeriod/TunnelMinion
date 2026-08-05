## 1. 双平台运行包 spike 与停止门禁

- [x] 1.1 建立最小本地应用/Gateway 启动 fixture、运行包清单 schema 和干净环境验收脚本，禁止读取源码 checkout、开发 `.venv`、`PYTHONPATH` 或全局 site-packages
- [x] 1.2 在 Windows 比较单目录冻结与独立 CPython+锁定 wheel 目录，记录 keyring、原生扩展、启动、体积、错误诊断和离线可重复性
- [x] 1.3 在 macOS 运行同一比较，覆盖 Keychain/受限文件、arm64 原生扩展、终端退出后进程存活和包路径移动
- [x] 1.4 固定首版构建后端、版本/清单/校验规则和许可清单；任一平台无法满足依赖完整性与零环境泄漏时停止后续实现
- [x] 1.5 运行 spike、依赖安全、秘密扫描和干净环境门禁，提交并推送运行包决策阶段

## 2. runtime profile、目录边界与预检

- [x] 2.1 定义版本化 runtime profile，只允许绝对数据目录、启用组件、本地端口和预算等非秘密字段，拒绝 token、refresh、key、未知字段和程序目录内数据目录
- [x] 2.2 实现平台标准 profile/data/log/state 路径解析、原子写入和当前账户权限，保持现有默认数据目录与显式 `--data-dir` 兼容
- [x] 2.3 实现运行包清单/关键导入、profile/config schema、数据目录写入、端口占用和已有实例的只读预检
- [x] 2.4 实现模型 endpoint 有界只读健康检查与脱敏结果，证明模型不可达不阻止确定性组件进入可启动状态
- [x] 2.5 覆盖路径穿越、程序/数据重叠、只读目录、损坏清单、配置缺失、端口冲突和零秘密输出，运行质量门禁后提交并推送 profile/预检阶段

## 3. 进程所有权与手动生命周期内核

- [x] 3.1 定义逐组件进程记录、随机实例 ID、启动时间、版本、数据目录摘要和稳定生命周期/错误模型，使用受限权限与原子替换
- [x] 3.2 实现跨平台 detached 进程适配器和 fake 子进程，证明控制终端退出后健康实例继续运行且不注册任何系统自启动项
- [x] 3.3 实现 `start` 幂等、逐组件稳定窗口验证、部分失败 `degraded` 和非零退出，不自动停止已健康的另一组件
- [x] 3.4 实现 `status` 的 PID/启动时间/可执行文件/组件/实例联合验证，正确区分 running、stopped、failed、stale 和 ownership-conflict
- [x] 3.5 实现 `stop` 正常终止、checkpoint 等待、退出验证和超时 fail-closed，禁止默认强杀身份不明或未安全停止的进程
- [x] 3.6 覆盖 PID 复用、陈旧记录、重复启动、并发 start/stop、启动即崩溃、停止超时和进程身份替换，运行并发/分支覆盖门禁后提交并推送生命周期阶段

## 4. 本地应用、Gateway、状态与日志接线

- [x] 4.1 把现有常规 `tunnelminion` 本地应用接入 runtime 控制，验证只监听环回、managed lifespan 安全启停和未配置 managed node 的兼容行为
- [x] 4.2 把独立 `gateway` 接入 runtime 控制，仅在 profile 启用且 `gateway.json` 有效时启动，保持私网绑定和现有 SecretStore 不变
- [x] 4.3 实现本地应用、Gateway 无 token 鉴权拒绝、外部模型和进程稳定窗口的分层健康检查，禁止为探测读取秘密正文
- [x] 4.4 实现逐组件有界轮转日志、受限状态和脱敏 `status` 输出，覆盖异常、远端不可信正文和完整 endpoint 清洗
- [x] 4.5 覆盖模型离线、Coordinator 离线、Gateway 未配置/端口占用/secret-store 不可用、本地应用健康和两个组件独立恢复矩阵
- [x] 4.6 运行 CLI、应用、Gateway、Web、secret-store、无模型和全量回归门禁，提交并推送组件接线阶段

## 5. 构建、版本切换与保留数据移除

- [x] 5.1 实现由锁定输入生成 Windows/macOS 版本化运行目录、清单、许可清单和可复核构建摘要
- [x] 5.2 实现新版本并行落地、清单验证、手动停止、切换、启动与健康验证流程，不覆盖数据目录或 SecretStore
- [x] 5.3 实现健康失败后的上一运行包切回，证明不回滚 SQLite、checkpoint、节点身份、Gateway token 或 Coordinator refresh
- [x] 5.4 实现只移除程序和非秘密安装元数据的安全路径，默认保留数据/keyring，并保持现有显式数据卸载确认不变
- [x] 5.5 在干净 Windows/macOS 当前用户环境验证安装、终端退出后常驻、手动停止、零自启动注册、新会话保持 stopped、手动恢复、替换和移除；不为验收重启生产节点
- [x] 5.6 运行可重复构建、依赖/许可、路径边界、秘密扫描和双平台 CI，提交打包/切换阶段
- [x] 5.7 将打包/切换阶段及验收规划修订推送到 `origin/feature/manual-node-runtime`，保留远端恢复点

## 6. 真实 A/B 验收、评估与收尾

- [x] 6.1 建立真实 A/B 执行前只读基线，记录生产配置/SecretStore 摘要、HomeMac、B 手写接口、route、Murus/防火墙、8082、8787 和现有进程状态
- [x] 6.2 在不改网络配置的前提下执行首次 A/B 替换：证明 A 本地应用可由运行包管理；捕获 B 冻结 Gateway 被 macOS Application Firewall 挂起入站 flow 的失败证据；安全停止打包进程、恢复既有 Gateway 并验证 A 重新得到 `401`
- [x] 6.3a 记录用户选择当前机器人工防火墙授权，验证精确正式 executable 获准、A peer 无 token `401`、终端脱离常驻，以及 Murus/WireGuard/稳定 route/配置/SecretStore/8082/零自启动不变量；Developer ID/公证延期到未来分发 change
- [ ] 6.3b 完成独立 `fix-macos-gateway-runtime-health` 后重跑 B Gateway runtime-managed start/status/stop、重复 start、终端退出常驻、新会话 stopped 与手动恢复；本机 hairpin 失败不得误报 `startup_unstable`，监听器存在不得替代 peer `401`
- [ ] 6.4a 在临时数据目录、临时 profile 和不可达模型 endpoint/fake 模型中验证 `unavailable` 不改变确定性工具、Gateway 鉴权、进程所有权、停止和恢复决定，记录延迟与资源开销；不得停止、改写或读取生产模型秘密
- [x] 6.4b 明确记录真实 A/B 未配置 Coordinator，真实 enrollment/sync 延期且不作为本 change 收尾门禁；保留既有 fake/集成测试对“模型离线不阻止 Coordinator 代码路径”的契约证据，不伪报真机同步通过
- [x] 6.5 评估启动成功率、错误参数率、安全拦截率、状态正确率、恢复成功率、启动/停止延迟、CPU/内存、包体积和日志增长；失败率保留真实 B Gateway 未通过结果，不以回退成功冲抵
- [x] 6.6 保存并对照执行后不变性证据，证明配置、秘密、HomeMac、用户 WireGuard、route、Murus、8082 和零自启动未被打包流程改写；Application Firewall 只有用户明确批准的精确正式 executable 许可条目发生预期变化，对含动态缓存项的 route 全表摘要同时保存稳定的 WireGuard 路由子集
- [x] 6.7 更新安装、数据/秘密边界、手动启动/停止/状态、模型外部依赖、升级回滚、日志和故障诊断文档，明确没有开机自启及 macOS 入站信任前置条件
- [ ] 6.7a 核对并按需更新主 FigJam 的外部模型、当前机器人工防火墙许可、本地生命周期/peer 可达性分层、Coordinator 延期、最后核对日期和当前/历史标记；当前 Figma Starter MCP 调用上限阻止画布读取，解除后补做，仓库文档链接已统一指向主图
- [ ] 6.8 运行全量质量、安全、OpenSpec、双平台构建、A/B 证据和主架构图门禁，提交、推送、创建 PR；合并后同步主规格并归档 change
