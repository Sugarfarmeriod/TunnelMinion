## 1. 隔离 spike、状态契约与停止门禁

- [x] 1.1 建立无系统写入的 macOS Gateway 隔离 fixture，复现“自有进程与监听器存在、B 本机 WireGuard hairpin 超时、独立 peer 得到 `401`”以及“监听器存在但 peer flow 挂起”两种相反场景；证据见 `evaluations/platform/runtime-health-spike-2026-08-05.json`
- [x] 1.2 完成 `psutil.Process(pid)` 进程专属 socket 合约、当前 Windows 账户自有监听器 smoke 与固定 executable/固定参数/无 shell 的 `lsof` 降级命令/解析契约；当前平台无 `lsof`，macOS 实机执行留在隔离验收阶段，权限不足时统一 `listener_ownership_unverified`
- [x] 1.3 固定本地 readiness、稳定错误码、peer 验收结果和 fail-closed 归属契约，确认不新增跨节点写协议、不持久化伪 peer 状态、不降低进程所有权检查；deadline 实现留在第 2 组
- [x] 1.4 运行 spike、路径/参数注入、权限不足、秘密扫描与 OpenSpec 门禁，提交并推送设计验证阶段；本阶段只记录当前 Windows smoke，macOS/lsof 真实权限证据待 macOS runner

## 2. 本地 readiness 与真实总 deadline

- [x] 2.1 将组件健康协议改为有界结构化 readiness 结果，为每个组件从 monotonic 起点计算总 deadline，并把单次探针、重试 sleep 和 stable window 裁剪到剩余预算
- [x] 2.2 保持本地应用环回 HTTP 健康行为；为 Gateway 接入进程专属 listener ownership，macOS 不再用自身 WireGuard HTTP 作为本地就绪硬依赖；Windows 启动 shim 子进程仅在同一受管进程树且命令行绑定同一组件时归并
- [x] 2.3 更新 `start/status` 的本地状态与稳定错误，保证监听器消失会报告失败、任意进程占端口不会成功、hairpin 不通不会把自有 Gateway 误报为本地失败
- [x] 2.4 用 fake clock/probe/sleep 覆盖立即成功、延迟成功、每次探针超时、稳定窗口跨 deadline、进程退出、监听器换主和并发操作，证明墙钟预算不再放大到约 185 秒
- [x] 2.5 运行 runtime 单元、分支、类型、格式和覆盖率门禁，提交并推送本地 readiness/deadline 阶段

## 3. status/stop 与 peer 验收分域

- [x] 3.1 保证 `status` 先验证本地进程/监听器所有权，`stop` 只按 PID、启动时间、executable、组件参数和实例身份安全终止，不访问 peer
- [x] 3.2 在独立 A/B acceptance 结果中表达 `peer_unverified`、`peer_reachable`、`peer_unreachable`，绑定 package/入口摘要与无 token `401`，不把结果伪装成 B 本地持久状态
- [x] 3.3 覆盖 peer 离线、监听器存在但防火墙挂起、错误 HTTP 状态、响应过大/恶意正文、listener 消失但自有进程仍可 stop、PID 冲突但 peer 可达等矩阵
- [x] 3.4 评估本地状态正确率、peer 分类正确率、错误参数率、安全拦截率、start/status/stop 延迟和零秘密输出，提交并推送状态分域阶段

## 4. 双平台回归与隔离 package

- [x] 4.1 构建新的 Windows amd64 与 macOS arm64 版本化 package，验证清单、许可、可重复输入和程序/数据/秘密分离，不覆盖当前 accepted 指针
- [x] 4.2 在临时 profile、临时数据目录和非生产端口验证 macOS package 的 start/status/stop、重复 start、终端脱离、新会话与 hairpin 不可用；验证 Windows Gateway/本地应用没有回归
- [x] 4.3 覆盖 listener ownership 权限不足、工具缺失、端口冲突、进程替换、模型不可达和 Coordinator 未配置，确认模型/Coordinator 不成为本地 lifecycle 前置
- [x] 4.4 运行 Windows/macOS 全量测试、100% 覆盖率、Ruff、format、Pyright、离线安全评估、依赖许可、构建/仓库/证据秘密扫描和 OpenSpec strict，提交并推送隔离验收阶段

## 5. 真实 A/B 受控切换

- [ ] 5.1 取得用户对实际保留的精确 package 与短时 Gateway 切换的确认，固定当前 direct Gateway 恢复命令、配置 endpoint 的 A peer `401`、package/配置/SecretStore、客户管理防火墙规则或只读视图摘要、route/接口、8082/8787、进程与零自启动基线；不把缺少厂商专用 VPN CLI、完整 peer 导出或不影响放行策略的 logging 状态单独当作 blocker
- [ ] 5.2 在不改客户管理的防火墙、VPN、WireGuard 或 route 且不停止生产模型的前提下，停止当前 direct Gateway、启动 runtime-managed 候选并退出控制终端，验证 B 本地 running 与配置 endpoint 上的 A peer `401` 同时成立
- [ ] 5.3 验证重复 start、status、正常 stop、新会话保持 stopped、手动恢复、listener 消失后的安全 stop 和 peer 暂时离线；任一失败恢复切换前已验证入口并复核 `401`
- [ ] 5.4 保存相关防火墙规则/只读视图与 route/接口摘要的执行后不变性、deadline/首次与稳定 peer 延迟、CPU/内存、日志增长、状态正确率和恢复成功率证据，不以 direct fallback 成功冲抵 runtime-managed 失败

## 6. 文档、架构图与交付

- [ ] 6.1 更新本地 lifecycle/peer accepted 区别、真实总 deadline、listener ownership、客户负责防火墙放行、传输方式无关、当前机器人工许可、升级回退和故障诊断文档，明确无开机自启且旧 Python 环境不是可靠退路；局域网自动发现留给独立 change
- [ ] 6.2 核对并按需更新主 FigJam 的本地生命周期/peer 数据面、客户管理防火墙、可替换网络传输、外部模型、Coordinator 延期、当前 direct/目标 runtime-managed 状态、最后核对日期和当前/历史标记；若无需改图，在验收证据中说明原因
- [ ] 6.3 运行最终全量质量、安全、双平台 package、真实 A/B、文档链接、主架构图和 OpenSpec 门禁，提交并推送最终阶段，创建 PR
- [ ] 6.4 合并后同步 `macos-gateway-runtime-health` 主规格，完成 `package-manual-node-runtime` 6.3b 的真实复验并分别归档 change
