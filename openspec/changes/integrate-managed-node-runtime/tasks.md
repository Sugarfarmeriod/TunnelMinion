## 1. 配置、秘密与 enrollment 纵向切片

- [x] 1.1 定义版本化 `ManagedNodeConfig`、状态/错误模型和原子文件仓储，拒绝未知字段与任何 token、refresh、assertion 或私钥字段
- [x] 1.2 扩展安全导出与卸载允许列表，证明 managed 配置可导出而 refresh/checkpoint 中的认证材料不泄露
- [x] 1.3 实现 `coordinator-enroll` CLI，从标准输入读取 token、确认固定指纹、幂等注册并写入可选 keyring/受限文件秘密存储
- [x] 1.4 覆盖有效/过期/重放 token、指纹不匹配、凭据存储失败、重复 enrollment、日志与命令行零泄漏测试
- [x] 1.5 运行配置、CLI、秘密扫描、格式、类型和分支覆盖门禁，提交并推送 enrollment 阶段

## 2. 运行时监督与恢复内核

- [x] 2.1 定义 `ManagedNodeRuntime` 依赖、分域状态、任务监督、单并发、取消安全点和停止超时契约
- [x] 2.2 实现 fake 目录同步、服务观察和 managed config 循环，覆盖独立失败、退避、重启上限和无界任务防护
- [x] 2.3 实现 lifespan 启停、checkpoint 原子恢复和进程未知异常 fail-closed，保证未配置 managed node 时零行为变化
- [x] 2.4 覆盖正常停止、启动失败、循环崩溃、响应丢失、重复触发、取消和同数据目录重启测试
- [x] 2.5 运行监督器、并发、恢复、格式、类型和分支覆盖门禁，提交并推送运行时内核阶段

## 3. 确定性服务观察与完整快照

- [x] 3.1 建立平台无关服务观察模型和稳定 service ID，规范监听/进程/Docker 的地址、协议、来源、置信度、可访问性和生命周期
- [x] 3.2 使用现有 Windows/macOS 只读适配器实现监听与进程默认来源、Docker best-effort 来源和主动探测默认关闭
- [x] 3.3 实现单并发、超时、记录数/字节预算、最小刷新间隔与完整性门禁，失败时不得提交部分快照
- [x] 3.4 覆盖服务出现/消失、双栈、UDP、权限不足、Docker 缺失/超限、超时、敏感元数据过滤和无模型场景
- [x] 3.5 运行服务快照、跨平台契约、秘密扫描、格式、类型和分支覆盖门禁，提交并推送服务观察阶段

## 4. Coordinator 目录同步常规接线

- [x] 4.1 将现有 enrollment 凭据、能力渲染、服务快照、checkpoint、目录缓存和 `AgentCoordinatorSynchronizer` 注入运行时
- [x] 4.2 实现首次心跳/能力/服务顺序、周期刷新、full-sync 恢复、stale/offline/incompatible 和有界退避状态聚合
- [x] 4.3 证明 Coordinator 离线、认证失败、快照超限或无模型时本地页面、只读工具、static peer、操作到期与恢复继续工作
- [x] 4.4 覆盖 Windows/macOS 相同身份重启、重复/乱序修订、服务停止收敛、撤销和固定 key 轮换测试
- [x] 4.5 运行 Coordinator 客户端、目录、降级、Web 零泄漏和全量回归门禁，提交并推送目录接线阶段

## 5. managed config、治理与路径状态接线

- [x] 5.1 将 `ManagedNetworkSynchronizer`、签名 key、凭据、SQLite checkpoint 和 acknowledgement/path sink 注入运行时
- [x] 5.2 将合法 desired config 收敛到 pending/awaiting-authorization，并只通过既有 L3 governance 与 Provider 执行
- [x] 5.3 接入 applied/verified/rolled-back/manual-intervention、last-known-good、控制面 stale 和恢复状态，禁止模型/对话/记忆提供配置或授权
- [x] 5.4 用 fake Provider 覆盖无授权、幂等成功、verify 失败、部分失败、回滚失败、崩溃恢复、Coordinator 离线和 static 降级矩阵
- [x] 5.5 运行网络同步、治理、所有权、架构边界、格式、类型和分支覆盖门禁，提交并推送受管配置阶段

## 6. Windows/macOS 常规应用与资源体验

- [x] 6.1 在 Windows 与 macOS 本地应用工厂中按显式配置创建 `ManagedNodeRuntime` 并组合 FastAPI lifespan，不改变环回绑定
- [x] 6.2 扩展 CLI 常规启动配置选择、状态与稳定错误输出，保持私网 Gateway 独立监听和现有命令兼容
- [x] 6.3 扩展资源 API/页面，分域显示 enrollment、目录、服务观察、managed config、授权、路径与 last-known-good 的脱敏状态
- [x] 6.4 覆盖未配置、enrollment-required、ready、backoff、awaiting-authorization、observation-degraded、重启恢复和零秘密页面测试
- [x] 6.5 运行 Windows/macOS 应用、CLI、Web 安全、键盘操作、无模型和全量质量门禁，提交并推送平台接线阶段

## 7. 综合评估、A/B 验收与收尾

- [x] 7.1 建立常规入口首次加入、重启恢复、Coordinator 离线、服务变化、配置待批准、Provider 失败和无模型数据集
- [x] 7.2 评估目录/服务收敛正确率、重复身份数、错误参数率、安全拦截率、恢复成功率、同步延迟、CPU/内存和模型零依赖
- [x] 7.3 比较模型启用/禁用前后的身份、服务快照、配置 hash、授权、Provider 计划、同步与恢复结果，要求确定性路径完全一致
- [x] 7.4 在隔离 A/B 数据目录用常规入口完成 enrollment、心跳、服务目录、managed 状态、无模型和控制面离线验收
- [x] 7.5 保存并核对 `HomeMac`、B 手写配置、Murus/防火墙、用户 route、Gateway `8787` 和模型 `8082` 前后不变性证据
- [x] 7.6 更新架构、启动运维、enrollment、故障诊断、恢复与卸载文档，说明 Gateway 仍是独立私网进程
- [ ] 7.7 运行全量质量、安全扫描、OpenSpec、性能和 A/B 证据门禁，提交、推送、创建 PR 并在合并后归档 change
