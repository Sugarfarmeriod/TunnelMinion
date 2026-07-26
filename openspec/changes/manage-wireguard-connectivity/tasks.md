## 1. 基线、spike 与停止门禁

- [x] 1.1 只读采集 Windows A `HomeMac` 与 macOS B 手写 WireGuard 的接口、地址、peer、route、配置位置、服务/PID 和启停方式摘要，排除私钥并建立恢复检查表
- [x] 1.2 固定 Gateway `8787`、模型 `8082`、Coordinator、Murus/Windows 防火墙和用户 route 的前后不变性基线与脱敏哈希
- [x] 1.3 在 fake/sandbox 中比较 Windows 官方客户端与 tunnel service 的创建、替换、停止、删除、权限、回执和失败恢复语义
- [x] 1.4 在不修改 B 手写配置的 fixture 中比较 macOS `wg`/`wg-quick` 或当前工具链的创建、替换、停止、删除、权限、回执和失败恢复语义
- [x] 1.5 比较受信 WireGuard hub 与不透明 UDP datagram relay 的机密性、转发/防火墙前置条件、DoS、部署和性能，记录选择或拆分结论
- [x] 1.6 评估显式 endpoint、Coordinator 观察、STUN 和 NAT 映射方案；未证明的穿透能力保持非目标
- [x] 1.7 建立地址/route 冲突扫描器设计并只读运行 A/B，形成候选测试地址池和 B UDP 端口需求，不把扫描结果当用户授权
- [x] 1.8 更新威胁模型、数据分类和 ADR 草案，覆盖私钥、签名配置、route 劫持、relay 信任、部分成功、误删与控制面攻破
- [x] 1.9 运行 spike、秘密扫描、OpenSpec 和只读不变性门禁，提交并推送基线阶段

## 2. Provider、配置与状态契约

- [x] 2.1 定义 `NetworkProvider` 的 observe/plan/apply/verify/rollback/recover 协议、结构化错误和取消安全点
- [x] 2.2 定义 observed-user、managed-owned、ownership-conflict、配置 revision、计划、步骤、回执、验证和恢复契约
- [x] 2.3 定义受管 network identity、公钥、地址租约、候选 endpoint、relay role、signed desired config 和 acknowledgement 契约
- [x] 2.4 定义 unconfigured/awaiting-authorization/applying/probing/direct/relayed/degraded/rolling-back/manual-intervention 状态机
- [x] 2.5 建立契约预算、协议版本、JSON 序列化、未知字段拒绝和禁止秘密字段的架构测试
- [x] 2.6 实现内存 fake Provider，覆盖幂等成功、响应丢失、逐步失败、验证失败、回滚失败、取消和崩溃恢复
- [x] 2.7 建立地址、route、接口、公钥和所有权 fixture，覆盖默认路由、重叠地址、名称复用和外部替换
- [x] 2.8 运行契约、状态机、分支覆盖、格式和严格类型门禁，提交并推送核心契约阶段

## 3. Coordinator 地址、配置与路径控制面

- [x] 3.1 扩展 SQLite schema，保存 network 地址池、稳定租约、节点公钥、候选、relay role、desired/parent revision 和逐节点 acknowledgement
- [x] 3.2 实现事务地址分配、保留/重叠拒绝、并发唯一性、撤销/恢复和数据库重启恢复
- [x] 3.3 实现公钥注册/轮换的 pending/active/retired 生命周期，拒绝私钥、预共享密钥和完整配置正文
- [x] 3.4 实现候选 endpoint 来源、数量/字节、有效期和速率预算，拒绝跨 network、模型输入和畸形地址
- [x] 3.5 实现域分离 Ed25519 desired config 签名、固定指纹、目标/父修订/有效期绑定和 key 轮换窗口
- [x] 3.6 实现共同 revision saga、节点阶段 acknowledgement、全部验证后 active、任一失败后的回滚指令和幂等恢复
- [x] 3.7 实现管理员 network/address-pool/relay-role 管理 API，只绑定环回管理员应用并提供不含秘密的审计
- [x] 3.8 覆盖并发租约、乱序/篡改配置、未知 key、跨节点重放、跨 network、部分成功、撤销和存储增长测试
- [x] 3.9 运行控制面正确性、事务、签名、安全、性能和 OpenSpec 门禁，提交并推送 Coordinator 阶段

## 4. Agent 同步、所有权账本与 L3 治理

- [x] 4.1 实现本地受管资源 SQLite 账本与操作系统秘密引用，普通数据库和导出不得保存 WireGuard 私钥
- [x] 4.2 实现 desired config 拉取、签名/指纹/目标/父修订/预算验证、pending 保存和 full-sync 恢复
- [x] 4.3 实现配置锁、单并发同步、超时、取消安全点、指数退避和 last-known-good 缓存
- [x] 4.4 扩展 Operation Policy，注册仅供治理工作流调用的 L3 network plan，保持普通 Tool Gateway 和模型工具集无写能力
- [x] 4.5 实现绑定 network/node/Provider/所有权/地址池/host routes/peer/relay/revision/hash/有效期的本机批准与预授权策略
- [x] 4.6 实现同一批准范围内的幂等自动修复，以及任一范围扩大、撤销或到期后重新进入 awaiting-authorization
- [x] 4.7 实现逐步回执、独立验证、逆序回滚、ownership conflict 熔断、本机紧急停止和无模型恢复
- [x] 4.8 扩展 Agent acknowledgement 与脱敏路径状态同步，排除私钥、用户完整 route 和未允许物理 endpoint
- [x] 4.9 覆盖模型/prompt/记忆尝试批准、签名配置扩权、并发 apply、取消、崩溃、Coordinator 离线和无模型测试
- [x] 4.10 运行治理、秘密、恢复、分支覆盖和严格类型门禁，提交并推送 Agent 治理阶段

## 5. Windows Provider 纵向切片

- [x] 5.1 实现 Windows observe-only 适配器，读取官方 WireGuard 客户端/tunnel service 的接口、peer、地址、route 和服务状态
- [x] 5.2 实现 Windows 平台权限/依赖预检和固定参数 runner，禁止 Shell 字符串、动态命令和交互式提权
- [x] 5.3 实现独立接口命名、ACL 受限秘密/配置材料、所有权指纹和计划 diff，不触碰 `HomeMac`
- [x] 5.4 实现 create/update/stop/remove 的固定步骤、幂等回执、实时 verify 和父 revision rollback
- [x] 5.5 实现 Windows 重启恢复、半写配置检测、ownership conflict 和卸载清理
- [x] 5.6 用 fake runner 覆盖每个步骤失败、权限不足、服务缺失、名称冲突、route 冲突和外部替换
- [x] 5.7 在只读模式真机复核 A 基线；任何 managed 写入前保存候选地址/端口方案并等待用户明确授权
- [x] 5.8 运行 Windows Provider、状态不变性、安全和全量回归门禁，提交并推送 Windows 阶段

## 6. macOS Provider 纵向切片

- [x] 6.1 实现 macOS observe-only 适配器，读取当前 `wg`/接口/peer/address/route/进程状态且不读取 B 私钥
- [x] 6.2 实现 macOS 平台权限/依赖预检和固定参数 runner，禁止 sudo prompt、Shell 字符串和动态配置路径
- [x] 6.3 实现独立配置目录、接口标识、0600 必需秘密文件、所有权指纹和计划 diff，不触碰 B 手写配置
- [x] 6.4 实现 create/update/stop/remove 的固定步骤、幂等回执、实时 verify 和父 revision rollback
- [x] 6.5 实现 macOS 重启恢复、半写配置检测、ownership conflict 和卸载清理
- [x] 6.6 用 fake runner 覆盖每个步骤失败、权限不足、依赖缺失、接口/route 冲突和外部替换
- [x] 6.7 在只读模式真机复核 B 基线；任何 managed 写入前核对 Murus/UDP 前置条件并等待用户明确授权
- [x] 6.8 运行 macOS Provider、状态不变性、安全和全量回归门禁，提交并推送 macOS 阶段

## 7. 直连路径闭环

- [x] 7.1 实现本机策略过滤后的候选排序和有界探测，不接受模型/对话提供的 endpoint
- [x] 7.2 实现 handshake、期望 host route 与请求节点目标探测的联合 direct 验证和证据模型
- [x] 7.3 实现连续失败阈值、成功稳定窗口、最小驻留时间、hysteresis 和单并发路径控制器
- [x] 7.4 实现路径 revision 与配置 saga 联动，切换失败恢复 last-known-good
- [x] 7.5 扩展目录/Gateway endpoint 选择，优先 fresh verified managed path，并明确区分 direct、relayed 与 static
- [x] 7.6 扩展资源页显示 Provider、revision、授权、候选/握手/route/目标探测新鲜度和稳定错误码
- [x] 7.7 覆盖旧握手、route 缺失、目标探测失败、单次丢包、持续失败、恢复抖动、static 回退和控制面离线
- [x] 7.8 运行路径正确性、延迟、切换稳定性、安全和 Web 零泄漏门禁，提交并推送 direct 阶段

## 8. relay 机制与隔离三节点闭环

- [x] 8.1 根据 1.5 spike 确认不透明专用 packet relay 方向；因缺少协议/DoS/三节点证据，拆分为 `build-isolated-packet-relay`
- [x] 8.2 将 relay-capable/active、管理员启用/撤销和路径 revision 迁移到独立 change，本 change 保留现有角色契约
- [x] 8.3 禁止在本 change 伪实现 relay 数据面或复用普通 Coordinator；客户端/服务端迁移到独立 change
- [x] 8.4 将 relay 身份、network/node 隔离、容量/带宽、审计和敏感数据边界迁移到独立 change
- [x] 8.5 将 direct/relayed 切换、实际 relay 验证与安全切回迁移到独立 change；当前无 relay 时保持 static/degraded
- [x] 8.6 将隔离三节点 direct/relayed、离线、容量、撤销和恢复矩阵迁移到独立 change
- [x] 8.7 将真实握手、切换中断、延迟、吞吐、CPU/内存和信任对照迁移到独立 change，不宣称未测 NAT 类型
- [x] 8.8 完成 relay 拆分门禁；本 change 不提交未经验证的协议/数据面，独立 change 自行执行全套门禁

## 9. 评估、运维与安全收尾

- [x] 9.1 建立地址冲突、签名篡改、跨节点重放、策略扩权、部分成功、回滚失败、所有权冲突和控制面离线数据集
- [x] 9.2 评估配置收敛正确率、direct/relay 选择正确率、错误参数率、安全拦截率、回滚成功率、切换时间、延迟和资源成本
- [x] 9.3 证明模型启用/禁用不改变 Provider 计划、授权、执行、验证和回滚结果；记录模型解释的 token/延迟/成本但不把它作为网络正确性
- [x] 9.4 扩展威胁模型、数据分类、ADR、架构、运维、恢复、卸载和人工干预手册
- [x] 9.5 扩展安全扫描与导出/卸载测试，禁止私钥、完整配置、认证头、用户 route 和未过滤 endpoint 泄漏
- [x] 9.6 建立 OpenSpec 场景、自动测试、隔离环境证据、指标和任务对照
- [x] 9.7 运行格式、严格类型、100% 源/分支覆盖、全量测试、安全扫描、OpenSpec、性能和协议兼容门禁
- [x] 9.8 提交并推送评估与文档阶段

## 10. A/B 独立测试隧道与最终清理

- [ ] 10.1 展示只读冲突扫描、候选地址池、A/B UDP 端口、接口名、route、Murus/Windows 防火墙前置条件和完整回滚计划，获得用户明确授权后才继续
- [ ] 10.2 在隔离数据目录生成本机私钥和所有权账本，先创建 B、再创建 A 的独立 managed 测试接口，不切换生产 endpoint
- [ ] 10.3 完成地址租约、公钥/候选同步、双方本机 L3 批准、配置 saga 和 direct 联合验证
- [ ] 10.4 完成响应丢失、单端 apply 失败、验证失败、key rotation、Coordinator 离线、Agent 崩溃和 ownership conflict 真机矩阵
- [ ] 10.5 完成有前置条件的隔离 relay 验收或引用第 8 阶段三节点证据；不得让生产 A/B/Coordinator 静默承担 relay
- [ ] 10.6 清理全部测试接口、配置、route、秘密和账本，证明清理幂等且无 ownership conflict 遗留
- [ ] 10.7 保存 A/B 前后不变性快照，确认 `HomeMac`、B 手写配置、8787、8082、防火墙、用户 route 和 static 回退均未改变
- [ ] 10.8 更新路线图和三分钟演示，运行最终门禁，提交推送、创建 PR、合并并同步 main
