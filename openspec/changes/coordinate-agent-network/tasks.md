## 1. 协议、安全与基线

- [x] 1.1 盘点静态 peer、Gateway 认证、节点摘要、动态工具加载、资源 API 和 A/B 配置的现有入口与迁移约束
- [x] 1.2 用隔离 spike 比较标准 Ed25519 JWT 实现，固定 assertion 字段、算法、key ID、TTL、audience 和拒绝规则
- [x] 1.3 定义 Coordinator 协议版本、network/node 身份、状态、修订、快照、分页、错误和审计契约
- [x] 1.4 定义 enrollment、refresh、assertion、签名私钥和验证公钥的数据分类、存储、轮换与删除规则
- [x] 1.5 固定现有静态 A/B 诊断、动态工具选择、延迟、token、成本和网络不变性迁移基线
- [x] 1.6 建立架构测试，禁止 Coordinator 接收工具正文、操作正文、模型密钥、记忆、对话或 WireGuard 私钥
- [x] 1.7 运行协议、密码学、安全扫描、格式和类型门禁，提交并推送基线阶段

## 2. Coordinator 节点注册与持久化

- [x] 2.1 建立 Coordinator 独立应用工厂、显式 WireGuard Agent API 监听配置和环回管理员 API 配置
- [x] 2.2 实现 SQLite network、node、credential、enrollment token、signing key、revocation、revision 和 audit 存储
- [x] 2.3 实现只保存哈希、绑定 network/TTL/次数且原子消费的一次性 enrollment token 服务
- [x] 2.4 实现节点首次注册、幂等重试、稳定 node ID、refresh 凭据签发和 keyring 兼容存储边界
- [x] 2.5 实现 refresh 凭据认证、轮换、旧凭据失效、速率限制和不含秘密的审计
- [x] 2.6 覆盖 token 过期/重放/撤销/跨 network、并发消费、重复注册、身份占用和数据库重启恢复测试
- [x] 2.7 运行节点注册正确性、隔离、秘密零泄漏和存储迁移门禁，提交并推送注册阶段

## 3. 签名身份、心跳与撤销

- [x] 3.1 实现 Coordinator Ed25519 签名密钥秘密存储、验证公钥发布、固定指纹和 key ID 轮换窗口
- [x] 3.2 实现绑定 network/node/audience/protocol/jti/iat/exp 的短期 access assertion 签发
- [x] 3.3 实现 assertion 的标准离线验证器，拒绝未知 key、算法降级、错误 audience、跨 network、过期和畸形声明
- [x] 3.4 实现认证心跳和基于服务器接收时间的 online → stale → offline → revoked/incompatible 状态机
- [x] 3.5 实现管理员节点查看、refresh 轮换、撤销和显式恢复 API，并在撤销事务生成目录修订
- [x] 3.6 覆盖签名篡改、未知 key ID、旧 key 窗口、assertion 重放、Agent 时钟漂移、心跳超时和撤销测试
- [x] 3.7 运行认证、状态机、时间边界和故障注入门禁，提交并推送签名身份阶段

## 4. 能力与服务目录

- [x] 4.1 实现逐节点能力完整快照、工具版本/平台/风险/可用性/schema 哈希和原子替换
- [x] 4.2 实现稳定 service ID、逐节点服务完整快照、来源/置信度/时间和 stopped 收敛
- [x] 4.3 实现 snapshot ID、本地单调序号、幂等键、乱序拒绝和单调 server revision
- [x] 4.4 实现基于节点状态与服务器时间的能力/服务 fresh、stale、offline、revoked 传播
- [x] 4.5 实现按节点、状态、平台、工具版本、协议、端口、可访问性和新鲜度过滤的有界稳定分页查询
- [x] 4.6 覆盖重复/乱序/并发/超限快照、服务消失、节点离线、跨 network 游标和一致读取测试
- [x] 4.7 运行目录收敛、隔离、性能、事务和数据最小化门禁，提交并推送目录阶段

## 5. Agent Coordinator 客户端与降级

- [x] 5.1 实现 Agent Coordinator 配置、enrollment 命令/API、refresh keyring 保存和验证公钥指纹确认
- [x] 5.2 实现后台心跳、能力/服务完整快照同步、server revision 保存和 full-sync 恢复
- [x] 5.3 实现超时、取消、数量/字节/并发预算，以及带抖动的指数退避和停止生命周期
- [x] 5.4 实现最小化能力摘要与服务快照渲染，排除 schema 秘密示例、环境变量、正文、对话和记忆
- [x] 5.5 实现目录增量拉取、本地有界缓存、last-success/freshness/error 状态和授权状态只读视图
- [x] 5.6 证明 Coordinator 离线、认证失败、快照过大和本地无模型时资源 API、静态 peer 与操作恢复仍可用
- [x] 5.7 运行客户端生命周期、退避、缓存、降级和秘密扫描门禁，提交并推送同步阶段

## 6. Gateway 身份与动态远端工具

- [ ] 6.1 扩展 Tool/Operation Gateway 认证，区分显式 static token 与 Coordinator assertion，保持现有 static peer 兼容
- [ ] 6.2 实现本地 Coordinator 授权缓存、验证公钥、节点状态与 TTL；撤销到达立即拒绝，缓存过期对 managed peer 失败关闭
- [ ] 6.3 实现按稳定 node ID 解析目录 endpoint，禁止模型直接注入未知 endpoint 或认证材料
- [ ] 6.4 实现目录预筛选 → 短期 assertion → Gateway 验签 → 目标能力直连复核 → 工具执行链路
- [ ] 6.5 实现 network、节点状态、endpoint TTL、授权、平台、协议/工具版本、风险和任务阶段的动态工具过滤
- [ ] 6.6 记录目录 revision、直连能力 revision、候选/保留/排除计数与原因，并在冲突时以目标实时证据为准
- [ ] 6.7 覆盖 assertion 过期/撤销/audience 错误、Coordinator 篡改能力、目录陈旧、static 回退和写操作不扩权测试
- [ ] 6.8 运行 Gateway 认证、动态工具正确性、操作治理和兼容回归门禁，提交并推送集成阶段

## 7. 管理与资源体验

- [ ] 7.1 提供环回管理员页面/API，创建一次性 token、查看节点状态/最后心跳/版本并执行撤销与凭据轮换
- [ ] 7.2 扩展本地资源页面/API，显示 Coordinator 连接、目录 revision、新鲜度、节点、能力和服务摘要
- [ ] 7.3 在目录或 Coordinator 故障时明确显示 stale/offline/incompatible/managed-auth-expired，不把缓存表示为实时状态
- [ ] 7.4 建立响应与页面零泄漏测试，禁止显示完整 enrollment/refresh/assertion、认证头、签名私钥或远端正文
- [ ] 7.5 运行无模型页面、键盘操作、错误状态、分页、性能和 Web 安全门禁，提交并推送体验阶段

## 8. 综合评估与安全验证

- [ ] 8.1 建立注册成功、token 重放、跨 network、节点撤销、心跳超时、乱序快照、服务消失、协议不兼容和 Coordinator 离线数据集
- [ ] 8.2 建立签名篡改、未知 key、错误 audience、过期 assertion、授权缓存过期和 static/managed 身份混淆的零容忍测试
- [ ] 8.3 评估目录节点/服务收敛正确率、新鲜度、撤销传播时间、乱序拒绝率、查询/同步延迟和存储增长
- [ ] 8.4 比较 static peer 与 Coordinator 路径的工具选择正确率、任务完成率、错误参数率、安全拦截率、延迟、token 和成本
- [ ] 8.5 注入 Coordinator、单节点模型、目标 Gateway 和本地同步器独立故障，验证失败归因与确定性降级
- [ ] 8.6 运行全量格式、严格类型、测试/分支覆盖、安全扫描、协议兼容、OpenSpec 和性能门禁，提交并推送综合评估阶段

## 9. A/B 迁移、真机验收与文档

- [ ] 9.1 在隔离数据目录部署测试 Coordinator，只绑定既有 WireGuard 私网地址和环回管理员地址，不新增公网/通配监听
- [ ] 9.2 先注册 B、再注册 A，同步能力与服务目录并保存 WireGuard、Gateway、模型和服务前后不变性快照
- [ ] 9.3 完成“目录选择 B → 动态工具 → assertion 认证 → 直连复核 → 跨节点诊断 → 引用证据回答”真机闭环
- [ ] 9.4 完成 token 重放、Coordinator 离线、A 撤销、授权缓存到期、服务停止和协议不兼容真机故障矩阵
- [ ] 9.5 证明 static peer 回退、已有临时共享操作、撤销/到期/恢复和无模型资源面板在控制面故障时仍可用
- [ ] 9.6 更新架构、ADR、威胁模型、数据分类、部署运维、A/B 验收、路线图和三分钟演示文档
- [ ] 9.7 建立 OpenSpec 场景、自动测试、真机证据、指标和任务对照，运行最终门禁并提交推送
