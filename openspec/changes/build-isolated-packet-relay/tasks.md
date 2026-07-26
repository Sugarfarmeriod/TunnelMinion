## 1. 协议与停止门禁

- [ ] 1.1 建立 QUIC DATAGRAM 与 TLS 1.3 framed stream 的相同负载 fixture、状态机和脱敏测量模型
- [ ] 1.2 固定认证前消息、数据 envelope、最大 frame/datagram、序号、TTL、重放和断连恢复语义
- [ ] 1.3 对两种传输运行延迟、吞吐、head-of-line、CPU/内存和依赖安全对照，记录选择与淘汰理由
- [ ] 1.4 更新 relay threat model，覆盖匿名流量、反射/放大、跨 network、重放、队列耗尽和元数据泄露
- [ ] 1.5 若协议、安全或资源预算证据未达标则停止实现；不得回退为裸 UDP 或普通 Coordinator 转发

## 2. 身份、协议与容量契约

- [ ] 2.1 定义 relay service identity 固定、节点 assertion audience、network/node/target/session/nonce 绑定契约
- [ ] 2.2 定义版本化二进制 envelope、未知字段拒绝、opaque payload 和无任意 IP/端口约束
- [ ] 2.3 定义认证、会话、隔离、容量、撤销、过期和稳定错误模型，禁止 payload/秘密进入审计
- [ ] 2.4 建立每会话、节点、network 和全局的并发、datagram、带宽、内存、队列、空闲/绝对 TTL 默认预算
- [ ] 2.5 用属性/模糊测试覆盖畸形长度、未知版本、乱序、重复、跨 network、过期和容量边界
- [ ] 2.6 运行协议契约、序列化、安全扫描和语句/分支覆盖门禁，提交协议阶段

## 3. 独立 relay 数据面

- [ ] 3.1 实现独立 relay 入口、只读预检、固定监听和受限数据目录，不复用 Coordinator/Gateway app
- [ ] 3.2 实现服务身份固定、短期 assertion 离线验证、nonce 消耗和认证前字节/时间预算
- [ ] 3.3 实现同 network 的 source/target session 映射、有界 opaque packet 转发和过期回收
- [ ] 3.4 实现分层令牌桶、会话/队列/内存上限、公平隔离和全局过载 fail-closed
- [ ] 3.5 实现服务停止、崩溃恢复、身份轮换和撤销，不恢复过期或不可证明的 session
- [ ] 3.6 覆盖每个协议阶段失败、慢消费者、目标离线、容量耗尽、撤销、重放和重启
- [ ] 3.7 运行 relay 协议、隔离、DoS、资源、安全和全量回归门禁，提交数据面阶段

## 4. Coordinator、Agent 与路径集成

- [ ] 4.1 扩展 relay capability probe，只允许本机管理员把验证通过的节点设为 capable/active
- [ ] 4.2 发布绑定 relay identity、地址、容量摘要、revision 和有效期的候选，不发布普通 Coordinator endpoint
- [ ] 4.3 实现节点 relay 客户端、服务身份固定、会话认证和 target node 绑定
- [ ] 4.4 扩展路径控制器，仅在 relay 会话、handshake、host route 和目标探测联合成功后选择 relayed
- [ ] 4.5 实现 direct 达阈值后尝试 relayed、relay 失败恢复 last-known-good/static/degraded 和 direct 稳定切回
- [ ] 4.6 扩展资源页和审计，显示 relay identity 摘要、revision、容量、新鲜度和稳定错误且零 endpoint/秘密泄漏
- [ ] 4.7 覆盖控制面离线、过期候选、错误 relay identity、撤销 revision、切换抖动和双路径单并发
- [ ] 4.8 运行 Coordinator/Agent/Gateway 集成、安全和 Web 门禁，提交路径集成阶段

## 5. 隔离三节点部署与验收

- [ ] 5.1 由用户明确指定独立第三节点、管理员、操作系统、测试 network、监听端口和防火墙前置条件
- [ ] 5.2 保存 A/B/relay 的接口、route、监听、进程和生产服务只读基线，证明测试资源完全隔离
- [ ] 5.3 部署独立 relay 服务和测试身份，不让生产 A/B、Coordinator、8787、8082、HomeMac 或 utun4 兼任
- [ ] 5.4 验证 direct、relayed、relay 离线、目标离线、跨 network、容量耗尽、撤销、轮换和恢复矩阵
- [ ] 5.5 清理测试资源并证明生产 A/B、Murus/防火墙、用户 route 和服务前后不变
- [ ] 5.6 保存可复核命令、脱敏哈希、回滚结果和未验证假设，提交三节点证据阶段

## 6. 性能、安全与运维收尾

- [ ] 6.1 对相同负载记录 direct/relayed 的握手、p50/p95 延迟、吞吐、切换中断、丢包、CPU、内存和带宽
- [ ] 6.2 评估路径选择正确率、任务完成率、错误参数率、安全拦截率、恢复成功率、延迟和资源成本
- [ ] 6.3 证明模型启用/禁用不改变 relay 身份、授权、协议、容量、选择、撤销和恢复决定
- [ ] 6.4 完成第三方依赖审查、模糊测试、DoS/隔离测试、秘密扫描、Web 零泄漏和全量双平台 CI
- [ ] 6.5 更新 ADR、威胁模型、部署、监控、容量、轮换、撤销、恢复和卸载手册
- [ ] 6.6 展示完整证据与生产迁移风险，另行获得明确授权；未授权时保持测试限定和 degraded/static
- [ ] 6.7 同步主规格、归档 change，提交、推送、创建 PR、合并 main 并同步本地
