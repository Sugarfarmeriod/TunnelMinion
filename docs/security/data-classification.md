# 数据分类与保留策略

本策略适用于每个 TunnelMinion 节点。数据默认仅保存在本机；跨越节点边界必须具有明确
schema 并经过对等节点授权。WireGuard 已建立连接不代表应用数据访问已经获得授权。

## 数据类别

| 类别 | 示例 | 允许的存储位置 | 模型与上下文用途 | 默认保留时间 |
|---|---|---|---|---|
| 秘密 | 模型 API key、网关凭据、认证头、WireGuard 私钥 | 操作系统凭据存储；禁止进入应用数据库 | 禁止使用 | 直到撤销或删除所属配置 |
| Coordinator enrollment token | 一次性注册材料 | Coordinator 只保存带独立盐的哈希；完整值只在环回管理员创建响应出现一次 | 禁止使用 | 默认 10 分钟或首次成功消费即删除；撤销只保留脱敏审计 |
| Coordinator refresh 凭据 | 单节点长期重连材料 | Agent 操作系统 keyring；Coordinator 只保存验证哈希 | 禁止使用 | 轮换时新值原子生效、旧哈希立即删除；节点撤销或卸载时删除 |
| Coordinator access assertion | 绑定 network/node/audience/jti/protocol/iat/exp 的 Ed25519 JWT | Agent 仅内存；Gateway 仅在请求验证期间解析 | 禁止使用 | 固定 120 秒 TTL，不落盘；仅容忍 5 秒未来签发/激活时钟偏差且不延长到期；撤销缓存可提前拒绝 |
| Coordinator signing private key | Ed25519 assertion 签名私钥 | 仅 Coordinator 服务端秘密存储，禁止配置、日志、备份明文和模型上下文 | 禁止使用 | 按 key ID 轮换；重叠窗口结束后销毁旧私钥，泄漏时立即停发 managed assertion |
| Coordinator verification public key | Ed25519 公钥、key ID 与管理员确认的指纹 | Coordinator 发布公钥集合；Agent/Gateway 本地固定指纹 | 禁止进入 prompt | 轮换窗口保留新旧公钥；过窗删除旧公钥，未知 key ID 必须拒绝 |
| Coordinator 目录元数据 | network/node、私有 endpoint、状态、能力/服务摘要、修订与新鲜度 | Coordinator SQLite 与 Agent 有界缓存 | 只允许脱敏摘要用于节点选择 | 删除节点业务摘要后只保留最小撤销与审计关系；缓存按 TTL/修订失效 |
| WireGuard network identity | 节点公钥、秘密引用存在状态、Provider、地址租约、配置 revision | Coordinator 最小控制面元数据与 Agent 本地账本 | 只允许公钥摘要、revision 和状态用于解释 | 节点撤销后按租约策略释放；公钥轮换窗口结束后删除 retired key |
| WireGuard 私钥与预共享密钥 | `PrivateKey`、PSK 正文 | 所属节点操作系统秘密存储或 Provider 必需的 ACL 受限文件 | 禁止使用 | 撤销、卸载或轮换完成后删除；临时明文必须立即验证清理 |
| 签名 desired config | network/node、父/目标 revision、公钥、host route、候选、relay policy、签名 | Agent 有界 pending/last-known-good 存储；Coordinator 保存生成所需最小字段 | 模型最多看到脱敏计划摘要，不得看到完整 envelope | pending 失败/过期后删除；last-known-good 保留到下一验证 revision 或卸载 |
| 受管资源所有权账本 | network/node、Provider、稳定接口 ID、nonce、配置哈希、系统指纹、回执 | 所属节点 SQLite；秘密只保存引用 | 禁止进入模型；页面仅显示状态和短哈希 | 资源验证删除后清理；ownership conflict 保留到人工解决或用户删除 |
| endpoint 与路径观测 | 允许的 UDP endpoint、来源、有效期、握手/route/目标探测新鲜度、relay 摘要 | Coordinator 有界候选与 Agent 本地状态 | 只允许脱敏候选数量、路径类型和错误码 | 按短 TTL 过期；未允许物理 endpoint 不持久化 |
| 网络不变性基线 | 接口/route/服务/防火墙的规范化 SHA-256、必要冲突摘要 | 本地评估报告 | 只用于确定性门禁，不进入普通对话 | 跟随 change 验收；完整原始 route 与防火墙规则不落库 |
| 实时状态 | peer 握手、监听端口、进程、容器、可达性结果 | 内存缓存或有大小限制的工具 artifact | 仅作为当前 run 的证据 | 缓存 60 秒过期；artifact 跟随所属 run |
| 短期上下文 | 用户消息、公开 run 状态、证据引用、有界摘要 | 本地 checkpoint/消息存储 | 经过上下文预算处理后供当前线程使用 | 直到用户删除线程；不自动同步到云端 |
| Checkpoint | run 状态、预算、取消状态、工具引用 ID | 与消息分离的本地 checkpoint 存储 | 仅用于工作流恢复 | 直到删除线程；中断 run 禁止自动重放 |
| 长期记忆 | 用户确认的节点别名、偏好、稳定服务事实、安全约束 | 按用户/网络/节点 namespace 隔离的本地记忆存储 | 仅为相关 namespace 检索 | 直到修正、删除或清空 namespace |
| 工具 artifact | 过大的结构化工具结果及相关片段 | 本地 artifact 存储；条件允许时依赖系统磁盘加密 | 仅向模型提供选中片段和引用 | 直到删除所属线程；后续可增加更短的可配置 TTL |
| 审计元数据 | ID、工具/版本、节点、脱敏参数摘要、时间、结果/错误 | 仅追加的本地审计存储 | 默认禁止进入模型上下文 | 30 天后删除；安全失败可由用户显式导出 |
| 评估记录 | 数据集/模型/prompt/工具版本、指标、脱敏轨迹、成本和延迟 | 本地报告或经过确认的公开产物 | 仅用于离线评估 | 直到用户删除；公开前必须检查秘密和系统数据 |
| 受管连接保障记录 | 固定 case ID、计划哈希占位、状态、路径、回滚结果、耗时和资源单位 | 仓库内脱敏数据集与报告 | 模型只可解释汇总，不得成为指标真值 | 跟随 OpenSpec change；真实地址、endpoint、route 正文和系统指纹不得进入固定数据集 |

## 强制处理规则

1. 秘密不得进入日志、异常、Web API 响应、模型 prompt、记忆、工具 artifact、评估
   fixture 或远端请求。配置 API 只能返回“是否已经配置”。
2. 实时状态是证据而不是记忆。新的工具结果必须覆盖历史消息和缓存中的旧状态。
3. 远端工具输出属于不可信输入。运行时必须校验 schema、限制字节数，并将其中的文本
   视为数据而不是指令。
4. 长期记忆必须属于允许的数据类型并经过用户明确确认。模型猜测和实时快照不得写入。
5. 删除线程时必须删除其消息、checkpoint 和所属工具 artifact；除非用户另行要求，
   不得删除独立确认的长期记忆。
6. 所有适用的持久记录都必须携带用户、网络和节点 namespace。远端工具请求不得读取
   本机对话、模型配置或私有记忆 namespace。
7. 导出属于明确的本地操作。导出器必须执行与日志相同的脱敏规则，并拒绝无法安全
   分类的记录。
8. Coordinator signing private key 只允许签发 assertion；verification public key 只允许
   通过管理员确认的指纹和 key ID 更新。不得信任 assertion 自带的下载地址或未知 key ID。
9. Coordinator 卸载或网络删除必须删除 enrollment/refresh 哈希、签名私钥、目录业务摘要和
   本地凭据引用；撤销关系与脱敏审计按保留期处理，不删除 static peer 或 WireGuard 配置。
10. Coordinator、日志、评估和导出不得接收 WireGuard 私钥、PSK、完整平台配置或用户完整
    route；不变性证据默认保存规范化哈希和必要冲突摘要。
11. endpoint 必须带认证来源与有效期。控制连接源地址、模型文本和独立 STUN socket 的结果
    不得自动升级为 WireGuard endpoint。
12. 所有权账本不构成单独删除凭据；修改、回滚和删除前必须与实时系统稳定 ID、公钥和指纹复核。
13. 模型启用/禁用对照必须分别记录确定性网络结果与解释成本；不得把模型回答质量、token 数或
    延迟用于判断 Provider 计划、授权、验证、回滚或路径是否正确。

## 实现要求

- 存储接口必须显式编码数据类别，不得接收无类型 payload。
- 日志字段必须使用允许列表；脱敏是第二道防线，不能替代最小化采集。
- 保留期删除必须支持可控时钟测试，并删除二级索引和派生片段。
- 在单独规定加密、保留和删除语义之前，备份与未来同步功能不在当前范围内。
