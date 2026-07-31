## 1. 信任路线 spike 与用户决策门

- [ ] 1.1 建立隔离 macOS Gateway、伪 peer、签名/防火墙状态 fixture 和版本化证据 schema，证明测试不读取生产 SecretStore、不修改 Murus/WireGuard/route，也不依赖源码外隐式工具
- [ ] 1.2 在用户明确批准的非生产 executable/端口上验证 `local-firewall-authorization`：记录首次提示、允许/拒绝、精确对象、撤销、终端脱离和第二个 package ID 的升级行为；不得关闭防火墙或添加通配规则
- [ ] 1.3 只读验证 `developer-id-notarized` 前置条件，并用无秘密 fixture 固定 hardened runtime、嵌套 Mach-O 签名顺序、ZIP/PKG 公证、ticket、Gatekeeper 和签名后清单门禁；没有有效 Developer ID 时明确停止真实签名
- [ ] 1.4 对比安全性、用户交互、每版升级成本、外部账户、可撤销性和 A/B 可验证性，取得用户对唯一首发 trust mode 的明确选择，更新 design 并提交/推送决策阶段；未选择时停止实现

## 2. Artifact 身份与只读信任状态

- [ ] 2.1 定义 trust manifest/schema，绑定 package ID、payload/distribution 摘要、入口 SHA-256、签名身份摘要、模式、状态和时间，不允许凭据、完整本机路径或不可信正文
- [ ] 2.2 实现 macOS `codesign`、`spctl`、notarization ticket 和 Application Firewall 的有界只读适配器，统一返回 `trust_mode_required`、`identity_unavailable`、`trust_pending`、`artifact_mismatch` 等稳定错误
- [ ] 2.3 把 trust preflight/status 接入运行包清单与安装状态；清单损坏、artifact 被替换或前置身份缺失时 fail closed，不启动生产 Gateway
- [ ] 2.4 覆盖损坏签名、过期/撤销、路径替换、命令超时、权限不足、恶意工具输出和零秘密日志，运行单元/分支/秘密门禁后提交并推送只读信任阶段

## 3. 所选信任路线的授权执行

- [ ] 3.1 仅实现用户在 1.4 选择的首发 trust mode；每个写动作展示精确 package 摘要并要求明确确认，不在运行时读取或缓存管理员密码、签名私钥或公证认证
- [ ] 3.2 为 `local-firewall-authorization` 实现系统 UI/管理员步骤生成、执行后只读验证和精确撤销，或为 `developer-id-notarized` 实现批准的 Keychain/CI 签名、公证、staple 与 Gatekeeper 验证
- [ ] 3.3 实现幂等、并发、取消、拒绝、部分失败和恢复语义；失败不改变当前 accepted package，不停止既有 Gateway，也不降级为另一种隐式模式
- [ ] 3.4 在隔离包上完成首次授权、撤销、重试和第二版本矩阵，运行平台安全门禁后提交并推送信任执行阶段

## 4. 分层 Gateway 健康与 peer 证据

- [ ] 4.1 扩展状态契约，分别表达 `process_owned`、`listener_owned`、`system_trust` 和 `peer_reachable`，禁止把前三者或单独监听器映射为端到端 accepted
- [ ] 4.2 实现独立 A 端 acceptance runner：固定 peer/node/package 身份，无 Authorization header 请求 `/v1/capabilities`，只保存 `401`、延迟、时间预算和摘要
- [ ] 4.3 实现 `peer_unverified`、`peer_unreachable`、`trust_pending` 与本地进程失败的分域状态；peer 暂时离线不强杀健康自有进程，替换事务未通过则可安全回退
- [ ] 4.4 覆盖监听存在但 flow 挂起、错误 HTTP 状态、超时、错误 peer、响应过大/恶意正文、A 离线和恢复，运行双节点 fake/集成门禁后提交并推送健康证据阶段

## 5. 签名后打包、升级与安全回退

- [ ] 5.1 分离可重复 unsigned payload 清单与 signed distribution 清单，验证嵌套文件、入口、签名身份、ticket、许可清单和安装路径边界
- [ ] 5.2 把信任与 peer 门禁接入 stage/activate/accepted 状态；新版本并行落地，未通过不得覆盖 accepted 指针或生产数据
- [ ] 5.3 实现候选失败后的所有权验证、正常停止、上一入口恢复和 peer `401` 复核，不回滚 SQLite、节点身份、token、refresh 或模型
- [ ] 5.4 覆盖签名后篡改、错误发布者、旧 ticket、新路径、版本替换、PID 复用与回退失败，运行可重复构建/签名/安装/移除门禁后提交并推送升级阶段

## 6. 真实 A/B 生产替换

- [ ] 6.1 取得用户对精确信任动作与短时 Gateway 切换的执行确认，固定执行前 package、配置/SecretStore、进程、Murus、Application Firewall、WireGuard、稳定 route、8082/8787 和零自启动摘要
- [ ] 6.2 在不改 Murus/WireGuard/route 的前提下停止旧 Python Gateway、切换受信任候选并退出控制终端，验证 B 状态四层证据和 A 无 token `401`
- [ ] 6.3 验证重复 start、手动 stop、新会话保持 stopped、手动恢复、第二版本信任行为和失败回退；不执行生产机器重启，不接管外部模型
- [ ] 6.4 对照执行后不变性，评估许可成功率、错误参数率、安全拦截率、状态正确率、恢复成功率、首次/升级交互次数、启动/停止/peer 延迟、CPU/内存、包体积和日志增长

## 7. 文档、质量门禁与交付

- [ ] 7.1 更新安装、首次入站许可、签名/公证、管理员与秘密边界、四层状态、升级、撤销、回退和故障诊断文档，明确没有开机自启且不修改第三方网络配置
- [ ] 7.2 运行 Windows/macOS 全量质量、100% 覆盖率、离线安全评估、仓库/构建/证据秘密扫描、依赖许可、双版本签名和 OpenSpec strict 门禁
- [ ] 7.3 提交并推送最终阶段，创建 PR；合并后解除 `package-manual-node-runtime` 的 macOS B 阻断，同步主规格并归档本 change
