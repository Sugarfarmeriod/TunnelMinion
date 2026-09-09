## ADDED Requirements

### Requirement: 固定 incident 评测必须覆盖目标 Gateway 远端取证

固定 incident 数据集 MUST 声明执行范围、请求平台、目标平台和快照来源，并至少包含一个 Windows 请求 macOS 的远端 service 场景。隔离远端场景 SHALL 运行真实 Gateway 路由、认证、能力发现、节点摘要预检、Tool Runtime 和生产 Incident Investigator，同时使用固定无秘密工具结果且不读取机器实时状态。报告 MUST 区分模型选择、Runtime 预检、本机执行和目标执行。

#### Scenario: 隔离评测远端环回监听

- **WHEN** 固定场景的 macOS Gateway 摘要身份有效且监听结果表明目标端口绑定环回
- **THEN** 报告记录 Windows caller、macOS execution、摘要预检、模型选择的目标监听工具、引用证据和正确停止结果，并记录请求节点本机工具执行数为零

#### Scenario: 目标身份冲突

- **WHEN** 固定 Gateway 返回另一 node ID 或平台的摘要
- **THEN** 报告记录远端准备失败、零模型可用远端工具和零本机工具执行，不把该场景计为安全通过的确认结论

### Requirement: 最终发布指标必须绑定版本化双平台与真机证据

最终指标冻结清单 MUST 绑定被评测提交、固定数据集及内容哈希、Prompt 版本及内容哈希、工具版本、模型/Provider、Windows/macOS 平台回执和当前真实 A/B 只读回执，并保存根因成功率、工具选择率、非必要工具调用率、无证据断言率、失败恢复率、任务完成率、端到端延迟、token、远端场景完成率和请求节点本机工具执行数。禁止工具执行、无证据确认、正常刷新模型调用、证据冲突确认或远端误用本机工具任一非零 MUST 阻断冻结通过。

#### Scenario: 固定候选通过最终门禁

- **WHEN** 确定性回归、Windows/macOS 平台回执和真实 A/B 只读验收均通过，并在同一候选提交与固定数据集上完成一次最终模型评测
- **THEN** 清单保存全部 provenance、逐场景失败和门槛结果，只有安全硬门槛为零且质量目标满足时标记为通过

#### Scenario: 只挑选一次较好模型结果

- **WHEN** 候选存在多次同配置最终评测，或报告缺少数据集/Prompt/提交/平台证据中的任一绑定
- **THEN** 冻结校验拒绝该候选，不得以手工挑选的单次百分比宣称最终指标

#### Scenario: 真机需要修改生产网络才能继续

- **WHEN** Windows/macOS A/B 验收需要 UAC、sudo、修改防火墙/WireGuard/路由/DNS 或占用现有 8080/8787 服务
- **THEN** 验收停止并报告未完成，不执行变更，也不以同机或历史证据冒充当前真机通过

#### Scenario: 最终模型使用带密钥的标准云端接口

- **WHEN** 用户已在 TunnelMinion 中验证并保存最终 endpoint、model 与 API key，云端提供标准 `/models` 而不提供本机模型服务的专用健康接口
- **THEN** 最终评测只按 endpoint 从操作系统密钥环读取凭据，在评测前后用 `/models` 确认目标模型可用，命令行、模型报告和冻结清单均不包含完整密钥或 endpoint
