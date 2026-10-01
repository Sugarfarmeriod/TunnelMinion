# Incident 受控修复串联隔离验收报告

## 结论

本轮在非特权隔离环境中验证了 Incident 来源约束和既有 Operation Runtime 的正常、拒绝、回滚与清理路径。
有效来源能持久绑定到 Operation；无来源的手动操作保持旧 1.0 wire 兼容；来源不存在、证据不足、目标、
端口或最新服务状态不匹配时，会在诊断或远端写入前拒绝。

本报告中的临时 HTTP 共享由 FakeAdapter、MockTransport、临时 SQLite 和内存凭据模拟，不代表真实双机部署。
未修改 WireGuard、防火墙、路由、DNS、生产服务或现有端口进程，也未启动真实私网共享。

## 固定范围

- 分支：`feature/incident-repair-chain`
- 基线：`21d3bfddbdf39db69014537e361448710dd19611`
- 本轮被测实现提交：`f831c0336aa943d4b91d54b8d091b51a9a4d1ce4`
- Python：`3.11.15`
- 前端：锁定的 Node/npm 依赖环境
- 操作定义：既有 `share_local_http_service`，等级 L2

## 可重复纵切入口

```powershell
uv run --frozen pytest --no-cov `
  tests/evaluation/test_incident_repair_chain.py `
  tests/operation/test_requester.py::test_incident_source_is_verified_and_persists_with_operation `
  tests/operation/test_requester.py::test_invalid_incident_source_stops_before_diagnostics_or_remote_write `
  tests/operation/test_requester.py::test_incident_source_requires_latest_snapshot_and_matching_realtime_endpoint `
  tests/operation/test_requester.py::test_authorized_execute_captures_memory_token_and_proxies_get_head `
  tests/operation/test_requester.py::test_execute_bind_unknown_and_authorization_fail_closed `
  tests/operation/test_workflow.py::test_success_is_independently_verified_and_expires_without_model `
  tests/operation/test_workflow.py::test_expired_or_missing_authorization_never_reaches_adapter `
  tests/operation/test_workflow.py::test_service_change_execution_failure_and_verification_failure_roll_back `
  tests/operation/test_workflow.py::test_cleanup_failure_is_visible_and_blocks_false_success `
  tests/operation/test_workflow.py::test_revoke_and_recovery_clean_without_replaying_write -q
```

## 场景与证据

| 场景 | 期望 | 结果 |
|---|---|---|
| 已确认且证据完整的 `local_only` 来源 | 来源写入计划，提交一次，SQLite 重读仍存在 | 通过 |
| 实际服务观察产生 TCP 来源并完成调查 | 实时 HTTP 计划重算同一监听端点后提交 | 通过 |
| 来源不存在、证据不足、目标或端口错误 | 诊断和远端提交前拒绝 | 通过，调用数均为 0 |
| 最新快照已无来源服务 | 诊断前拒绝 | 通过 |
| 实时诊断监听地址与来源端点不同 | 远端提交前拒绝 | 通过，提交调用数为 0 |
| 无来源计划发往旧 1.0 wire | 只省略新增的空来源字段 | 通过；有来源字段仍保留 |
| 目标节点已批准 | 请求端执行一次并沿回调独立验证 | 通过 |
| 未批准或批准过期 | 不触达写适配器 | 通过 |
| 服务指纹变化、执行失败或验证失败 | 回滚自有临时资源，不报假成功 | 通过 |
| 清理失败或所有权不匹配 | 状态为 `cleanup_failed` 并给出人工动作 | 通过 |
| 成功后到期或主动撤销 | 清理资源与内存凭据，不重放执行 | 通过 |

本轮修复定向回归结果：`38 passed`；其中实际观察、调查、来源校验和操作提交的单条串联入口为
`tests/evaluation/test_incident_repair_chain.py`，结果 `1 passed`。

## 门禁结果

- 来源服务单模块覆盖率：`100%`，`292` statements、`60` branches。
- 本轮修复定向回归：`38 passed`。
- 前端全量：`110 passed`。
- 前端类型检查与生产构建：通过；保留既有单包超过 500 kB 提示，本阶段未引入拆包工作。
- 全仓 Ruff：检查通过，`365 files already formatted`。
- 全仓 Pyright：`0 errors, 0 warnings`。
- 固定本机接口基线：`2 passed`；OpenAPI 新指纹为
  `db28b3944b45832723fc69b51469a60a6b058d864781c027855c1d01dc604c13`。
- 运行时打包定向测试：`6 passed`（使用锁文件既定 `package` 依赖组）。
- 后端全量：`1531 passed, 6 skipped`，statement 与 branch coverage 均为 `100%`；唯一告警为
  Starlette TestClient 对当前 httpx 兼容层的既有弃用提示。

独立审查针对被测提交 `f831c0336aa943d4b91d54b8d091b51a9a4d1ce4` 给出 `APPROVE`，无遗留阻断。
审查接受的能力边界是：Incident 提供历史来源，最新快照确认该稳定 TCP 端点仍存在，实时诊断确认当前
HTTP 应用候选与监听端点，执行前实时指纹和目标授权保护当前操作。当前数据不证明历史进程连续性，也不
检测历史同端口换进程。

报告生成时，本地分支因 TLS 握手故障尚未推送到远端：默认 Schannel 最近一次返回
`schannel: failed to receive handshake, SSL/TLS connection failed`；按授权进行的一次非持久化 OpenSSL
后端尝试返回 `TLS connect error: error:00000000:lib(0)::reason(0)`。未关闭证书验证，也未修改网络、代理、
防火墙或 Git 全局配置；因此远端 CI 尚未启动，本报告不把本地门禁写成远端 CI 结果。

## 产品边界

该串联只创建 TunnelMinion 自有、限时、限请求节点的临时入口。它不修改原服务监听地址，因此“恢复访问”
是可撤销缓解，不是原服务配置根治。模型仍不能直接触达写适配器，Incident 也不能替代目标节点授权。
有来源的新字段不承诺兼容旧节点；只有无来源手动路径保持旧 1.0 wire 兼容。
