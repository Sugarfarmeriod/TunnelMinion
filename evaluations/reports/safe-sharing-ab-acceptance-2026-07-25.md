# 临时共享本机服务 A/B 真机验收记录（2026-07-25）

## 结论

本轮在 Windows A（`10.77.0.2`）与 macOS B（`10.77.0.1`）完成真实双节点验收：

- 逐次批准链路从只读诊断、真实模型候选计划、B 本地批准、入口创建、A 回调验证、Windows 回环浏览器桥访问，一直到租约到期自动清理，全部通过。
- 精确预授权在同一 peer、工具、服务 ID、服务指纹、端口、时长和有效期内自动命中；端口越界后重新进入 `awaiting_authorization`。
- 错误凭据、端口占用、服务进程替换、A 离线、验证失败和 B 重启均保守失败或恢复，没有误报成功。
- 验收前后，正式 `5984/8082/8787/8888` 监听记录一致，Docker 运行摘要 SHA-256 一致。
- 隔离数据完成卸载，B 的 `18880–18889` 无残留监听；临时凭据和代码归档已删除。

## 固定端口与隔离边界

| 用途 | 地址 | 说明 |
|---|---|---|
| HTTP fixture | B `127.0.0.1:18880` | 仅 B 回环，不经过 Murus |
| 临时共享入口 | B `10.77.0.1:18881–18888` | Murus 已由节点所有者预先放行 |
| 隔离验收 Gateway | B `10.77.0.1:18889` | 独立数据目录、Node ID 和应用凭据 |
| 验证回调 | A `10.77.0.2:18900` | B 把一次性访问凭据交给 A 内存验证器 |
| 浏览器桥 | A `127.0.0.1:18901` | 凭据不进入 URL、日志或浏览器存储 |

正式 `8787` Gateway、模型 `8082`、Docker 服务 `5984/8888` 没有被停用、复用或改配。TunnelMinion 未修改 Murus、WireGuard、路由、Docker 或用户服务。

## 标志性逐次批准场景

机器可读证据：

- 候选计划：[`safe-sharing-ab-submit-success-2026-07-25.json`](safe-sharing-ab-submit-success-2026-07-25.json)
- 执行与到期：[`safe-sharing-ab-execute-success-2026-07-25.json`](safe-sharing-ab-execute-success-2026-07-25.json)

结果：

1. A 经认证读取 B 的监听、进程和 Docker 证据，只选中 `127.0.0.1:18880`。
2. 本地 Qwen 生成 L2 候选计划，用时 `11.847s`、`1029 tokens`；节点、工具、端口、时长和证据引用由确定性代码固定。
3. B 本地 CLI 逐次批准后，创建 `10.77.0.1:18883` 临时入口。
4. B 通过 A 的 `18900` 回调发起真实验证；验证结果为 `passed`。
5. A 的 `127.0.0.1:18901` 浏览器桥返回 HTTP `200`、`2959` 字节。
6. 15 秒后最终状态为 `expired`，入口自动清理。

## 精确预授权场景

机器可读证据：

- 预授权命中：[`safe-sharing-ab-submit-preauthorized-2026-07-25.json`](safe-sharing-ab-submit-preauthorized-2026-07-25.json)
- 自动执行与到期：[`safe-sharing-ab-execute-preauthorized-2026-07-25.json`](safe-sharing-ab-execute-preauthorized-2026-07-25.json)
- 端口越界：[`safe-sharing-ab-submit-out-of-scope-2026-07-25.json`](safe-sharing-ab-submit-out-of-scope-2026-07-25.json)

B 本地预授权同时约束临时 A Node ID、`share_local_http_service`、服务 ID、服务指纹、仅 `18884`、最长 15 秒和 120 秒授权有效期。范围内计划提交后直接为 `authorized`，执行、浏览器访问和到期清理通过；相同服务改用 `18885` 后状态为 `awaiting_authorization`，没有自动执行。

## 故障注入

脱敏汇总见 [`safe-sharing-ab-failures-2026-07-25.json`](safe-sharing-ab-failures-2026-07-25.json)。

| 场景 | 真实结果 | 安全行为 |
|---|---|---|
| 错误 Gateway 凭据 | HTTP `401` | 未进入能力发现或操作流程 |
| 入口端口被占用 | `rolled_back / execution_failed` | 未删除占位进程；测试结束后由验收脚本清理 |
| 计划后替换服务 PID | `rolled_back / service_changed` | 执行前重新读取监听 PID/进程并拒绝旧指纹 |
| A 不提供验证回调 | `rolled_back / requester_offline` | 已创建入口立即按所有权清理 |
| 上游健康路径返回 404 | `rolled_back / verification_failed` | 没有把“代理已启动”误报为最终成功 |
| B 在活跃租约中重启 | `rolled_back / cleanup succeeded` | 启动恢复不重放写操作，立即收敛持久化状态 |
| 清理异常与所有权冲突 | 自动化注入通过 | 进入 `cleanup_failed`，不删除未知资源 |

真实故障注入同时发现并修复了五个 Harness/运行时缺口：

1. macOS 普通用户下 `psutil.net_connections()` 权限不足，改为固定参数、无 Shell 的只读 `lsof` 降级。
2. 跨节点时钟偏差会使状态历史倒退，改为由目标节点时钟记录服务端状态。
3. 指定端口诊断过去仍顺序探测最多 32 个无关端口，现只探测目标端口，并把已认证远端工具成功计入节点在线证据。
4. Uvicorn 入口就绪不再依赖 Mac 对自身 WireGuard 地址的自连；绑定就绪由 Uvicorn 状态确认，最终可用性仍必须由 A 回调验证。
5. 活跃租约期间 B 重启后，启动恢复立即回滚 `succeeded` 记录，不再保留“状态成功但进程已消失”的窗口。

## 模型表现与 API 判断

原始真实模型评估为 2/2 结构化计划成功、固定字段安全率 100%，平均 `7.682s`。首次完整 Agent 链路同时调用“诊断解释”和“结构化计划”，诊断解释在 120 秒超时，而计划仍成功，总耗时 `140.996s`。移除已确认发布场景中的重复解释调用后，后续真实计划耗时为 `8.471–14.352s`。

因此当前本地 Qwen 的计划质量足够，外部 API 不是安全或功能上线的必需条件。若需要更快的自然语言解释，可以把 API 作为可选 Provider；节点、证据、L2 等级、授权、服务指纹、端口范围、执行和回滚仍必须由本地确定性 Harness 控制，不能交给 API 决定。

## 清理与残留检查

- B 使用 `uninstall --confirm DELETE-TUNNELMINION-DATA` 删除 6 个自有数据项。
- A 使用同一卸载入口删除 3 个自有数据项。
- B 的临时 Gateway、fixture、占位服务、源代码目录和传输归档已删除。
- A 的临时 Node 数据、验收凭据、基线临时文件和传输归档已删除。
- B `18880–18889` 无监听。
- 正式监听记录和 Docker 摘要与操作前基线一致。
- `docs/questions/` 未读取、修改、暂存或提交。

## 已知边界

- 首版只支持环回明文 HTTP 上游，不支持通用 TCP、HTTPS 终止、WebSocket 和任意网络转发。
- 临时访问凭据只在 A 进程内存中存在；独立产品化浏览器会话、企业 RBAC 和公共 SaaS 不在本变更范围。
- 清理失败和资源所有权冲突使用自动化故障适配器覆盖；真实验收没有故意制造无法回收的未知系统资源。
- Murus 规则由 Mac 节点所有者管理；TunnelMinion 只使用已明确放行的 `18881–18889`，不会自行开防火墙端口。
