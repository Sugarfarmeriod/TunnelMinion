# TunnelMinion A/B 真机失败矩阵

日期：2026-07-18

拓扑：Windows A `10.77.0.2` 请求 macOS B `10.77.0.1:8787`。所有报告均排除 Gateway
token、Authorization 头、API Key、WireGuard 私钥和原始工具正文。

| 场景 | 故障注入或真实状态 | 确定性结果 | 模型行为 | 恢复证据 |
|---|---|---|---|---|
| 远端服务发现 | 正常 Gateway 与 Docker | 5984/8888 `reachable`；80/443 `unreachable` | 解释端口证据和监听权限不足 | 正常运行 |
| 环回服务 | 临时容器仅发布 `127.0.0.1:18080` | `local-only`，容器端口 3000 | 明确只解释、不执行修复 | 临时容器已停止并由 `--rm` 删除 |
| 节点离线 | 临时停止 B Gateway | `node_unreachable`，约 2.1 秒返回 | 未调用模型，不编造服务 | Gateway 重新启动 |
| Docker 不可用 | Gateway 临时使用不存在的 `DOCKER_HOST` | 节点摘要成功；监听与 Docker 来源 unavailable | 明确无法确认服务，保留未知 | 正常 Gateway 恢复，Docker available、3 个原有容器 |
| 单节点模型失败 | 临时删除 A 的无 Key 模型配置 | AI run 503；本地资源和 A→B Gateway 仍 success | 模型层不可用不拖垮工具层 | Qwen 恢复 available，AI run 200 |

## 脱敏证据

- [正常服务发现](../platform/ab-cross-node-diagnostic-2026-07-18.json)
- [环回诊断](../platform/ab-loopback-diagnostic-2026-07-18.json)
- [节点离线](../platform/ab-node-offline-2026-07-18.json)
- [Docker 不可用](../platform/ab-docker-unavailable-2026-07-18.json)
- [模型故障隔离](../platform/model-failure-isolation-2026-07-18.json)
- [恢复后的六工具 Gateway 验收](../platform/ab-gateway-acceptance-2026-07-18.json)

## 恢复后状态

- B Gateway 再次监听 `10.77.0.1:8787`。
- `get_node_summary` 返回 macOS、Agent ready、模型 available、6 个允许工具。
- `list_docker_services` 返回 available，原有容器计数为 3。
- 临时 `tunnelminion-loopback-acceptance` 容器不存在。
- WireGuard 仍为权限降级状态；验收没有修改 WireGuard 配置、路由或私钥。

该矩阵记录成功和失败场景，不把“没有崩溃”当成任务完成。每个失败场景都要求稳定错误码、未知项
或确定性分类，并记录故障注入后的恢复证据。
