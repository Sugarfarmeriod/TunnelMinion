# Coordinator A/B 场景、测试、证据与任务对照

## 结论

2026-07-26 在 Windows A（`10.77.0.2`）和 macOS B（`10.77.0.1`）完成隔离迁移验收。
Coordinator 只绑定 A 的 WireGuard/环回地址，B 只临时使用 `18888`。生产模型 `8082`、
Gateway `8787` 与临时端口状态前后不变。

## 对照

| OpenSpec 任务 | 场景与自动测试 | 真机证据 | 结果 |
|---|---|---|---|
| 9.1 | Coordinator 双应用绑定校验；拒绝环回/通配 Agent 地址和非环回管理员地址 | 报告 `bindings` | 通过 |
| 9.2 | 注册、心跳、完整快照、full-sync、目录新鲜度测试 | `registration_order`、`remote_ready`、`before/after` | 通过 |
| 9.3 | 动态目录过滤、assertion、直连能力复核和远端执行测试 | `assertion_diagnostic`、`managed_flow` 与两个 `tool_run_id` | 通过 |
| 9.4 | token 重放、撤销、缓存过期、协议不兼容、服务 stopped 数据集 | `enrollment_replay_status=401`、`fault_matrix`、`service_state=stopped` | 通过 |
| 9.5 | static/managed 共存、无模型资源 API、操作到期/撤销/恢复自动测试 | `static_fallback`；既有临时共享 A/B 报告与失败矩阵 | 通过 |
| 9.6 | 架构、ADR、威胁模型、数据分类、运维、验收、路线图、演示文档 | 本报告及对应文档链接 | 通过 |
| 9.7 | OpenSpec 场景、460 项自动测试、真机 JSON、综合评估与最终门禁 | 本地总门禁、CI/PR Checks 与提交记录 | 本地通过，待 CI 确认 |

## 故障矩阵解释

- enrollment token 改变身份后重放返回 401，完整 token 不进入报告。
- A 被撤销后不能再获取可用 managed 身份；B 的缓存到期后旧 assertion 返回 401。
- Coordinator Agent/Admin 监听停止后，生产 static `8787` 仍能运行固定只读工具。
- 请求 Gateway 协议主版本 2 返回 409，不做模糊兼容。
- managed 隔离 Gateway 的监听器和节点摘要均成功，并分别保留 `tool_run_id`。
- static Docker 工具在 Docker 不可用时结构化失败，其余五项成功；节点和 Gateway 不被拖垮。

## 数据最小化

JSON 不包含 enrollment、refresh、assertion、Authorization header、签名私钥、Gateway
static token、WireGuard 私钥、完整监听/进程/Docker 正文或模型业务正文。PID 只指向验收时
临时进程，清理后不可复用。
