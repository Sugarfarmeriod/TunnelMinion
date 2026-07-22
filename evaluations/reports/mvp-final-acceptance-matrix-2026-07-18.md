# TunnelMinion 只读分布式 Agent MVP 最终验收矩阵

日期：2026-07-18

本表把 OpenSpec 场景、自动测试、固定离线评估、真实 Qwen 评估、Windows A / macOS B 真机证据和干净环境生命周期放在一起。结论中的“通过”表示 MVP 的确定性只读边界与交付场景有证据覆盖，不表示当前本地模型在所有自然语言任务上都达到生产质量。

## OpenSpec 场景对照

| OpenSpec 能力域 | 主要场景 | 自动测试证据 | 离线或真机证据 | 判定 |
|---|---|---|---|---|
| 模型 Provider 配置 | 保存与删除配置、秘密留在本机、能力探测、认证/超时失败、安全降级 | `tests/model/`、`tests/test_macos_app.py` | [模型故障隔离](../platform/model-failure-isolation-2026-07-18.json)、[干净环境生命周期](clean-environment-acceptance-2026-07-18.md) | 通过 |
| 节点工具 Runtime | 只读工具注册、拒绝写工具、Schema 校验、超时与结果预算、平台降级、审计 | `tests/tools/`、`tests/platforms/` | [Windows 只读验收](../platform/windows-read-only-acceptance.json)、[macOS 状态不变证明](../platform/macos-readonly-invariance-2026-07-18.md) | 通过 |
| Agent 对话 | 本地环回面板、有界工具循环、取消、轨迹、证据回答、提示注入隔离、线程删除 | `tests/agent/`、`tests/web/`、`tests/test_app.py` | [真实双机人工验收说明](../../docs/guide/真实双机人工验收.md)及脱敏截图 | 通过 |
| 上下文与记忆 | 四类状态隔离、上下文预算、历史压缩、checkpoint 恢复、长期记忆增删改、会话与节点隔离 | `tests/memory/`、`tests/agent/test_conversation.py` | [架构与边界说明](../../docs/architecture.md) | 通过 |
| 跨节点诊断 | WireGuard Gateway 认证、能力发现、超时/取消、服务发现、环回不可达、节点离线、禁止远端写操作 | `tests/gateway/`、`tests/agent/test_remote.py`、`tests/agent/test_diagnostics.py` | [六工具 Gateway 验收](../platform/ab-gateway-acceptance-2026-07-18.json)、[正常诊断](../platform/ab-cross-node-diagnostic-2026-07-18.json)、[失败矩阵](ab-real-failure-matrix-2026-07-18.md) | 通过 |
| Agent 评估 | 版本化数据集、工具与参数评分、事实与证据评分、提示注入/秘密/写操作安全门、性能记录、A/B 真机独立验收 | `tests/evaluation/`、CI 中的 `run_offline_evaluation.py --check` | [首轮真实模型报告](agent-evaluation-2026-07-18.md)、[策略 v2 评分](qwen-mvp-v1-policy-v2-2026-07-18.json)、A/B 真机报告集合 | 通过；保留模型质量限制 |

## 三层验证结果

| 验证层 | 结果 | 它证明什么 |
|---|---|---|
| 确定性自动测试 | Windows 本地运行 216 项测试全部通过，源码与分支覆盖率 100%；Ruff、Pyright 和格式检查通过 | 代码路径、协议、安全边界和平台降级行为可重复 |
| 固定离线评估 | `tunnelminion-mvp:v1` 使用假模型固定响应通过 `--check` 安全门 | CI 不依赖外部模型，也能阻止禁止工具执行、参数无效和证据冲突回归 |
| 真实 Qwen 固定数据集 | 策略 v2：期望工具命中率 100%，非必要工具率 0%，参数有效率 100%，禁止工具尝试/执行 0/0，安全失败 0，任务完成率 75%，证据一致率 100% | 确定性策略修复了首轮安全失败；自然语言完成度仍不是 100% |
| A/B 真机 | A 经 WireGuard 调用 B 的六个只读工具；覆盖正常服务、环回服务、节点离线、Docker 不可用、模型失败隔离和恢复 | 不只验证 fixture；真实网络、Gateway、平台采集、模型和故障恢复可协同工作 |
| 干净环境生命周期 | Windows/macOS 均完成隔离安装、启动、无模型降级、Gateway、停止、卸载和数据清理 | 项目不是只在开发目录内偶然可运行，且卸载不会残留临时数据 |

## 安全与恢复检查

- 仓库安全扫描未发现 API Key、Gateway token、Bearer 凭据或私钥。
- Gateway 未认证请求稳定返回 401；应用凭据与 WireGuard 私钥分离。
- 远端能力清单只包含固定版本的只读工具；写操作请求没有对应工具可执行。
- 故障注入结束后，正式 macOS Gateway 已恢复到 `10.77.0.1:8787`，Docker 数据源为 `available`，原有容器计数为 3，节点与模型状态为 `ready` / `available`。
- 临时容器、临时 token、临时数据目录和临时监听进程均已清理。

## 已知限制

- macOS 在当前普通用户权限下无法读取完整监听进程和 WireGuard peer 明细，因此相关数据明确标为 `degraded` / `permission_denied`，不会编造结果。
- 本地 Qwen 策略 v2 的任务完成率为 75%，仍需继续改进回答完整度与多次运行稳定性；这不会绕过 Runtime 的确定性安全边界。
- 本地 Provider 没有价格信息，因此成本为未知；模型延迟会随本机负载波动。
- MVP 严格只读：不会开放端口、重启服务、修改 WireGuard、控制容器或执行远端命令。

## 发布结论

OpenSpec 中本次只读分布式 Agent MVP 的场景均有自动化、离线评估或真实 A/B 证据对应；Windows/macOS 干净环境生命周期与故障恢复已完成。该分支满足进入 Pull Request 审阅的 MVP 验收条件，已知限制已明确保留，不以模型偶发的漂亮回答替代确定性测试。
