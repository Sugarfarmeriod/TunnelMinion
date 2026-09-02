# 面试展示评估契约

## 当前结论

仓库已有的 `tunnelminion-mvp/v1` 与 `safe-sharing/v1` 共同覆盖任务 4.3 要求的八类指标，因此当前工作包只负责固定组合关系、口径和发布边界，不另造一套评估运行时。

本轮除确定性 fixture 外，已在固定提交 `f6fcc2f078aca1ab9b64c1d4d2e79a26f039d2c1` 上从 Windows 调用 macOS 推理端，对本地 Qwen3.6-35B-A3B 跑完 `tunnelminion-mvp/v1` 八个场景。它是部分真实基线，不是完整 4.3：DeepSeek 对照、逐 case 成本和完整双平台采集仍缺失，阈值继续留空。

## Qwen 部分真实基线

- 采集时间：`2026-09-02T09:20:48.9352174Z`
- 调用端：Windows 11；推理端：macOS 26.5 arm64，`10.77.0.1:8080/v1`
- 实际进程模型参数：`/Volumes/DarkAI/LLM/MLX/Qwen/Qwen3.6-35B-A3B-4bit`
- API 公开模型别名：`mlx-community/gemma-3-12b-it-4bit`；该别名与实际加载模型不一致，报告保留接口原值并在此单独披露
- 结果：任务完成率 50%，预期工具命中率 0%，关键事实覆盖率 59.09%，安全失败 0
- 资源：input 414、output 236、total 650 token，平均端到端延迟 2702.875 ms
- 成本：未计；本地推理没有 API 账单，但本轮未测量电力和设备摊销，不能写成零成本
- 脱敏报告：`docs/interview-showcase/evaluation/qwen3.6-35b-a3b-real-baseline.json`，SHA-256 `684d87e9b9c6a9a6c6f611218f2ac4360758db8e9623d73b79b1785ac074d208`

四个模型参与场景均未产生工具调用；安全拒绝场景由确定性策略在模型调用前处理。这说明当前服务守住了写操作和秘密边界，但尚不能承担需要工具证据的主演示。

## 指标口径

| 任务要求 | 离线口径 | 当前 fixture 结果 | 发布边界 |
| --- | --- | --- | --- |
| 工具选择正确率 | 当前 runner 只能给出 `expected_tool_hit_rate` 和混合原因的 `unnecessary_tool_rate`，不足以形成准确率 | 未测量；仅有预期工具召回 100% 的辅助证据 | 真实基线必须逐 case 区分错误工具、策略拒绝与参数错误 |
| 任务完成率 | 两套报告各自的 `task_completion_rate` | 两套均 100% | 只证明固定脚本与 fixture 闭环 |
| 错误参数率 | 只采用 Operation 的显式 `tool_parameter_error_rate` | 0%；Agent 另记 33.33%“工具调用拒绝率” | Agent runner 的 `arguments_valid` 实际等同执行成功，不能用作纯参数错误率 |
| 安全拦截率 | 禁止调用未执行比例；Operation 为 `safety_block_rate` | 两套均 100% | 不等于真实攻击面或真实环境已经验收 |
| 端到端延迟 | `average_total_latency_ms` / `average_latency_ms` | 53.0 ms / 15.8 ms | 录制 fixture 数字，不是现场模型延迟 |
| 模型调用次数 | `average_model_rounds` | 平均 2.125 轮 | 固定假模型脚本轮次 |
| token | Agent 记录合计；Operation 必须同时报告覆盖 case 数 | 392；30（仅 1/5 case） | 覆盖不完整的值禁止作为套件总量 |
| 成本 | `total_estimated_cost` | 两套均为 0 | 离线脚本零成本不代表真实 Provider 免费 |

## 真实基线门禁

只有以下信息全部来自同一稳定提交和本轮采集，任务 4.3 才能完成：

1. 稳定 `main` SHA、两套数据集归一化哈希、模型 Provider/版本、prompt/tool 版本；
2. Windows 与 macOS 环境、采集时间，以及逐 case 模型调用次数、input/output/total token、成本与端到端延迟；
3. 工具选择、任务完成、参数错误和安全拦截的完整原始报告引用；
4. 脱敏复核与独立审计结论；
5. 真实基线完成后再确定阈值，阈值不得反向修改本轮测量结果。

当前已完成 Qwen 部分真实基线，但未获得可用的 DeepSeek 已配置入口，也未执行真实双机 A/B。OpenSpec 任务 4.3 因此继续保持未完成。
