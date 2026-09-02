# 面试展示评估契约

## 当前结论

仓库已有的 `tunnelminion-mvp/v1` 与 `safe-sharing/v1` 共同覆盖任务 4.3 要求的八类指标，因此当前工作包只负责固定组合关系、口径和发布边界，不另造一套评估运行时。

本轮除确定性 fixture 外，已对本地 Qwen3.6-35B-A3B 与 DeepSeek-V4-Flash 跑完相同的 `tunnelminion-mvp/v1` 八场景，并对两者各跑两个 Safe Sharing 候选计划。它仍是部分真实基线：Safe Sharing 的结构化计划均失败，且完整双平台采集和独立审计尚缺，阈值继续留空。

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

## DeepSeek 部分真实基线

- 采集提交：`e4a3c9c3e61511a1df051eec1b39e78acf439603`
- 模型：`deepseek-v4-flash`；调用端：Windows 11；Endpoint：`https://api.deepseek.com`
- 结果：任务完成率 75%，预期工具命中率 100%，关键事实覆盖率 90.91%，安全失败 0
- 资源：input 4004、output 991、total 4995 token，平均端到端延迟 2377 ms
- 成本：按采集时官方离峰缓存未命中价估算上限 `$0.00153494`；逐 case 成本已写入报告
- 脱敏报告：`docs/interview-showcase/evaluation/deepseek-v4-flash-real-baseline.json`，SHA-256 `595476f682727b2393faa34e0d0cc726b3c73b1c1e4463d550c6da6df85e3907`

DeepSeek 明显优于当前 Qwen 服务，但仍有两个失败：prompt injection 场景没有覆盖全部要求事实，loopback PDF 诊断没有形成合格最终答案。因此它适合作为后续修复基线，不能宣称主演示已经达标。

## Safe Sharing 真模型结果

固定提交 `cd6357a` 上，Qwen 与 DeepSeek 的两个候选计划均为 0/2，错误均归因于 `invalid_response` / `prompt_or_model`。没有计划被生成或执行，也没有发生写操作。由于响应在结构化解析前失败，API 未向当前报告暴露 token 与成本；这些结果只能作为失败基线，不能用于发布成功指标。

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

当前已完成 Qwen/DeepSeek 对照与 Safe Sharing 失败基线，但完整双平台采集、Safe Sharing token/成本和独立审计仍缺失。OpenSpec 任务 4.3 因此继续保持未完成。
