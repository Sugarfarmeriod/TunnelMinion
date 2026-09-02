# 面试展示评估契约

## 当前结论

仓库已有的 `tunnelminion-mvp/v1` 与 `safe-sharing/v1` 共同覆盖任务 4.3 要求的八类指标，因此当前工作包只负责固定组合关系、口径和发布边界，不另造一套评估运行时。

本轮除确定性 fixture 外，已对本地 Qwen3.6-35B-A3B 与 DeepSeek-V4-Flash 跑完相同的 `tunnelminion-mvp/v1` 八场景。修复 Safe Sharing 固定键名后，DeepSeek 在同一稳定提交上重新完成八场景和两个候选计划，阈值随后固定并通过只读复算审计。Qwen 保留为未达标对照，不进入发布阈值。

## Qwen 部分真实基线

- 采集时间：`2026-09-02T15:25:54.5920625Z`
- 调用端：Windows 11；推理端：macOS 26.5 arm64，`10.77.0.1:8080/v1`
- 实际进程模型参数：`/Volumes/DarkAI/LLM/MLX/Qwen/Qwen3.6-35B-A3B-4bit`
- API 公开模型别名：`mlx-community/gemma-3-12b-it-4bit`；该别名与实际加载模型不一致，报告保留接口原值并在此单独披露
- 结果：任务完成率 50%，预期工具命中率 0%，关键事实覆盖率 59.09%，安全失败 0
- 资源：input 414、output 236、total 650 token，平均端到端延迟 2724.375 ms
- 成本：未计；本地推理没有 API 账单，但本轮未测量电力和设备摊销，不能写成零成本
- 脱敏报告：`docs/interview-showcase/evaluation/qwen3.6-35b-a3b-real-baseline.json`，SHA-256 `4d47380a199e80b47f9ff56a4930b7e649e4350a63d9518ffd05e53533b54e1d`

四个模型参与场景均未产生工具调用；安全拒绝场景由确定性策略在模型调用前处理。这说明当前服务守住了写操作和秘密边界，但尚不能承担需要工具证据的主演示。

## DeepSeek 发布阈值基线

- 采集提交：`b1e94aaed2b44db57563bcbca4b721d009656550`
- 模型：`deepseek-v4-flash`；调用端：Windows 11；Endpoint：`https://api.deepseek.com`
- 结果：任务完成率 100%，预期工具命中率 100%，关键事实覆盖率 100%，安全失败 0
- 资源：input 4016、output 971、total 4987 token，平均端到端延迟 2358.625 ms
- 成本：按采集时离峰缓存未命中价估算上限 `$0.00152438`；逐 case 成本已写入报告
- 脱敏报告：`docs/interview-showcase/evaluation/deepseek-v4-flash-real-baseline.json`，SHA-256 `6b32b9d2ce0a82095b2a195d9c86b6bbb9e522173057f0fdc1106d4dabcfff8c`

DeepSeek 当前八场景全部完成，并满足下述发布阈值。该结论只证明真实模型只读评估，不外推为真实 A/B 网络写入或最终主演示素材已经完成。

## Safe Sharing 真模型结果

Qwen 在同一稳定提交上的两个候选计划仍为 0/2，继续保留为失败对照。DeepSeek 在 `b1e94aaed2b44db57563bcbca4b721d009656550` 上实测为 2/2：结构化生成率与固定字段安全率均为 100%，共 1683 token、估算 `$0.00063338`。两个计划均未批准或执行，没有发生网络写操作。

## 发布阈值

阈值在上述真实基线完成后固定：工具选择正确率与任务完成率均为 100%，错误参数率为 0%，安全拦截率为 100%，平均端到端延迟不超过 5000 ms，平均模型调用不超过 2 次，八场景总 token 不超过 6000，估算成本不超过 `$0.002`。Safe Sharing 另要求结构化生成率和固定字段安全率均为 100%。

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

1. 不可变采集提交 SHA、两套数据集归一化哈希、模型 Provider/版本、prompt/tool 版本；
2. Windows 与 macOS 环境、采集时间，以及逐 case 模型调用次数、input/output/total token、成本与端到端延迟；
3. 工具选择、任务完成、参数错误和安全拦截的完整原始报告引用；
4. 脱敏复核与独立审计结论；
5. 真实基线完成后再确定阈值，阈值不得反向修改本轮测量结果。

DeepSeek 主评估与 Safe Sharing 已在同一稳定提交采集，逐 case 模型调用、token、成本和延迟字段完整，报告已脱敏并由 `verify_evaluation.py` 只读复算。任务 4.3 的阈值和审计证据已完成；真实 A/B 与最终素材仍由阶段 5 单独门禁。
