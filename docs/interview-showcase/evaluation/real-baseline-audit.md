# 真实模型基线只读复算审计

## 审计结论

审计结论：通过。DeepSeek 主评估与 Safe Sharing 来自同一不可变提交；Qwen 修正后的主评估与 Safe Sharing 来自同一身份门禁提交。逐 case 资源字段按各 Provider 实际可得范围记录，八项发布阈值均在 DeepSeek 测量完成后设置并由校验器从原始报告复算通过。

该提交位于 `feature/interview-showcase`，不是 `main`；因此本结论只覆盖 OpenSpec 任务 4.3 的真实模型评估，不证明真实双机网络写入、Stage 6 A/B、最终截图、录屏或主线发布已经完成。

## 固定证据

- DeepSeek 稳定提交：`b1e94aaed2b44db57563bcbca4b721d009656550`
- Qwen 身份门禁提交：`d99fda89e38a002209a81545fa9d3fd310d9671d`
- 主评估报告 SHA-256：`6b32b9d2ce0a82095b2a195d9c86b6bbb9e522173057f0fdc1106d4dabcfff8c`
- Safe Sharing 报告 SHA-256：`738910d81188d39dfb37bfeb647f26bb9e7ec3ed2e46bb2698fd6953122d56b4`
- Qwen 跨平台主报告 SHA-256：`1accfcba331fcbeae133e8b69731d6ab9a9e5730e9fd1a47a7f1adb8b4ba6243`
- Qwen Safe Sharing 报告 SHA-256：`ca266d4c81204b81c72635f00d2f5dcdd78bb60ef63b829658694fed1c3ae2cc`
- 数据集：`tunnelminion-mvp/v1`，8 个场景；Safe Sharing 真实候选计划，2 个场景
- 环境：Windows 11 调用 DeepSeek API；Safe Sharing 只生成未授权候选计划，没有执行网络操作

## 复算结果

| 指标 | 实测 | 阈值 | 结果 |
| --- | ---: | ---: | --- |
| 工具选择正确率 | 100% | ≥ 100% | 通过 |
| 任务完成率 | 100% | ≥ 100% | 通过 |
| 错误参数率 | 0% | ≤ 0% | 通过 |
| 安全拦截率 | 100% | ≥ 100% | 通过 |
| 平均端到端延迟 | 2358.625 ms | ≤ 5000 ms | 通过 |
| 平均模型调用次数 | 1.75 | ≤ 2.0 | 通过 |
| 8 场景 token | 4987 | ≤ 6000 | 通过 |
| 8 场景估算成本 | $0.00152438 | ≤ $0.002 | 通过 |

Safe Sharing 结构化生成率与固定字段安全率均为 100%（2/2），共 1683 token，估算成本 `$0.00063338`。prompt injection 用例仍保持服务端固定的节点、端口、L2 等级和工具名。

## 审计方法

`verify_evaluation.py` 不采用 suite 中手填的实测值作为结论，而是重新读取原始报告、校验 SHA-256、核对报告请求模型与 manifest 实际模型完全一致、检查逐 case token/成本/延迟字段、复算八项指标并逐项比较阈值。Qwen 失败基线只作为对照，不进入本次发布阈值。
