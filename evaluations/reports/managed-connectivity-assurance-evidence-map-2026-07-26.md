# 受管连接第 9 阶段证据映射

| OpenSpec 任务 | 场景或指标 | 自动化证据 | 结论 |
|---|---|---|---|
| 9.1 | 地址冲突、签名篡改、跨节点重放、策略扩权、部分成功、回滚失败、所有权冲突、控制面离线 | `evaluations/datasets/managed-connectivity-assurance-v1.json` | 固定 case ID，数据集不含地址、endpoint 或秘密 |
| 9.2 | 收敛、direct/relay/static 选择、错误参数、安全拦截、回滚、切换、延迟、资源成本 | `scripts/run_managed_connectivity_assurance.py` 与 JSON 报告 | 全部指标由固定观测计算，不以模型文本为真值 |
| 9.3 | 模型启用/禁用不变量 | `model_disabled` 与 `model_enabled` 完整 `OperationalObservation` 相等比较 | Provider 计划、授权、执行、验证、回滚、路径和状态必须一致；只单列解释 token/延迟/成本 |
| 9.4 | 威胁、数据、架构、ADR、恢复与卸载 | `docs/security/`、ADR-0007、架构和受管连接恢复手册 | 明确用户资源、秘密、控制面、Provider、relay 和人工干预边界 |
| 9.5 | 安全扫描、导出与卸载 | 网络契约/账本测试、`tests/test_operations.py`、平台 Provider remove/recover 测试 | 未知字段失败关闭；导出不含秘密引用；卸载不递归误删用户资源 |
| 9.6 | OpenSpec 到自动化与证据 | 本表、固定数据集、单测、隔离 fake Provider 与报告 | 离线证据和第 10 阶段真实 A/B 证据严格分开 |

## 不能由本报告证明的内容

- 没有执行真实 WireGuard、route、防火墙或端口写入。
- 没有证明 Murus 的 `18881-18889` 规则具体包含 UDP 入站。
- 没有三节点 relay 数据面、安全或性能证据；relay 继续属于独立 change。
- 没有证明真实 A/B 清理后的不变性；该证据只能在用户明确授权第 10 阶段后产生。
