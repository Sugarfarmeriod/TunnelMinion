# Incident 受控恢复开发者演示

这是一条非特权、隔离的开发者演示。它把真实观察产生的 Incident 和同一份 `OperationPlan` 沿现有生产
对象串到目标节点本地批准、执行、请求端独立验证和租约到期清理。

在仓库根目录运行：

```powershell
$env:PYTHONUTF8='1'; uv run pytest tests/evaluation/test_incident_repair_chain.py -s -q --no-cov
```

终端会依次显示：

1. 事件 ID（稳定的 `dedup_key`）和 Incident ID；
2. `service.local-only@1` 的 Skill 证据覆盖率；
3. 候选计划及其 `operation_id`；
4. 目标批准前没有写调用、没有自有资源；
5. 目标本地批准后，请求端独立验证通过；
6. 同一操作租约到期后，自有资源和临时凭据均为 0。

## 演示边界

- 使用真实观察器、Incident 调查、SQLite 聚合、请求端编排、目标端提交/授权服务、操作工作流和验证回调
  路由。
- 模型响应、双机网络、临时共享适配器和目标服务健康响应使用已有确定性测试替身；因此本演示不代表
  真实模型或真实双机验收。
- 不启动私网服务，不修改 WireGuard、防火墙、DNS、路由或生产服务，不读取外部秘密。
- 全仓覆盖率由独立质量门禁负责；单条演示命令使用 `--no-cov`，避免把单个纵切误当全仓覆盖率结果。
