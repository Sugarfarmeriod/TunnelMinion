# Incident 受控恢复十分钟演示

- 状态：`已完成（PR #97 已合并，CI 8/8）`
- 主写分支：`test/incident-demo`
- 基线：`d5edeb2589bf379dfeff6696fc4b7d81a33c3ee2`
- 对应总流程：`十分钟完整演示`

## 结果与用户影响

开发者可以用一条命令重复观看生产观察器处理模拟监听证据后，从 Incident 和 Skill 证据到目标节点批准、
执行、请求端验证及到期清理的同一条链路。输出直接展示模拟边界、事件标识、证据覆盖、候选计划、批准前
无写和清理后资源归零。

## 当前证据与缺口

- 已有：Incident 到候选计划和独立的目标授权、执行、验证、清理测试均已存在。
- 缺口：原有纵切停在提交，无法证明同一 Incident、计划和 `operation_id` 完成后半程。

## 范围

- 本阶段完成：扩展现有纵切，复用生产对象、SQLite、内存秘密存储和既有测试替身；提供开发者命令和中文
  阶段输出。
- 本阶段不做：真实模型、真实双机、实际私网服务、生产网络配置变更、新 CLI、新框架或新依赖。

## 依赖与顺序

```mermaid
flowchart LR
    A["真实观察与 Incident"] --> B["Skill 证据 4/4"] --> C["候选计划提交"]
    C --> D["目标本地批准"] --> E["执行与请求端验证"] --> F["到期清理归零"]
```

## 完成标准

- [x] 用户可见主路径可重复运行。
- [x] 未批准执行被拒且写适配器调用为 0。
- [x] 同一链路批准、执行、验证与到期清理成功。
- [x] 输出事件标识、Skill 证据覆盖、计划、验证和资源归零结果。
- [x] 定向验证与必要门禁通过。
- [x] PR 合并，路线图与本页结果已回写。

## 实施记录

- 沿现有 `RequesterOperationService`、`TargetOperationGatewayService`、`OperationControlService` 和
  `OperationWorkflow` 串联，没有复制生产状态机。
- 目标提交和批准使用实际服务 API；没有手工构造 `AUTHORIZED` 记录。
- 进程间网络、模型、共享适配器和健康响应仍为确定性测试替身，演示输出和指南明确标注该边界。

## 完成结果

- 演示命令：见 [`../../guide/incident-demo.md`](../../guide/incident-demo.md)。
- 本地门禁：纵切及相邻操作工作流、请求端测试 `23 passed`；Ruff 和 Pyright 通过。
- PR：[#97](https://github.com/Sugarfarmeriod/TunnelMinion/pull/97)；首个实现提交：`cdd1910`。

- 最终实现 head：`63268362dcadde6dd3fe27f4e6fca4702721daf3`；合并提交：`6fb73d4ac6c00fdd69ecf1024143abe4a0442247`。
- [远端 CI 36900227249](https://github.com/Sugarfarmeriod/TunnelMinion/actions/runs/36900227249)：8/8 通过。
- 指南已补十分钟讲解顺序和职责图；本阶段仅隔离开发者演示，不包含真实双机受控恢复验收。
