## Context

现有 `DeterministicServiceObserver` 已能通过 Windows 只读适配器生成有界服务快照，`IncidentObservationService` 也会周期性比较 Overview；但服务观察循环只随已 enrollment 的 managed runtime 启动。默认未配置 Coordinator 的 Windows 产品因而只有本机节点、没有本机服务事实。

## Goals / Non-Goals

**Goals:**

- 让 Windows 默认运行时复用既有只读服务观察，不依赖 Coordinator 或模型配置。
- 让首份真实快照成为 incident 基线，后续稳定变化才触发事件。
- 保留现有预算、脱敏、零模型正常刷新与 lifespan 停止语义。

**Non-Goals:**

- 不改 macOS、远端目录、真实模型、网络配置或 incident 处理审批。
- 不增加观察器、工具、依赖、通用事件总线或新的运行时配置界面。

## Decisions

1. 复用 `DeterministicServiceObserver` 和 `ServiceSnapshotCache`，不建立第二套采集或服务合同。
2. 当 managed runtime 已提供服务缓存时继续复用它；仅在没有 managed coordinator 时，由 incident 周期在组装快照前刷新默认本机缓存。这样没有两个并发采集循环，也不访问 Coordinator。
3. 为 Overview 增加可选本机服务快照来源，默认仍读取 managed cache；Windows 默认应用显式传入复用或独立缓存。API schema 不变。
4. 刷新失败时不发布部分快照，也不把旧缓存伪装成新事实；后台循环的既有失败传播语义保持不变，本 change 只验证成功路径和模型未配置降级。

## Risks / Trade-offs

- [启动时把已有服务误报为新增] → 首次刷新先填充本机缓存，再由 incident 服务建立基线。
- [managed 与默认观察重复采集] → managed coordinator 存在时不注入独立刷新回调。
- [本机服务变化产生噪声] → 继续使用现有两次确认、稳定去重和 30 秒周期，不新增规则引擎。
- [Windows 实现先于 macOS] → 本 change 明确限于已完成正式包体验验收的 Windows；跨平台行为另行验证后再扩展。

## Migration Plan

应用升级后自动开始 Windows 本机只读观察；数据库和 API 无需迁移。回滚代码即可恢复为 managed-only 服务数据源，既有 incident 与快照仍可读取。

## Open Questions

无。
