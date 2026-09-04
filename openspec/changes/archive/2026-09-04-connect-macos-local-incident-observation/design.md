## Context

`DeterministicServiceObserver`、`ServiceSnapshotCache` 和 incident 的 `before_snapshot` 接线已经在 Windows 默认应用验证。macOS 使用同一服务观察协议和复用的监听/进程/Docker 适配器，但本地应用仍只在 managed coordinator 存在时获得服务缓存。

## Goals / Non-Goals

**Goals:**

- 让 macOS 默认运行时复用现有只读服务观察，不依赖 Coordinator、模型或提权。
- 首份完整快照建立基线，后续稳定变化才触发 incident。
- managed 已配置时继续使用唯一服务缓存和采集路径。

**Non-Goals:**

- 不修改 Windows、模型服务、网络配置、Provider 或 incident 审批。
- 不新增观察器、配置项、工具、依赖或运行时抽象。

## Decisions

1. 在 `build_macos_local_application` 中采用与 Windows 相同的缓存选择和 `before_snapshot` 接线，直接复用现有组件。
2. managed coordinator 存在时使用其缓存；不存在时才创建本机 observer 并在 incident 快照前刷新。
3. 复用 macOS 现有只读适配器；真实验收只在临时目录和环回监听运行，不请求 `sudo`。

## Risks / Trade-offs

- [启动服务被误报为新增] → 首轮先刷新缓存，再建立 incident 基线。
- [默认与 managed 重复采集] → 只在 coordinator 不存在时创建默认 observer。
- [macOS 系统观察较慢] → 继续使用适配器现有线程卸载和既有周期，不引入并行框架。
- [只读权限不足] → 保留结构化降级，不提权或伪造完整结果。

## Migration Plan

升级后自动启用 macOS 默认本机只读观察；无数据迁移。回滚应用接线即可，既有 incident 数据保持可读。

## Open Questions

无。
