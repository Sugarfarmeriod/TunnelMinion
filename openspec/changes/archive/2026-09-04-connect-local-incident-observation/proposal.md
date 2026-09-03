## Why

Windows 默认产品即使未接入 Coordinator，也已经启动 incident 后台循环，但 Overview 没有真实本机服务快照，循环因此无法发现本机服务变化。把现有确定性只读服务观察接入该路径，才能让“自动观察 → incident”从离线夹具变成默认本机产品能力。

## What Changes

- Windows 默认运行时周期性复用现有监听、进程和 Docker 只读适配器，形成有界本机服务快照。
- 本机服务快照进入现有 Overview 与 incident 差异链；首份快照只建立基线，不创建启动噪声。
- 未配置模型时仍可发现并持久化 incident，调查明确降级为 `investigation_unavailable`，正常刷新继续保持零模型调用。
- 增加定向测试和隔离本机监听验收，证明真实监听变化可由后台自动发现。
- 非目标：真实模型、远端节点、macOS、网络写入、自动处理 incident、新工具或新 Provider。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `autonomous-incident-investigation`: 明确 Windows 未配置 Coordinator 时也必须从真实本机只读观察组装 incident 快照，并避免首轮启动噪声。
- `local-product-interface`: Overview 在未配置 Coordinator 时也必须展示当前本机服务观察结果。

## Impact

影响 Windows 应用组装、现有 Overview 本机服务数据源、incident 观察调度与对应定向测试；不增加依赖，不改变 API schema、秘密存储、模型配置或网络状态。
