## Why

macOS 默认产品与 Windows 一样已经启动 incident 后台循环，但未配置 Coordinator 时 Overview 没有真实本机服务快照。当前真实 A/B 已证明 macOS 只读服务观察可用，因此应复用 Windows 已验证的最小接线补齐平台一致性。

## What Changes

- macOS 默认运行时复用现有监听、进程和 Docker 只读适配器形成有界本机服务快照。
- 本机快照进入现有 Overview 与 incident 差异链；首份完整快照只建立基线。
- managed runtime 已配置时继续复用其服务缓存，不启动第二个观察路径。
- 增加定向测试和 Mac 非特权真机验收；不调用模型、不请求 `sudo`、不修改网络或生产服务。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `autonomous-incident-investigation`: macOS 未配置 Coordinator 时也必须从真实本机只读观察组装 incident 快照。
- `local-product-interface`: macOS Overview 在未配置 Coordinator 时也必须展示当前本机服务观察结果。

## Impact

影响 macOS 本地应用组装和对应定向测试；复用现有跨平台观察、缓存、Overview 与 incident 组件，不新增依赖或 API schema。
