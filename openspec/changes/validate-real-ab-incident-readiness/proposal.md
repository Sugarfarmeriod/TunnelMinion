## Why

Windows 本机 incident 闭环已经合入主线，但当前代码尚未在现有 Windows/macOS 节点上重新证明常规入口、控制面降级和生产网络不变。复用既有真实 A/B 验收脚本可以用最小风险补齐这条当前版本证据。

## What Changes

- 在当前主线执行一次非特权、只读优先的真实 Windows/macOS A/B 验收。
- 保存不含凭据和系统正文的脱敏报告，并验证临时进程、端口和目录已清理。
- 固化真实 A/B 验收的零副作用预检、生产状态前后不变和失败时清理要求。
- 不启动或配置模型服务，不修改 WireGuard、防火墙、路由、DNS、Provider/L3 资源或生产服务。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `agent-evaluation`: 明确真实 A/B 验收必须先通过只读预检，并证明生产端口与网络基线前后不变、临时资源已清理。

## Impact

影响 OpenSpec 的 `agent-evaluation` 契约和一份版本化脱敏评估报告；复用现有验收脚本，不新增依赖、产品功能或网络写入。
