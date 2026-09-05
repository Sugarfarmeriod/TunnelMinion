## Why

Windows 与 macOS 正式包已经能安全识别本机 `service_added`，但 2026-09-05 的重复实机门槛中，macOS 连续 3 个有效样本均未调用只读工具、没有形成证据化结论；首次启动还会把面板自己的监听端口记录成无关 incident。用户因此看到的是噪声和“证据不足”，而不是能帮助定位新增服务的调查结果。

## What Changes

- 首次启动时先等待一个正常观察周期再建立服务基线，避免把应用自己的面板监听误报成新增服务。
- 对 `local_observation` 来源的 `service_added`，首轮只向模型暴露 `list_network_listeners`；如果模型仍未选择工具，不论返回格式是否有效，都通过现有 Tool Runtime 受控执行一次该工具，再让模型基于真实结果继续收敛，后续仅保留监听与进程摘要工具。
- 保留已有证据门槛、轮次与调用预算；工具失败或后续证据仍不足时继续安全落为 `insufficient_evidence`。
- 远端或目录来源不向模型暴露、也不执行当前节点的本机工具；模型仍不能获得 Shell、Python、网络写入或未知工具。
- 以单元回归和 Windows/macOS 正式包重复场景验收：10 个目标样本至少 8 个取得相关只读工具证据、至少 7 个形成证据化结论，且不出现无证据确认、禁止工具执行或无关工具调用。
- 非目标：不恢复 packet relay、复杂 Provider、自动组网或 showcase；不修改 WireGuard、防火墙、路由、DNS、生产服务或模型服务。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `autonomous-incident-investigation`: 收紧本机服务 incident 的启动基线和首轮取证要求，同时保持远端证据边界。

## Impact

- 影响后台观察调度、本机 incident 调查循环及其回归测试。
- 更新 `autonomous-incident-investigation` 规格和本阶段正式包实机证据。
- 不新增依赖、不改变公开 API，不触碰任何网络写入路径或外部服务配置。
