## Why

常见的 RAG 或模拟 AIOps Agent 难以证明模型能够在真实环境中安全、可靠地完成复杂任务。现有 Windows 节点 A 与 macOS 节点 B 已通过 WireGuard 连通，本 change 将直接利用该真实环境，交付一个能调用本机与远端只读工具、管理上下文与记忆并基于证据完成跨节点诊断的 AI Agent MVP。

## What Changes

- 在 A、B 上运行 Python 3.11+ AI Agent Runtime，并提供仅监听本机的聊天与资源面板。
- 支持用户在每个节点配置兼容的大模型 API；密钥只保存在所属节点。
- 使用 LangChain 建立带停止条件、工具预算和结构化结果的 Agent 工具调用循环。
- 提供 WireGuard 状态、监听端口、进程、Docker 和服务可达性的确定性只读工具。
- 允许 Agent 通过现有 WireGuard 网络发现并调用已授权的远端节点只读工具。
- 分离实时状态、短期上下文、工作流 checkpoint 和长期记忆，并限制单次模型上下文规模。
- 建立假模型/假工具自动测试和 A/B 真机评估，量化工具选择、参数正确性、任务完成、证据一致性、延迟与成本。
- MVP 不创建或修改 WireGuard 配置，不执行临时端口发布、服务重启、容器控制、任意 Shell/Python 代码或其他有副作用操作。

## Capabilities

### New Capabilities

- `model-provider-configuration`: 每节点模型 API 的本地配置、连通验证、秘密保护、可用状态和失败降级。
- `agent-conversation`: 本地聊天会话、流式工具轨迹、停止条件、错误处理和基于工具证据的最终回答。
- `node-tool-runtime`: 结构化只读工具的定义、权限分级、参数校验、执行隔离、结果大小限制和审计。
- `context-and-memory`: 实时状态、短期对话、工作流 checkpoint 与长期记忆的分层、检索、裁剪和删除行为。
- `cross-node-diagnostics`: 通过现有 WireGuard 网络发现远端 Agent 工具，并完成跨节点服务发现、可达性检查和故障诊断。
- `agent-evaluation`: 使用可重复数据集和 A/B 真机任务评估 Agent 的正确性、安全性、性能和模型成本。

### Modified Capabilities

无。

## Impact

- 新增 Python Agent Runtime、模型 Provider、Agent 编排、工具注册表、上下文/记忆存储、跨节点工具网关和本地 Web UI。
- 引入 LangChain；使用 LangGraph 提供 checkpoint/persistence 基础，并为后续人工审批工作流保留边界。
- 新增 Windows/macOS 平台只读适配器，读取 WireGuard、端口、进程和 Docker 状态，但不得改变现有 `HomeMac` 或 B 的手写配置。
- 跨节点工具接口必须绑定 WireGuard 地址或通过受控通道访问，并具备节点认证、工具允许列表、超时、速率限制和审计。
- 测试系统需要假模型、假工具、录制/固定工具结果和 A/B 真机评估集，避免所有测试依赖真实模型或实时系统状态。
- 原 `deliver-minimum-viable-mesh` change 后移为自动组网基础设施工作；本 change 不依赖其实现。
