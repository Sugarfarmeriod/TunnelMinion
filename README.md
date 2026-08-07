# TunnelMinion

TunnelMinion 是一个面向私有网络的跨平台分布式 AI Agent 平台。每个节点运行一个本地
Agent，通过受控工具发现和诊断本机及已授权对等节点上的服务，并通过配置的可路由 endpoint
完成跨节点通信。当前 A/B 实验使用现有 WireGuard；普通局域网、企业 VPN 或其他可路由网络
具有相同的 Gateway 与 peer 验收语义。

项目已经交付并归档首个只读 Windows/macOS Agent MVP、人工审批的临时服务共享，以及统一
Prompt/Context Runtime。稳定需求位于 [`openspec/specs`](openspec/specs)，后续范围按
[`openspec/ROADMAP.md`](openspec/ROADMAP.md) 管理。本轮手工运行包与 Gateway 健康交付不以
Coordinator 真机 enrollment/sync 为前置。

如果希望先用非框架术语理解产品、当前进度以及 FastAPI、LangChain、LangGraph 的分工，
请阅读[《从零理解 TunnelMinion》](docs/guide/从零理解-tunnelminion.md)。
实现边界、跨节点调用链和全部架构决策入口见[《TunnelMinion MVP 架构》](docs/architecture.md)。
实际启动、Qwen 配置、A/B peer、排错、脱敏导出和完整卸载见
[《A/B 开发启动与运维》](docs/guide/开发启动与运维.md)。安装版本化运行包、手工启停、升级和
回退见[《手工节点运行包》](docs/manual-node-runtime.md)。

## 开发环境

依赖条件：

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

安装锁定后的开发依赖：

```shell
uv sync --locked --all-groups
```

运行全部本地质量门禁：

```shell
uv run python scripts/quality.py all
```

也可以分别执行 `format`、`lint`、`typecheck` 和 `test`：

```shell
uv run python scripts/quality.py format
uv run python scripts/quality.py test
```

## 启动当前 Windows 资源页

```shell
uv run tunnelminion --data-dir .data/a --port 8765
```

浏览器打开 `http://127.0.0.1:8765/chat` 使用本地聊天页，打开
`http://127.0.0.1:8765/resources` 查看本机只读资源，打开
`http://127.0.0.1:8765/memories` 管理长期记忆，或打开
`http://127.0.0.1:8765/api/docs` 查看模型配置、thread/run、记忆与资源 API。服务固定绑定环回
地址，不会直接暴露到局域网或 WireGuard 网络。

默认运行仍将现有 WireGuard 网络视为用户基础设施。仓库包含受管网络 Provider、离线 fake
门禁和一次隔离的真实 A/B 验收证据，但每次真实写入仍必须使用独立接口、完整回滚计划并获得
单独明确授权；普通开发命令和测试不得创建、修改或删除现有 WireGuard 配置。
