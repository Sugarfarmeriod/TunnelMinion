# TunnelMinion

TunnelMinion 是一个面向私有网络的跨平台分布式 AI Agent 平台。每个节点运行一个本地
Agent，通过受控工具发现和诊断本机及已授权对等节点上的服务，并利用现有 WireGuard
隧道完成跨节点通信。

项目已经交付并归档首个只读 Windows/macOS Agent MVP、人工审批的临时服务共享，以及统一
Prompt/Context Runtime。稳定需求位于 [`openspec/specs`](openspec/specs)，下一阶段按
[`openspec/ROADMAP.md`](openspec/ROADMAP.md) 规划 Coordinator、节点身份和服务目录，不直接
实施范围过大的旧自动组网 change。

如果希望先用非框架术语理解产品、当前进度以及 FastAPI、LangChain、LangGraph 的分工，
请阅读[《从零理解 TunnelMinion》](docs/guide/从零理解-tunnelminion.md)。
实现边界、跨节点调用链和全部架构决策入口见[《TunnelMinion MVP 架构》](docs/architecture.md)。
实际启动、Qwen 配置、A/B peer、排错、脱敏导出和完整卸载见
[《A/B 开发启动与运维》](docs/guide/开发启动与运维.md)。

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

MVP 将现有 WireGuard 网络视为只读基础设施。任何开发命令和测试都不得创建、修改或
删除 WireGuard 配置。
