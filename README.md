# TunnelMinion

TunnelMinion 是一个面向私有网络的跨平台分布式 AI Agent 平台。每个节点运行一个本地
Agent，通过受控工具发现和诊断本机及已授权对等节点上的服务，并利用现有 WireGuard
隧道完成跨节点通信。

项目当前正在实现首个只读 Windows/macOS MVP，具体范围由
[`openspec/changes/deliver-ai-agent-over-existing-mesh`](openspec/changes/deliver-ai-agent-over-existing-mesh)
定义。

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

MVP 将现有 WireGuard 网络视为只读基础设施。任何开发命令和测试都不得创建、修改或
删除 WireGuard 配置。
