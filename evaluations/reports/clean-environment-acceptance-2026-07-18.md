# TunnelMinion Windows/macOS 干净环境生命周期验收

日期：2026-07-18

本轮使用与日常运行目录隔离的临时根目录，验证全新安装、启动、无模型降级、只读工具、Gateway 认证、停止、卸载和数据清理。验收材料不记录 Gateway token、Authorization 头、API Key 或 WireGuard 私钥。

## 验收结果

| 平台 | 安装与启动 | 无模型降级 | 只读工具与 Gateway | 停止与清理 | 结果 |
|---|---|---|---|---|---|
| Windows 11 / Python 3.11 | 在 `.data/clean-acceptance/windows` 新建虚拟环境并从当前源码完成 editable 安装；本地面板仅监听 `127.0.0.1:8876` | 模型状态为 `unconfigured`；资源接口仍返回 200；AI 可用性接口返回 503 | 本机节点摘要成功，API 文档返回 200 | 停止临时进程；`tunnelminion uninstall` 删除 3 项；确认数据目录和临时根目录均不存在 | 通过 |
| macOS / Python 3.12 | 在 `/Users/mac/Working-Env/tunnelminion-clean-acceptance` 新建虚拟环境并从当前源码完成 editable 安装；本地面板仅监听 `127.0.0.1:8877` | 模型状态为 `unconfigured`；节点摘要返回 200；AI 可用性接口返回 503 | 临时 Gateway 绑定 WireGuard 地址；未认证请求返回 401；使用临时凭据后返回 200，能力清单仅含 `get_node_summary` | 停止临时面板和 Gateway；`tunnelminion uninstall` 删除 5 项；确认数据目录和临时根目录均不存在 | 通过 |

## 隔离与恢复证据

- 两个平台均使用独立临时数据目录，没有复用正式节点数据库或覆盖正式配置。
- macOS 临时 Gateway 只在验收期间占用 `10.77.0.1:8787`，临时 token 仅保存在临时根目录，未写入仓库或报告。
- 验收结束后，macOS 正式 Gateway 已恢复监听 `10.77.0.1:8787`；Windows 侧 TCP 连接成功。
- 恢复后的真实 A→B 验收完成能力发现和六个只读工具调用；未认证请求为 401，Docker 数据源为 `available`，原有容器计数为 3，节点摘要显示 Agent `ready`、模型 `available`。
- macOS 监听端口与 WireGuard peer 明细仍因系统权限呈降级状态；这是已知的只读权限边界，不影响进程、Docker、节点摘要和 Gateway 认证验收。

## 结论

Windows 与 macOS 都能从隔离的空目录安装和启动；未配置模型时，资源与只读工具仍可用，只有 AI 运行明确返回不可用；停止和卸载后不残留临时数据。正式 macOS Gateway 在验收后已恢复，原有 Docker 与模型状态未被临时环境破坏。
