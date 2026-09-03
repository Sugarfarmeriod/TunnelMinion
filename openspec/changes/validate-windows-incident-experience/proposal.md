## Why

自主 incident 调查已经合入主线，但目前只有组件测试和离线评估，尚未证明 Windows 用户能在真实 Overview 页面看到一条调查结果。先用完全隔离、无真实模型和无网络改动的方式补这一条产品体验证据，可以低成本判断主线是否值得继续部署。

## What Changes

- 在 Windows 临时目录和独立环回端口启动现有产品包，不影响正在运行的本地实例。
- 复用现有固定 incident 数据集与离线 Investigation Agent，向隔离数据库写入一条可复现的调查结果。
- 通过真实 HTTP API 和 Overview 页面验证 incident 卡片、调查轨迹、结论与未知项可见。
- 记录普通刷新期间模型调用数为零，并输出不含秘密的验收报告。
- 验收结束后停止隔离进程并删除临时运行数据。
- 非目标：真实模型调用、macOS 部署、双机 A/B、自动发现真机故障、网络或 WireGuard 修改、Stage 6、生产密钥读取及新增后端或演示模式。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `agent-evaluation`: 增加 Windows 隔离产品体验验收，要求使用现有离线场景、真实 Overview 与 HTTP API，并证明普通刷新零模型调用及清理完成。

## Impact

影响范围仅限 OpenSpec、现有本地产品包验收脚本/测试和版本化验收报告；不新增运行时依赖，不改变生产 API、模型配置、系统密钥或网络状态。
