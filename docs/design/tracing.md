# 链路追踪：把一次提问在几台电脑上的全过程串成一条线

> 状态：已实现（OpenTelemetry），默认关闭。

## 一句话

打开追踪后，一次提问会被记成一条完整链路：Agent 运行、每次模型调用、每次工具调用，以及委派给另一台电脑后对方做的所有事。A、B 两台电脑的记录共用同一个链路编号，能看出每一步花了多少时间、失败在哪一步。

## 怎么打开

用环境变量 `TUNNELMINION_TRACE` 控制：

| 取值 | 效果 |
|---|---|
| 不设，或设为 `off` | 关闭（默认）。不安装追踪组件，行为和性能都不变 |
| `console` | 打印到标准错误 |
| `file` | 每结束一步，往文件里追加一行 JSON。默认写到数据目录下的 `traces.jsonl`，可以用 `TUNNELMINION_TRACE_FILE` 指定别的文件 |
| `otlp` | 按 OTLP/HTTP 发给 Jaeger 这类收集器，地址用标准的 `OTEL_EXPORTER_OTLP_ENDPOINT` 设置 |

本机界面、网关和后台组件启动时都会读这个设置，退出时会把还没写出的记录写完。

## 记了哪些步骤

| 步骤 | 位置 | 记什么 |
|---|---|---|
| `agent.run` | 一次 Agent 运行（包括委派到对方电脑后对方的那次运行） | 轮数、工具调用次数、结束原因 |
| `model.call` | 所有模型调用的统一入口（包括模型借用的双方） | 模型名、输入和输出 token 数、成功或失败 |
| `tool.call` | 工具执行通道 | 工具名、在哪台电脑执行、状态、结果是否被截断 |
| `gateway.client.*` / `gateway.server.*` | 网关请求的两端 | 动作名、HTTP 状态码 |

每条记录都带着产生它的电脑的节点 ID 和平台。

**不记的：** 消息内容、提示词、工具参数的取值、工具输出、令牌、文件路径。出错时只记"失败"，不记录错误内容和调用栈。测试会放一个特殊标记，确认它没有出现在任何记录里。

## 怎么跨电脑串起来

- **请求头传编号。** A 发出的每个网关请求都按 W3C `traceparent` 标准，把当前的链路编号放在请求头里；B 的网关从请求头里取出编号，接到同一条链路上。
- **委派的特殊处理。** 委派是异步的：A 提交后，B 在后台运行，A 定时查进度。B 的后台运行沿用"提交请求"那一步的链路，所以 B 的 `agent.run` 挂在 A 那次委派工具调用的下面。A 每次查进度都单独记成一个很短的步骤。

## 真机验收（2026-10-26）

**做法：**
- 这台 Windows 电脑用 DeepSeek 提问："Mac mini 上 9001 端口是什么服务？请交给 Mac mini 去查。"
- Mac mini 上运行一个临时网关，只允许这台电脑委派。
- 两台电脑都用 `file` 模式记录，最后把两边的文件合起来看。

**结果：**
- **同一个链路编号下共 18 步，其中 Windows 10 步、macOS 8 步。**
- 父子关系完整：Windows `agent.run` → `tool.call`（委派） → `gateway.client.submit_delegation` → macOS `gateway.server.submit_delegation` → macOS `agent.run` → macOS `model.call`。
- 查进度的请求也一一对应：`gateway.client.delegation_status` → `gateway.server.delegation_status`。

**一个失败步骤：** 验收时 Mac mini 的主人已经关掉了本机模型服务，所以 Mac 的 `model.call` 记为失败，Agent 也照实回答"对方的模型暂时不可用"。链路准确显示了失败出在哪台电脑的哪一步，这正是追踪的用处。
