## Context

Overview 的服务摘要源数据已经包含 `protocol`、`host` 和 `port`，但本机产品 API 丢弃了 `host`。Chat 的运行结果和 Operation 摘要都已有 `tool_run_ids`，但前端没有利用这组稳定引用建立跳转。

## Goals / Non-Goals

**Goals:**

- 在 Overview 显示由服务摘要确定性组成的完整地址。
- 在 Chat 中只读列出与当前运行共享工具证据的 Operation 链接。
- 地址或操作列表缺失时保持现有页面可用。

**Non-Goals:**

- 不新增聚合 API、页面、写操作或网络探测。
- 不让模型生成地址或 Operation 关联。
- 不自动打开地址，不执行真实 A/B。

## Decisions

1. Overview API 增加可空 `access_address`，由现有 `ServiceSummary` 在服务视图适配器中组成。IPv6 主机加方括号；字段只作为不可信文本渲染，不生成外部链接。
2. Chat 复用现有 `/api/operations` 列表，在浏览器中按 `tool_run_ids` 交集匹配。没有交集时不显示链接；读取失败只隐藏该辅助区，不影响聊天。
3. Operation 跳转使用现有详情路由和普通 `<a>`，不新增路由、状态或依赖。

## Risks / Trade-offs

- [服务 host 可能是绑定地址而非可达地址] → 同时保留 accessibility/state，不把显示地址声明为探测成功。
- [多个 Operation 共享证据] → 全部列出，不猜测唯一关系。
- [操作列表读取失败] → 静默保留原聊天内容，不产生写请求。
