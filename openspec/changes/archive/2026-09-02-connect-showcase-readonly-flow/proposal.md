## Why

稳定产品界面已经分别提供服务总览、聊天运行和操作详情，但总览缺少可直接识别的完整服务地址，聊天也不能打开由同一批工具证据产生的操作记录。用户必须自己拼地址、抄 ID 和跨页搜索，三分钟展示闭环因此仍靠口头解释。

## What Changes

- Overview 为每项服务显示服务端提供的完整只读访问地址；地址只按文本展示，不自动发起网络请求。
- Chat 使用已有 `tool_run_ids` 与已有操作列表做只读匹配，为相关 Operation 提供详情页链接。
- 缺失地址或没有匹配 Operation 时保持现有降级表达，不猜测地址、不创建操作。
- 非目标：不新增聚合页面、后端领域、写接口、网络探测、Provider 操作或真实 A/B。

## Capabilities

### New Capabilities

无。

### Modified Capabilities

- `local-product-interface`: 总览展示完整只读服务地址，聊天展示与当前运行证据关联的 Operation 链接。

## Impact

- 修改本机 Overview 响应与 React schema/展示。
- 复用现有只读 `/api/operations` 列表和现有 Operation 详情路由。
- 不新增依赖，不改变授权、执行或网络协议。
