## ADDED Requirements

### Requirement: 服务总览必须显示确定性的完整访问地址

本机产品界面 SHALL 为已有 `protocol`、`host` 和 `port` 的服务显示完整 `access_address`，并 MUST 将该地址作为不可信只读文本呈现。系统 MUST NOT 因展示地址自动发起网络请求，也 MUST NOT 把地址存在等同于服务探测成功。

#### Scenario: 服务摘要包含完整地址来源
- **WHEN** Overview 收到包含 protocol、host 和 port 的服务摘要
- **THEN** API 与页面显示由这三个字段确定性组成的完整地址，并继续显示独立的状态与新鲜度

#### Scenario: 地址不可获得
- **WHEN** 服务摘要无法提供完整地址
- **THEN** 页面明确显示地址未知且不猜测主机或发起探测

### Requirement: 聊天运行必须链接共享证据的操作记录

Chat SHALL 使用当前 Run 和 Operation 已有的 `tool_run_ids` 建立只读关联，并 SHALL 为每个存在交集的 Operation 提供现有详情页链接。该关联 MUST NOT 创建、批准、执行或重放 Operation。

#### Scenario: 一个操作共享当前运行证据
- **WHEN** Operation 的 `tool_run_ids` 与当前 Run 的 `tool_run_ids` 至少有一个相同值
- **THEN** Chat 显示该 Operation 的只读详情链接

#### Scenario: 没有相关操作或列表读取失败
- **WHEN** 没有共享证据的 Operation，或只读操作列表暂时不可用
- **THEN** Chat 保持原运行与证据内容可用，且不猜测关联或触发写请求
