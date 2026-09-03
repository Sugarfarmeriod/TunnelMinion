## ADDED Requirements

### Requirement: Overview 必须作为 incident 调查主入口
Overview SHALL 展示活动与近期重要 incident 的类型、对象、严重度、首次/最后观测时间、调查状态和当前结论摘要，并 MUST 明确区分待调查、调查中、已确认、信息不足、中断和模型不可用。普通用户无需先创建聊天即可发现异常与调查结果。

#### Scenario: 后台发现服务远端不可达
- **WHEN** 确定性比较器创建 incident 且调查正在运行
- **THEN** Overview 显示对应卡片、实时公开状态和证据时间，不要求用户先输入问题

#### Scenario: 模型不可用但 incident 已产生
- **WHEN** 快照差异已确认异常而模型 Provider 不可用
- **THEN** Overview 继续显示异常事实和 `investigation_unavailable`，且节点与服务总览仍可刷新

### Requirement: Incident 详情必须展示公开调查轨迹和证据边界
Incident 详情 SHALL 展示候选根因状态、已调用只读工具、公开结果摘要、证据引用、结论、未知项和停止原因。界面 MUST NOT 展示隐藏思维链、秘密、认证材料或无界原始工具输出。

#### Scenario: 调查因信息不足停止
- **WHEN** 必要远端工具不可用且报告状态为 `insufficient_evidence`
- **THEN** 详情列出已确认事实、仍未知问题、失败工具和停止原因，不把候选解释显示为已确认根因

### Requirement: 用户可以围绕当前 incident 进行小型上下文追问
Incident 详情 SHALL 提供绑定该 incident 的对话入口和基于未知项、证据缺口与允许下一步生成的有界建议问题。追问 MUST 复用现有 conversation 与 Context Runtime，仅注入当前 incident 的脱敏公开上下文；追问不得修改原调查证据或扩大工具权限。

#### Scenario: 用户追问为什么判定为仅本机可用
- **WHEN** 用户从 incident 详情选择建议问题
- **THEN** 系统在绑定 thread 中回答并引用该 incident 的监听与可达性证据，不要求用户重新描述上下文

#### Scenario: 建议问题增强不可用
- **WHEN** 模型无法生成建议问题
- **THEN** 页面根据未知项和固定模板显示可执行的建议问题，incident 详情保持可用
