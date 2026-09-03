# TunnelMinion 产品愿景与长期路线图

## 产品定义

TunnelMinion 是**面向个人多设备私有网络的自主服务观察与故障调查助手**。普通程序在后台确定性地观察节点、监听端口、进程、Docker 服务、连接状态和服务目录，比较前后快照；只有异常或重要变化才触发一个 Investigation Agent。用户主要从总览查看 incident、调查进度、证据化结论、未知项和建议问题，并可在 incident 上下文中进行小型追问。

一句话定位：

> 平时安静地观察你的私有网络，变化时自主调查，并把“发生了什么、为什么、还不知道什么”直接放到总览。

TunnelMinion 不是聊天机器人套壳，也不是自动改网工具。Agent 负责提出和淘汰根因假设、选择既有只读工具、收敛证据并停止；系统观察和操作仍由确定性代码执行。需要处理时继续使用 Plan → Confirm → Execute → Verify → Rollback/Cleanup，本地策略和节点所有者始终拥有最终授权权。

## 当前目标用户与所有权边界

1. **当前正式目标：单所有者私有网络。** 同一位用户拥有 Windows、macOS 和家庭服务器等节点；秘密、权限策略和操作记录保存在所属节点。
2. **未来可选：家庭或小型实验室共享。** 请求者可以提出操作，目标节点所有者和本地策略最终裁决。
3. **暂停：公共 SaaS 与企业平台。** 多租户控制面、SSO、RBAC、合规和批量运维不是当前产品主线，也不提前预埋。

## 核心用户问题

- 用户不知道设备、服务和连接状态何时发生了重要变化。
- 服务新增、消失、离线、陈旧或远端不可达后，用户通常要先发现问题，再猜应该检查什么。
- 监听地址、进程、Docker 映射、节点状态和网络证据分散，普通状态面板不会主动收敛根因。
- 直接让模型执行系统操作风险过高；观察、调查和处理必须有清晰权限边界。
- 项目价值必须由固定故障矩阵和真实使用指标证明，不能由功能数量、Agent 数量或长演示脚本代替。

## 当前标志性产品循环

1. 后台用既有确定性能力生成有界节点与服务快照。
2. 比较器识别新增、消失、离线、陈旧、仅本机可用、远端不可达等事件；正常刷新不调用模型。
3. 满足触发规则的事件形成 incident，并且每个 incident 最多启动一个 Investigation Agent。
4. Agent 维护候选根因，根据证据缺口选择既有只读工具，更新或淘汰假设。
5. 证据充分、信息不足或预算耗尽时停止，生成带证据、未知项和停止原因的报告。
6. Overview 展示 incident 卡片、公开调查轨迹、结论和建议问题；用户可进行绑定 incident 的小型追问。
7. 用户明确要求处理时，才进入既有审批操作链；调查本身不执行写操作。

## 产品原则

- **总览是产品主入口**：用户先看到状态变化和调查结果，聊天只承担上下文追问。
- **事件驱动 AI**：正常观察、刷新、快照差异和触发规则不调用模型。
- **单 Agent 优先**：先证明一个 Agent 能稳定收敛证据；真实评测证明瓶颈前不引入 Reviewer 或多 Agent。
- **工具确定执行**：模型只能选择注册、校验、受预算约束的工具，不能生成或运行任意 Shell/Python。
- **证据驱动**：结论区分事实、候选解释和未知项，并引用实际工具证据。
- **默认只读**：自主调查没有写权限；有副作用能力必须进入现有审批、验证和回滚流程。
- **本地优先**：模型密钥、长期记忆、incident 数据和本地界面默认只存在于所属节点。
- **可降级运行**：模型不可用时，快照、事件、目录、总览和既有操作控制仍可工作。
- **价值可量化**：固定报告根因成功率、工具选择率、非必要调用率、无证据断言率、失败恢复率和延迟。

## 能力分层与复用边界

### 确定性观察层

复用 `get_node_summary`、`get_wireguard_status`、`list_network_listeners`、`get_process_summary`、`list_docker_services`、`probe_service_reachability`，以及 Coordinator 节点/服务目录。该层负责事实采集、规范化快照、差异、去重、新鲜度和 incident 触发，不依赖模型。

### Investigation Agent 层

复用统一 Context Runtime、工具注册与过滤、证据引用、预算和公开运行事件。每个 incident 只有一个 Agent，状态包含候选根因、支持/反驳证据、工具轨迹、未知项和停止原因。隐藏思维链不保存。

### 产品界面层

复用已完成的本地 React 产品界面与 Overview 聚合契约。新增 incident 卡片、详情轨迹、上下文追问和建议问题；不建立第二套控制面或以聊天替代总览。

### 安全操作层

复用已完成的操作计划、目标节点授权、幂等执行、请求节点验证、回滚、过期和清理能力。incident 只提供证据，不提供授权。

## 重划后的阶段顺序

### 当前主线 A：确定性观察与 incident 基线

- 规范化本机与目录快照，只保留稳定身份、状态、来源、新鲜度和观测时间。
- 确定性识别六类首发事件并去重、抑制短暂抖动。
- 证明正常刷新零模型调用，模型不可用时仍能记录和展示事件。

对应 change：`add-autonomous-incident-investigation` 的第一纵向切片。

### 当前主线 B：单 Agent 自主调查

- 每个 incident 维护一个可恢复调查状态。
- Agent 根据当前证据缺口选择六个既有只读工具，更新或淘汰候选根因。
- 强制模型轮次、工具数、墙钟和上下文预算，并输出证据化停止结果。

对应 change：`add-autonomous-incident-investigation` 的第二纵向切片。

### 当前主线 C：总览主导的 incident 体验

- Overview 展示 incident 卡片、调查状态、公开轨迹、结论、未知项和建议问题。
- 复用现有 conversation 提供绑定 incident 的小型追问。
- 模型、Coordinator 或 peer 降级时继续如实展示确定性事实。

对应 change：`add-autonomous-incident-investigation` 的第三纵向切片。

### 当前主线 D：固定评测与退出判断

- 固定覆盖服务新增/消失、节点离线、目录陈旧、环回监听、远端不可达、Docker 不可用、工具失败、模型失败和预算耗尽。
- 报告六项核心指标并保留失败分类。
- 若真实使用不能减少发现与定位成本，停止扩展自主化，而不是继续堆 Agent 或网络能力。

### 后续可选 E：经批准的处理与可分发交付

- 当自主调查已证明价值后，再优化“从 incident 进入候选操作计划”的体验。
- Windows/macOS 安装、升级、卸载和演示材料按独立 change 推进，不与调查核心混合。
- Linux、游戏探测器和经验 Playbook 只在真实需求出现后评估。

## 暂停或降级为可选的旧方向

- **packet relay**：`build-isolated-packet-relay` 暂停。当前产品价值不依赖新 relay，只有现有私网路径成为已验证普遍阻塞时再评估。
- **更多网络 Provider**：n2n 与新 Provider 暂停。先复用现有网络和静态/受管只读状态，不用 Provider 数量衡量完成度。
- **复杂自动组网**：WireGuard 自动下发、复杂路径优化和跨平台网络写入降级为可选；不得成为自主调查 MVP 的前置。
- **通用服务/游戏智能识别**：作为未来 detector 增强，不在首轮 incident 闭环内建立插件框架。
- **多 Agent 与 Reviewer**：暂停。只有固定评测证明单 Agent 存在上下文、并行或独立复核瓶颈时另建 change。
- **通用 AIOps、公共 SaaS、企业 RBAC**：不属于当前产品路线。
- **`prepare-interview-showcase`**：暂停扩展，待新主线有可重复结果后，只把真实结果整理为展示，不反向驱动产品范围。
- **`package-manual-node-runtime`**：保留为可选分发工作，不阻塞 incident 核心验证。

以上暂停不删除已有代码、规格、归档 change 或 provenance；恢复任一方向都需要独立价值证据和独立 change。

## 已完成成果与历史 provenance

| 历史交付 | 状态 | 作为新主线的复用价值 |
|---|---|---|
| `deliver-ai-agent-over-existing-mesh` | 已归档 | 六个只读工具、跨节点诊断和证据化回答 |
| `approve-and-share-local-service` | 已归档 | Plan → Confirm → Execute → Verify → Rollback/Cleanup |
| `integrate-agent-context-and-prompt-runtime` | 已归档 | 统一上下文、预算、证据优先级和安全降级 |
| `coordinate-agent-network` | 已归档 | 节点身份、心跳、能力与服务目录、新鲜度 |
| `integrate-managed-node-runtime` | 已归档 | 受管节点运行与生命周期基础 |
| `manage-wireguard-connectivity` | 已归档 | 网络 Provider/所有权规格；真实写入不再是当前前置 |
| `complete-managed-path-runtime` | 已归档 | managed path 只读诊断与历史 Stage 6 provenance |
| `deliver-minimum-viable-mesh` | 已归档 | 历史范围与决策记录，不作为当前总 change |
| `improve-local-product-experience` | 已归档 | React 本地界面、Overview、操作/聊天/记忆/设置基础 |
| `connect-showcase-readonly-flow` | 已归档 | Overview 到操作详情、Chat 到 operation 的只读连接 |

归档表示历史 change 的事实被保留，不表示新产品循环已经完成，也不要求重启过去昂贵的真实网络验收。

## 当前验收标准

- 正常刷新不会创建 incident 或调用模型。
- 六类首发变化具有确定性、可去重、可复现的事件结果。
- 一个 incident 同时最多运行一个 Agent，且只能调用既有六个只读工具。
- 报告明确区分事实、候选解释、未知项和停止原因；确认结论具有证据引用。
- 模型、工具、peer 或 Coordinator 失败不会破坏快照、总览和既有操作控制。
- Overview 可以在不先聊天的情况下展示 incident 全流程，并允许绑定 incident 的小型追问。
- 固定故障矩阵产出六项核心指标；任何安全失败或无证据确认结论单独阻断发布。
- 实现与评测不修改防火墙、WireGuard、用户路由或生产服务，不要求反复提权操作。

## 明确非目标

- Agent 自写或执行 Shell、Python、脚本和未知工具。
- 自动修改防火墙、WireGuard、DNS、用户路由、服务或容器。
- 正常刷新调用模型，或为每个状态变化启动多个 Agent。
- 新 relay、新网络 Provider、公共 SaaS、企业 RBAC 和通用 AIOps 平台。
- 用 Agent 数量、prompt 长度、上下文窗口、Provider 数量或功能计数替代产品价值指标。
- 让历史成功、incident 结论或长期记忆自动成为执行权限。

## OpenSpec 文档策略

- 本文件维护产品主线、阶段顺序和暂停项；它不改写已归档 change 的历史事实。
- 每个 change 只承担可独立演示、评估和退出的纵向闭环。
- 每个 AI change 必须覆盖正常路径、工具失败、模型失败、上下文预算和安全边界。
- change 完成后归档，并将稳定需求同步到 `openspec/specs/`。
- 路线图不是承诺；真实指标不能证明价值时，优先缩小或停止，而不是扩大系统。
