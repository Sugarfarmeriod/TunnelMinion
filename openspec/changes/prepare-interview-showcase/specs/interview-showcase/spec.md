## ADDED Requirements

### Requirement: 首版展示必须形成可理解的 A/B 安全闭环

面试展示 SHALL 以设备、服务和访问地址为入口，并 SHALL 连续呈现只读诊断、无权限候选处理、必要的目标节点本地批准、执行后独立验证以及恢复或清理证据。首版展示 MUST NOT 将 A/B/C 三个独立 Agent 的直接通信作为已交付能力。

#### Scenario: 三分钟主流程完整呈现
- **WHEN** 演示者执行首版三分钟主流程
- **THEN** 观众无需在无关页面或架构材料之间自行拼接，即可理解问题、证据、授权、结果和恢复边界

#### Scenario: 三 Agent 能力尚未实现
- **WHEN** 展示材料提到未来的 A/B/C Agent 协作
- **THEN** 该内容被明确标记为后续能力，不出现在已完成主流程、成果数字或真实成功证据中

### Requirement: 展示必须复用现有公开领域与安全语义

展示 SHALL 使用 `Thread`、`Run`、`Operation` 和 `Evidence` 组织用户问题、公开工具轨迹、候选处理、授权状态和验证结果。展示 MUST NOT 暴露隐藏推理、秘密、未脱敏原始工具数据，也 MUST NOT 通过展示专用状态绕过既有授权和验证语义。

#### Scenario: 候选处理尚未获得权限
- **WHEN** Agent 生成候选 `Operation` 但目标节点尚未批准
- **THEN** 展示明确说明该候选没有执行权限，并且不会把计划状态呈现为已生效

#### Scenario: 公开运行轨迹
- **WHEN** 展示一个正在执行或已完成的 `Run`
- **THEN** 只显示允许公开的目标、工具、状态、耗时、tool run ID 和证据引用，不显示模型隐藏推理或秘密

### Requirement: 每条成果声明必须可追溯并区分交付状态

展示资产 MUST 为每条重要声明记录来源提交、分支或 PR、平台、环境、验证方式、采集时间和适用范围，并 MUST 将声明分类为 `main-verified`、`draft-pr-verified`、`planned` 或 `prohibited-claim`。Draft PR、历史证据、fixture 和降级路径成功 MUST NOT 被描述为稳定主线或本轮真实 A/B 成功。

#### Scenario: 使用 Draft PR 证据
- **WHEN** 展示材料引用尚未合并 PR 上的测试或产品能力
- **THEN** 材料标出精确 PR head 和 `draft-pr-verified` 状态，不将其写成 `main` 已发布能力

#### Scenario: 规划占位缺少真实证据
- **WHEN** 某项能力只有设计、fixture 或待授权计划
- **THEN** 该项保持 `planned` 或 `prohibited-claim`，并且不进入成果数字、最终截图或成功录屏

### Requirement: 展示工作包必须保持单一写入边界

本 change 的唯一主写者 SHALL 仅修改本 change 的 artifacts 与仓库内非公开、非最终的 `docs/interview-showcase/**` 工作包。根 README、产品前端、最终截图或录屏、公共发布材料和外部图纸 MUST 等待对应任务与授权门禁。

#### Scenario: 公共文件尚未分配 owner
- **WHEN** 展示工作需要修改根 README、产品前端或外部图纸，但公共文件写入者尚未明确
- **THEN** 本 change 只完成独立工作包和证据台账，不启动对应公共写入

### Requirement: 最终素材必须建立在稳定依赖与本轮证据上

最终 UI、README、截图、录屏和真实指标 SHALL 等待所依赖能力进入明确稳定基线后生成，并 SHALL 在该基线上重新运行相称的质量、跨平台和真实环境门禁。需要真实网络写入或 A/B 资源的证据 MUST 取得用户对精确资源和影响范围的明确授权。

#### Scenario: 依赖进入稳定基线
- **WHEN** 所需产品能力已进入确定的稳定基线且文件 owner 已明确
- **THEN** 实现任务从最新同步基线开始，并重新采集与最终素材相同提交上的证据

#### Scenario: 缺少真实资源授权
- **WHEN** 展示需求涉及真实接口、地址、路由、Provider 写入或恢复验证但用户未明确授权资源
- **THEN** 系统不执行该验证，展示材料也不声称已经完成真实门禁

### Requirement: 现场演示必须提供明确且诚实的降级方案

展示方案 SHALL 同时定义现场演示、同一稳定提交上的录屏兜底和离线可审计证据。模型、节点或网络不可用时，演示者 MUST 说明当前故障和降级范围，不得把录屏播放描述成当前现场执行结果。

#### Scenario: 现场模型不可用
- **WHEN** 现场模型健康检查失败或 Agent 对话不可用
- **THEN** 演示切换到确定性设备/服务状态、已有操作控制和标明来源的录屏或证据，并明确说明开放式诊断当前不可用

#### Scenario: 离线 fixture 演示失败场景
- **WHEN** 使用 fixture 展示超时、节点离线、重复、乱序、矛盾证据或操作失败
- **THEN** 画面和 manifest 明确标记 fixture，且其结果不计入真实 A/B 指标

### Requirement: 图纸与仓库发布证据必须保持可审计分层

自部署 Penpot SHALL 作为当前可编辑图源，仓库内离线 SVG、Mermaid 源和脱敏 manifest SHALL 作为可审计发布证据。主演示 SHALL 以产品流程为主，生命周期图用于流程收束，安全架构与审批图用于技术深挖。任何外部图纸写入 MUST 另获授权并遵守单一写入者。

#### Scenario: 最终展示引用架构图
- **WHEN** README、录屏或现场深挖引用架构图
- **THEN** 所用离线资产记录对应图源、导出时间和代码提交，并与当前稳定能力边界一致
