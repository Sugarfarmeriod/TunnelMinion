# 展示素材台账

本台账只定义素材职责和采集门禁，不代表素材已经生成。规划来源为 PR #63 head `39d1ab7bdc94c5a6fa424a9857ac5fb3980507f7`；“素材来源”必须填写最终采集时对应的稳定 `main` SHA，不能用规划 SHA、Draft PR head 或 fixture 代替。

| ID | 素材与职责 | 当前状态 | 素材来源 SHA | 采集环境 | 图源 / 导出关系 | 脱敏与发布门禁 |
|---|---|---|---|---|---|---|
| `live-main-flow` | 现场 A/B 主流程，展示产品真实状态 | `prohibited-claim` | 未采集：PR #40/#59 未稳定且没有真实 A/B 授权 | 精确 A/B 节点、平台与版本待授权后记录 | 不适用 | 需检查地址、tool run、原始输出和秘密；不得录成当前成功 |
| `recording-main-flow` | 同一稳定提交上的三分钟兜底录屏 | `planned` | 未采集：等待稳定 `main` | Windows/macOS 与精确构建待记录 | 录屏必须引用相同 SHA 的公开事件与 manifest | 逐帧检查；不得含隐藏推理、秘密或 planned 成功占位 |
| `recording-degraded-flow` | 模型或节点异常时的诚实降级录屏 | `planned` | 未采集：等待稳定 `main` | 故障注入方式与平台待记录 | 与对应 fixture 分离；fixture 不能冒充录屏现场事实 | 画面必须显示“录屏”及故障范围 |
| `screenshot-overview` | 设备、服务和访问地址入口 | `planned` | 未采集：等待 PR #40 稳定 | 平台、窗口尺寸与数据集待记录 | 来源页面与截图一一对应 | 地址和节点名称使用获准的脱敏值 |
| `screenshot-operation` | 候选、目标节点批准、执行与恢复状态 | `planned` | 未采集：等待 PR #40/#59 稳定 | 平台与 operation ID 待记录 | 与公开事件和 Evidence 引用对齐 | 不显示未授权操作已生效 |
| `diagram-lifecycle` | 主流程收束用生命周期图 | `planned` | 未导出：等待稳定能力边界 | 仓库离线渲染环境待记录 | Penpot 仅在另获授权时作为图源；仓库 SVG/Mermaid 为发布证据 | 导出物需安全扫描并记录图源版本 |
| `diagram-security-approval` | 技术深挖用授权与安全边界图 | `planned` | 未导出：等待稳定能力边界 | 仓库离线渲染环境待记录 | 同上，不在主演示开场使用 | 不包含真实网络、节点、秘密或内部地址 |
| `claim-manifest` | 每条展示声明的来源与发布资格 | `draft-pr-verified` | 当前 schema：`39d1ab7bdc94c5a6fa424a9857ac5fb3980507f7` | repository / Python validator | JSON Schema → 每条最终声明文件 | 最终条目必须换成稳定 `main` SHA 并重新验证 |
| `cross-platform-report` | Windows/macOS 质量与构建证据 | `planned` | 未采集：等待最终素材提交 | workflow、runner 与 run ID 待记录 | 报告引用原始 CI run，不复制秘密日志 | 仅通过的本轮 run 可支持发布声明 |
| `evaluation-report` | 正确率、安全拦截、延迟、调用与成本证据 | `planned` | 未采集：真实基线尚未运行 | 数据集、模型、节点、平台与采集时间待记录 | 原始评估输出 → 脱敏汇总表 | 阈值必须在真实基线后确定，fixture 数字不计入成果 |

## 采集规则

1. 每项素材采集后必须把“未采集”替换为精确 40 位稳定 `main` SHA，并记录平台、环境和采集时间。
2. 图源、导出物、代码提交和 manifest 必须能相互追溯；Penpot 未获授权时不得写入。
3. `planned`、`prohibited-claim`、fixture、历史证据和 Draft PR 证据不得进入最终指标或成功画面。
4. 根 README、产品前端、最终截图和录屏仍由依赖稳定后的明确 owner 写入，本工作包不抢占其所有权。
