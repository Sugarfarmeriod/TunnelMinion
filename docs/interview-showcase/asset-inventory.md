# 展示素材台账

本台账同时登记已生成的 fixture 工作包素材与尚未获准的最终素材。当前 fixture 采集基线为 `feature/interview-showcase@6d9e98aa492e30c2ba064bdf3ef0a0085565799e`；它不能替代最终采集时对应的稳定 `main` SHA 或真实 A/B 证据。

| ID | 素材与职责 | 当前状态 | 素材来源 SHA | 采集环境 | 图源 / 导出关系 | 脱敏与发布门禁 |
|---|---|---|---|---|---|---|
| `live-main-flow` | 现场 A/B 主流程，展示产品真实状态 | `prohibited-claim` | 未采集：没有真实 A/B 授权 | 精确 A/B 节点、平台与版本待授权后记录 | 不适用 | 需检查地址、tool run、原始输出和秘密；不得录成当前成功 |
| `recording-main-flow` | 同一稳定提交上的三分钟兜底录屏 | `planned` | 未采集：等待稳定 `main` | Windows/macOS 与精确构建待记录 | 录屏必须引用相同 SHA 的公开事件与 manifest | 逐帧检查；不得含隐藏推理、秘密或 planned 成功占位 |
| `recording-degraded-flow` | 模型或节点异常时的诚实降级录屏 | `planned` fixture 已采集，最终录屏未采集 | `6d9e98aa492e30c2ba064bdf3ef0a0085565799e` | Windows 11 / Chromium / 隔离 FastAPI fixture；VP8 1280×720，6.76 秒 | `assets/degraded-fixture-flow.webm` → `assets/asset-manifest.json` | 顶部持续标注 fixture；审批对话框只打开后关闭，不进入成功素材 |
| `screenshot-overview` | 设备、服务和访问地址入口 | `planned` fixture 已采集，最终截图未采集 | `6d9e98aa492e30c2ba064bdf3ef0a0085565799e` | Windows 11 / Chromium；1440×900 | `assets/overview-readonly-fixture.png` → `assets/asset-manifest.json` | 只证明无模型/无 Coordinator/无路径时的确定性降级，不代表真实 A/B |
| `screenshot-operation` | 候选、目标节点批准、执行与恢复状态 | `planned` fixture 已采集，最终截图未采集 | `6d9e98aa492e30c2ba064bdf3ef0a0085565799e` | Windows 11 / Chromium；1440×1559 | `assets/operation-awaiting-approval-fixture.png` → `assets/asset-manifest.json` | 明确显示 awaiting_authorization 与尚未授权，不显示已生效 |
| `readme-outline` | 根 README 未来展示段的信息顺序和证据插槽 | `planned` 结构稿已生成；根 README 未修改 | 作者基线 `9525d3e6f2b8543d3bfe11b182971aaf6ba4a16e`；等待稳定 `main` 后实施 | repository / `verify_readme_outline.py` | `readme-outline.md` → 未来根 README 展示段 | 所有 planned 行必须在发布前替换或删除；3.1 继续未完成 |
| `product-surface-review` | Overview、Chat、Operations、Memories、Settings 对主演示与深挖的承载复核 | `main-verified`，3.2/4.2 已完成 | `6c20fda5aa57f6f178569fc1aa1f5a34df65b3d2` | repository / `verify_product_surface_review.py` | `product-surface-review.md` → PR #66 最小补强结论 | 地址不等同探测成功；不新增展示专用后端 |
| `diagram-lifecycle` | 主流程收束用生命周期图 | `planned` 工作包已生成，非最终素材 | 作者基线 `d884acbde1bf5767fe3ced1f252b3a520d10ca5c`；等待稳定 `main` 后重采 | repository / `verify_diagrams.py` | `diagrams/lifecycle.mmd` → `diagrams/lifecycle.svg`；Penpot 仍未授权 | manifest 固定哈希和必需标签；SVG 不含外部引用，最终发布前重扫 |
| `diagram-security-approval` | 技术深挖用授权与安全边界图 | `planned` 工作包已生成，非最终素材 | 作者基线 `d884acbde1bf5767fe3ced1f252b3a520d10ca5c`；等待稳定 `main` 后重采 | repository / `verify_diagrams.py` | `diagrams/security-approval.mmd` → `diagrams/security-approval.svg`；不在主演示开场使用 | 只使用中性 A/B 标签，明确范围外资源与禁止自批；最终发布前重扫 |
| `claim-manifest` | 每条展示声明的来源与发布资格 | `draft-pr-verified` | 当前 schema：`39d1ab7bdc94c5a6fa424a9857ac5fb3980507f7` | repository / Python validator | JSON Schema → 每条最终声明文件 | 最终条目必须换成稳定 `main` SHA 并重新验证 |
| `cross-platform-report` | Windows/macOS 质量与构建证据 | `planned` | 未采集：等待最终素材提交 | workflow、runner 与 run ID 待记录 | 报告引用原始 CI run，不复制秘密日志 | 仅通过的本轮 run 可支持发布声明 |
| `evaluation-report` | 正确率、安全拦截、延迟、调用与成本证据 | `draft-pr-verified` 真实模型阈值已完成，尚未进入 main | 采集提交 `b1e94aaed2b44db57563bcbca4b721d009656550`；报告哈希见 suite | Windows→macOS Qwen 对照；Windows→DeepSeek API 发布基线 | `evaluation/evaluation-suite.json` → 四份真实报告 → `real-baseline-audit.md` | DeepSeek 达标、Qwen 未达标；不外推为真实 A/B 或最终成功素材 |

## 采集规则

1. fixture 工作包素材记录精确作者 SHA 并保持 `planned`；最终素材仍必须换成精确 40 位稳定 `main` SHA，并记录平台、环境和采集时间。
2. 图源、导出物、代码提交和 manifest 必须能相互追溯；Penpot 未获授权时不得写入。
3. `planned`、`prohibited-claim`、fixture、历史证据和 Draft PR 证据不得进入最终指标或成功画面。
4. 根 README、产品前端、最终截图和录屏仍由依赖稳定后的明确 owner 写入，本工作包不抢占其所有权。
