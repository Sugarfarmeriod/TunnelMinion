# 面试展示依赖与写入边界

## 现场快照

采集时间：`2026-09-02T15:20:00+08:00`

| 对象 | 精确版本 | 状态与证据 | 展示分类 |
|---|---|---|---|
| `origin/main` | `6c20fda5aa57f6f178569fc1aa1f5a34df65b3d2` | PR #40、#59、#64、#65、#66 均已合并；PR #66 CI 8/8 全绿 | `main-verified`，仅覆盖已合并实现与规格 |
| PR #40 | head `2e9b7957307e9fb378b8c052c4704b6dc2363cad`；merge `aae69d4868e58f094a5ad5c002f4192afe762475` | 已合并；8 项 CI 全绿；LPE 55/55 后同步并归档 | `main-verified`，真实双机写入不在该交付声明内 |
| PR #59 | head `535e2ff2ad7f02d46413b911e181a8e568230437`；merge `fe0f6b0601d53bc895558ee9d0b586858bad6063` | 已合并；Windows/macOS CI 全绿；后续 managed-path 已重划为诊断预览并归档 | `main-verified`，仅覆盖进入主线的能力 |
| PR #66 | head `6bc468c269bdb7f348a833a56fe8e7f6963c5444`；merge `6c20fda5aa57f6f178569fc1aa1f5a34df65b3d2` | 已合并；Overview 完整地址与 Chat→Operation 链接进入 main；CI 8/8 全绿 | `main-verified`，不包含真实模型或真实 A/B |
| PR #63 | merge baseline `f347caa3bf1744e0c75954b5a42c65bc6653e96f` | Draft/Open；本分支是 showcase 唯一写入者 | `draft-pr-verified`，不得冒充最终素材 |

以上是带时间戳的快照。最终截图、录屏或指标发布前仍须重新记录当时的稳定 `main` SHA、平台、采集时间与验证方式。

## Worktree 与写入顺序

- `feature/interview-showcase` 是本 change 唯一写入分支，只写 `openspec/changes/prepare-interview-showcase/**` 与 `docs/interview-showcase/**`。
- 保存的 `main` worktree 仍停在 `492d3dd` 且含用户修改，不作为写入或当前证据来源。
- LPE、managed-path 和归档 worktree 仅作历史参考；不覆盖、不重置、不修改。
- 根 README、产品前端与外部 Penpot 均不在本轮写入范围；需要时另立最小交付并明确唯一 owner。

## 当前 blocker

- PR #66 已解除完整访问地址与 Chat→Operation 产品承载缺口；定向无模型验证后 4.2 已裁决完成。
- 4.3 已在同一不可变提交完成 Qwen Windows→macOS 对照、DeepSeek 发布基线、Safe Sharing 2/2、阈值与只读复算审计；该证据仍是 `draft-pr-verified`，不是 main 或真实 A/B。
- 已采集顶部显著标注的 fixture 截图与降级短录屏，仅用于工作包复核，不计入最终成功素材。
- 没有精确 A/B 资源授权；阶段 5 的真实执行、截图和录屏继续保持 `prohibited-claim`。
- Penpot 未授权，本轮只保留仓库内离线 Mermaid/SVG。
