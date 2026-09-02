# 面试展示依赖与写入边界

## 现场快照

采集时间：`2026-09-02T15:20:00+08:00`

| 对象 | 精确版本 | 状态与证据 | 展示分类 |
|---|---|---|---|
| `origin/main` | `b21b00e68e2298bb5db6a5c75d3e8629a33e4d05` | PR #40、#59、#64、#65 均已合并；当前 OpenSpec strict 22/22 | `main-verified`，仅覆盖已合并实现与规格 |
| PR #40 | head `2e9b7957307e9fb378b8c052c4704b6dc2363cad`；merge `aae69d4868e58f094a5ad5c002f4192afe762475` | 已合并；8 项 CI 全绿；LPE 55/55 后同步并归档 | `main-verified`，真实双机写入不在该交付声明内 |
| PR #59 | head `535e2ff2ad7f02d46413b911e181a8e568230437`；merge `fe0f6b0601d53bc895558ee9d0b586858bad6063` | 已合并；Windows/macOS CI 全绿；后续 managed-path 已重划为诊断预览并归档 | `main-verified`，仅覆盖进入主线的能力 |
| PR #63 | merge baseline `f347caa3bf1744e0c75954b5a42c65bc6653e96f` | Draft/Open；本分支是 showcase 唯一写入者 | `draft-pr-verified`，不得冒充最终素材 |

以上是带时间戳的快照。最终截图、录屏或指标发布前仍须重新记录当时的稳定 `main` SHA、平台、采集时间与验证方式。

## Worktree 与写入顺序

- `feature/interview-showcase` 是本 change 唯一写入分支，只写 `openspec/changes/prepare-interview-showcase/**` 与 `docs/interview-showcase/**`。
- 保存的 `main` worktree 仍停在 `492d3dd` 且含用户修改，不作为写入或当前证据来源。
- LPE、managed-path 和归档 worktree 仅作历史参考；不覆盖、不重置、不修改。
- 根 README、产品前端与外部 Penpot 均不在本轮写入范围；需要时另立最小交付并明确唯一 owner。

## 当前 blocker

- Overview 的 `KnownServiceOverview` 明确不公开 host，页面只有协议、端口和节点短 ID；完整访问地址尚未形成产品证据，阻塞 4.2 与最终主演示。
- 当前只复跑了确定性 fixture；没有读取模型配置或调用真实模型，因此 4.3 的真实模型基线和阈值仍未完成。
- 没有精确 A/B 资源授权；阶段 5 的真实执行、截图和录屏继续保持 `prohibited-claim`。
- Penpot 未授权，本轮只保留仓库内离线 Mermaid/SVG。
