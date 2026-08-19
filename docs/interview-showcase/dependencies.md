# 面试展示依赖与写入边界

## 现场快照

采集时间：`2026-08-19T18:54:57+08:00`

| 对象 | 精确版本 | 状态 | OpenSpec | CI / review | 展示分类 |
|---|---|---|---|---|---|
| `origin/main` | `e84781aafaa73d7d61e4756b758f7c1dd0d70fbb` | PR #62 已合并，包含本 change 规划 | `prepare-interview-showcase` 0/24 | PR #62 Windows/macOS CI 成功，独立文档审计 ACCEPT | `main-verified`，仅证明规划已交付 |
| 当前实现 worktree | `feature/interview-showcase@e84781aafaa73d7d61e4756b758f7c1dd0d70fbb` | 8/24，当前改动尚未提交 | `prepare-interview-showcase` 8/24；`main` 仍为 0/24 | 本地 OpenSpec 与证据格式门禁待最终复审 | 非发布中的工作状态 |
| PR #59 `feature/managed-path-governance-lifecycle` | `86f4682c5289ddf93eb6a666ac044d3bf9831962` | Draft/Open，`CLEAN` / `MERGEABLE`；因 Draft 尚未进入合并裁决 | `complete-managed-path-runtime` 33/47；`main` 同名 change 仍为 15/47 | run `32135772613` 成功；0 review、0 review thread | `draft-pr-verified`，不得写成 `main` 已交付 |
| PR #40 `feature/local-product-experience` | `61398b76d01b3836dc6023f74b0ba3d17ef7cbb4` | Draft/Open，`DIRTY` / `CONFLICTING`，当前有基线冲突 | `improve-local-product-experience` 51/55；`main` 同名 change 仍为 0/55 | run `31586742270` 成功；0 review、0 review thread | `draft-pr-verified`，不得写成 `main` 已交付 |

以上是一次带时间戳的依赖快照，不是永久事实。进入公共 README、前端、最终截图或录屏前必须重新 fetch，并重新核对 PR head、合并状态、CI、review、OpenSpec 和证据来源。

## Worktree 现场状态

| 用途 | 状态 | 写入规则 |
|---|---|---|
| 面试展示主写 | `feature/interview-showcase@e84781a` | 当前唯一写入者；只写本 change tasks 与 `docs/interview-showcase/**` |
| 保存的 `main` worktree | `492d3dd`，落后于 `origin/main` | 不作为当前证据或集成写入者 |
| LPE 分支 worktree | `feature/local-product-experience@f021cf2`，落后于远端 PR #40 head | 不写；远端 `61398b7` 才是 PR 快照 |
| PR #40 只读快照 | detached `61398b7` | 只读参考，不修改 |
| 历史只读快照 | detached `3716c50` | 不作为当前完成证据 |

## 单一写入者与文件顺序

1. PR #59 owner 继续独占 `complete-managed-path-runtime`、managed path 实现与真实阶段 6–7；本 change 不修改其 artifacts 或任务状态。
2. PR #40 owner 继续独占 `improve-local-product-experience`、产品前端、根 README 和最终 LPE 素材；本 change 不修改其 artifacts 或任务状态。
3. 当前面试展示 owner 只写 `openspec/changes/prepare-interview-showcase/**` 与 `docs/interview-showcase/**`。
4. 只有 PR #59/#40 形成明确稳定基线、公共文件 owner 与合并顺序重新确认后，面试展示实现才可修改根 README、公共演示文档或前端。
5. Penpot 写入需要用户另行授权和唯一外部图纸写入者；当前阶段只允许引用已提交的离线、脱敏证据。

## 当前 blocker

- PR #59 尚未合并，真实阶段 6–7 没有精确资源授权；不得执行或声称真实网络写入、恢复和 A/B 完成。
- PR #40 尚未合并，最终 Overview/Chat/Operations 等页面承载能力不能作为稳定 `main` 能力。
- PR #59 虽为 `CLEAN` / `MERGEABLE`，但仍是 Draft，尚未进入合并裁决；PR #40 当前为 `DIRTY` / `CONFLICTING`。在各自 owner 完成门禁与基线处理前，本 change 不写根 README、产品前端、最终截图或录屏。
