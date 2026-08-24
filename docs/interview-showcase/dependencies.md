# 面试展示依赖与写入边界

## 现场快照

采集时间：`2026-08-24T20:57:09+08:00`

| 对象 | 精确版本 | 状态 | OpenSpec | CI / review | 展示分类 |
|---|---|---|---|---|---|
| `origin/main` | `fe0f6b0601d53bc895558ee9d0b586858bad6063` | PR #59 已合并；managed-path 阶段 1–5 已进入主线 | `complete-managed-path-runtime` 35/47；阶段 6–7 共 12 项仍未完成；`prepare-interview-showcase` 仍为 0/24 | PR #59 run `32723190276` Windows/macOS 全绿，独立 Sol/xhigh 终审 ACCEPT | `main-verified`，仅覆盖已合并的 managed-path 阶段 1–5 与展示规划 |
| PR #63 `feature/interview-showcase` | `a637e175b61c1f5cb4f69fcff4b8847fb3706ec3` | Draft/Open，`CLEAN` / `MERGEABLE`；本轮刷新前工作树与远端一致 | `prepare-interview-showcase` 12/24；`main` 仍为 0/24 | run `32352238790` Windows/macOS 成功；已完成工作包经独立审计 ACCEPT；0 GitHub review | `draft-pr-verified`，前置工作包不可作为最终展示成果 |
| PR #59 `feature/managed-path-governance-lifecycle` | `535e2ff2ad7f02d46413b911e181a8e568230437` | 已于 `2026-08-24` 合并，merge commit 为 `fe0f6b0` | 合并时 `complete-managed-path-runtime` 35/47；阶段 6–7 未授权且未勾选 | run `32723190276` 成功，独立 Sol/xhigh 终审 ACCEPT | 已合并部分为 `main-verified`；阶段 6–7 仍为 `prohibited-claim` |
| PR #40 `feature/local-product-experience` | `72869f81d064e2672bebbe6d15bfc237c72f47c6` | Draft/Open，`CLEAN` / `MERGEABLE`；已集成 PR #59 并修复 Overview managed-path 装配缺口 | `improve-local-product-experience` 52/55；8.5、8.8、8.9 未完成 | run `32728631826` 八项全绿；独立 Sol/xhigh 首审 REJECT、修复后复审 ACCEPT；0 GitHub review | `draft-pr-verified`，不得写成 `main` 已交付或已完成真实 A/B |

以上是一次带时间戳的依赖快照，不是永久事实。进入公共 README、前端、最终截图或录屏前必须重新 fetch，并重新核对 PR head、合并状态、CI、review、OpenSpec 和证据来源。

## Worktree 现场状态

| 用途 | 状态 | 写入规则 |
|---|---|---|
| 面试展示主写 | `feature/interview-showcase@a637e17` | 当前唯一写入者；只写本 change tasks 与 `docs/interview-showcase/**`；本轮从远端精确 head 建立独立 worktree |
| 保存的 `main` worktree | `492d3dd`，与 `origin/main@fe0f6b0` 不一致 | 不作为当前证据或集成写入者，不覆盖或重置 |
| LPE 分支 worktree | `feature/local-product-experience@72869f8` | PR #40 唯一写入者；工作树干净且与远端一致，本 change 只读引用 |
| PR #40 历史只读快照 | detached `61398b7` | 只读历史参考，不作为当前证据或写入者 |
| managed-path 阶段 worktree | `fix/managed-path-prefix-ownership@535e2ff` | 历史集成工作树；PR #59 已合并，不作为阶段 6–7 授权 |

## 单一写入者与文件顺序

1. PR #59 owner 继续独占 `complete-managed-path-runtime`、managed path 实现与真实阶段 6–7；本 change 不修改其 artifacts 或任务状态。
2. PR #40 owner 继续独占 `improve-local-product-experience`、产品前端、根 README 和最终 LPE 素材；本 change 不修改其 artifacts 或任务状态。
3. 当前面试展示 owner 只写 `openspec/changes/prepare-interview-showcase/**` 与 `docs/interview-showcase/**`。
4. 只有 PR #59/#40 形成明确稳定基线、公共文件 owner 与合并顺序重新确认后，面试展示实现才可修改根 README、公共演示文档或前端。
5. Penpot 写入需要用户另行授权和唯一外部图纸写入者；当前阶段只允许引用已提交的离线、脱敏证据。

## 当前 blocker

- PR #59 已合并，但真实阶段 6–7 仍缺少人工批准的独立接口、地址、host route、UDP 端口、数据目录、L3 授权有效期和停止方式；不得执行或声称真实网络写入、故障注入、恢复和 A/B 完成。
- PR #40 已消除冲突并通过 CI/独立复审，但仍为 Draft，8.5、8.8、8.9 未完成；Overview/Chat/Operations 等页面仍只能标为 `draft-pr-verified`。
- PR #63 的离线规划、fixture、图纸、评估契约与 Draft 预审均已通过当前 CI，但 3.1、3.2、4.2、4.3、阶段 5–6 仍受 PR #40 合并、真实模型基线或精确资源授权门禁约束；不得因 PR 自身 `CLEAN` 就提前转为最终交付。
