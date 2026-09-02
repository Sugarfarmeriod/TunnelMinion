# 无模型降级验证记录

## 结论

在稳定基线 `b21b00e68e2298bb5db6a5c75d3e8629a33e4d05` 上，定向验证证明：模型不可用时，确定性的设备/服务资源路由和已有操作控制仍可用。

OpenSpec 任务 4.2 仍保持未完成。当前证据没有证明完整访问地址继续可见，也没有成品录屏可供核验“录屏播放不会被描述为当前现场成功”。

## 覆盖矩阵

| 要求 | 当前状态 | 证据或缺口 |
| --- | --- | --- |
| 设备/服务状态在无模型时继续可用 | 稳定 main 已验证 | `test_resource_routes_work_without_model_provider` 通过 |
| 已有操作入口在无模型时继续可用 | 稳定 main 已验证 | `test_approval_is_persistent_idempotent_and_does_not_require_model` 通过 |
| 访问地址在无模型时继续可用 | 未证明 | 当前 Overview 摘要只公开端口与可访问性，不公开 host；不能把端口冒充完整访问地址 |
| 录屏播放不冒充当前现场成功 | 未证明 | 现阶段只有文字门禁和离线分类规则，尚无最终录屏资产可验收 |

## 独立验证

验证工作树：`F:/Project/codex/tunnelminion-interview-showcase`

基线：`origin/main@b21b00e68e2298bb5db6a5c75d3e8629a33e4d05` 合入 PR #63 工作分支后的 `f347caa3bf1744e0c75954b5a42c65bc6653e96f`

结果：

- `uv run pytest --no-cov` 定向运行上述 2 项测试：`2 passed`。
- PR #40 合并前的前端与浏览器证据保留为历史来源；本轮没有为 4.2 重跑测试洪水。

## 发布边界

历史 manifest 为 [PR #40 无模型降级声明](manifests/pr40-no-model-degradation.json)。在访问地址得到实现与验证、并有真实录屏资产完成真实性标注核验以前：

- 不勾选任务 4.2；
- 不把本记录写成 `main-verified`；
- 不进入最终指标、最终截图或成功录屏；
- 不用离线 fixture、历史运行或端口字段替代缺失证据。
