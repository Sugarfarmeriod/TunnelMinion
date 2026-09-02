# 无模型降级验证记录

## 结论

在稳定基线 `6c20fda5aa57f6f178569fc1aa1f5a34df65b3d2` 上，定向验证证明：模型不可用时，确定性的设备/服务资源路由、完整只读访问地址和已有操作控制仍可用。

OpenSpec 任务 4.2 已完成。README 结构检查固定要求“不得播放录屏并称为当前成功”；最终录屏本身仍属于阶段 5 素材，不因本任务完成而冒充已经采集。

## 覆盖矩阵

| 要求 | 当前状态 | 证据或缺口 |
| --- | --- | --- |
| 设备/服务状态在无模型时继续可用 | 稳定 main 已验证 | `test_resource_routes_work_without_model_provider` 通过 |
| 已有操作入口在无模型时继续可用 | 稳定 main 已验证 | `test_approval_is_persistent_idempotent_and_does_not_require_model` 通过 |
| 访问地址在无模型时继续可用 | 稳定 main 已验证 | 地址由确定性服务摘要组成，与模型 Provider 无关；后端格式化和 Overview 展示测试通过 |
| 录屏播放不冒充当前现场成功 | 发布门禁已验证 | `verify_readme_outline.py` 强制要求该禁语义；最终录屏仍保持 `planned`，待阶段 5 逐帧验收 |

## 独立验证

验证工作树：`F:/Project/codex/tunnelminion-interview-showcase`

基线：`origin/main@6c20fda5aa57f6f178569fc1aa1f5a34df65b3d2` 合入 PR #63 工作分支后的当前提交

结果：

- `uv run pytest --no-cov` 定向运行资源、操作与地址格式化测试。
- `npm test -- --run` 定向运行 Overview schema/组件与 Chat Operation 链接测试。
- `verify_readme_outline.py` 与 `verify_product_surface_review.py` 验证展示禁语义与页面承载结论。
- PR #66 CI run `33610222010` 的 8 项双平台门禁全绿；本轮不重复真实网络或 Provider 操作。

## 发布边界

历史 manifest 为 [PR #40 无模型降级声明](manifests/pr40-no-model-degradation.json)。4.2 完成不改变最终素材门禁：

- 本记录只支持任务 4.2，不支持真实模型指标或真实 A/B；
- 不进入最终指标、最终截图或成功录屏；
- 不用离线 fixture、历史运行或地址字段替代真实执行证据。
