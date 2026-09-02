# 面试展示工作包

本目录承载 `prepare-interview-showcase` 的独立实现材料。首版只组织现有 A/B 安全闭环，不改变 Agent、网络、授权、模型或跨节点协议语义。

- [依赖与写入边界](dependencies.md)
- [声明到证据 manifest schema](evidence-manifest.schema.json)
- [manifest 示例](evidence-manifest.example.json)
- [主演示与技术深挖脚本](storyboard.md)
- [根 README 展示结构稿](readme-outline.md)
- [稳定 main 产品页面承载复核](product-surface-review.md)
- [展示素材台账](asset-inventory.md)
- [无模型降级验证记录](no-model-verification.md)
- [离线 Mermaid / SVG 图纸与 manifest](diagrams/diagram-assets.json)
- [离线评估契约与 fixture 基线](evaluation-plan.md)
- [离线失败 fixture](fixtures/failure-scenarios.json)
- [声明分类样例](manifests)

运行 `uv run python docs/interview-showcase/verify_evidence.py` 可离线校验 schema、失败场景覆盖和声明分类边界；运行 `uv run python docs/interview-showcase/verify_diagrams.py` 可校验 Mermaid/SVG 追溯关系与外部引用风险；运行 `uv run python docs/interview-showcase/verify_evaluation.py` 可复算 fixture 基线；另外两个小检查验证 README 结构和稳定 main 页面承载结论。

本目录仍不是最终 README、截图、录屏或真实 A/B 成果。真实模型基线和真实资源门禁完成前，对应声明保持 `planned` 或 `prohibited-claim`。
