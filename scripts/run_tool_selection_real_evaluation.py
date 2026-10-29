"""对真实模型做挑工具前后对比：A 全部工具给模型，B 按问题挑工具并可设工具上限。

不进 CI。工具全部是固定返回值的假工具，不访问这台电脑；只有模型调用是真的。
地址和模型名从参数读取，密钥只从 TunnelMinion 已保存的密钥环读取，报告里不写地址。

用法示例（本机 Qwen，关闭思考，B 组上限 5，每组 3 轮）：

    uv run python scripts/run_tool_selection_real_evaluation.py \
        --endpoint http://127.0.0.1:8080/v1 --model qwen-local --disable-thinking \
        --label qwen-local --max-tools 5 --rounds 3 \
        --output-dir evaluations/reports/tool-selection-qwen-<日期>
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from tunnelminion.agent.tool_selection import ToolSelectionSettings
from tunnelminion.evaluation.tool_selection import (
    RealCaseRun,
    build_agent,
    build_registry,
    case_inputs,
    failed_run,
    load_dataset,
    score_run,
    summarize,
    summary_markdown,
)
from tunnelminion.model.configuration import model_api_key_name
from tunnelminion.model.contracts import (
    CancellationToken,
    ModelCapabilities,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderError,
)
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleProvider
from tunnelminion.model.secrets import KeyringSecretStore

DEFAULT_DATASET = Path("evaluations/datasets/tool-selection-v1.json")


class RecordingProvider:
    """转发给真实模型，同时记下模型请求过的工具名（含 request_more_tools）。"""

    def __init__(self, inner: ModelProvider) -> None:
        self._inner = inner
        self.requested: list[str] = []

    @property
    def capabilities(self) -> ModelCapabilities:
        return self._inner.capabilities

    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        response = await self._inner.complete(request, cancellation)
        self.requested.extend(call.name for call in response.tool_calls)
        return response


async def _run(args: argparse.Namespace) -> tuple[RealCaseRun, ...]:
    dataset = load_dataset(args.dataset)
    cases = tuple(
        case for case in dataset.cases if not args.cases or case.case_id in set(args.cases)
    )
    registry = build_registry(dataset.tool_outputs)
    config = OpenAICompatibleConfig(
        endpoint=args.endpoint,
        model=args.model,
        timeout_seconds=args.timeout,
        disable_thinking=args.disable_thinking,
    )
    api_key = (
        KeyringSecretStore().get(model_api_key_name(config.endpoint))
        if args.configured_api_key
        else None
    )
    variants = {
        "A-全部工具": ToolSelectionSettings(focus=False),
        "B-按问题挑": ToolSelectionSettings(max_tools=args.max_tools),
    }
    runs: list[RealCaseRun] = []
    for round_index in range(1, args.rounds + 1):
        for case in cases:
            for variant, settings in variants.items():
                provider = RecordingProvider(OpenAICompatibleProvider(config, api_key))
                agent = build_agent(provider, registry, settings)
                context, allowed, target = case_inputs(case)
                try:
                    result = await agent.run(case.question, context, allowed, target=target)
                except ProviderError as exc:
                    # 一次模型调用失败只记这一条，不中断整轮对比。
                    runs.append(failed_run(case, variant, round_index, exc.code.value))
                    print(f"[{round_index}] {variant} {case.case_id}: 模型调用失败 {exc.code}")
                    continue
                run = score_run(case, variant, round_index, result, tuple(provider.requested))
                runs.append(run)
                print(
                    f"[{round_index}] {variant} {case.case_id}: "
                    f"first={run.first_tool} ok={run.first_tool_ok} "
                    f"missing_claim={run.claimed_missing_tool}"
                )
    return tuple(runs)


def main(argv: Sequence[str] | None = None) -> int:
    """跑完写出逐条结果、汇总 JSON 和一页中文摘要。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--label", required=True, help="报告里显示的模型名称，不写地址")
    parser.add_argument("--disable-thinking", action="store_true")
    parser.add_argument("--configured-api-key", action="store_true")
    parser.add_argument("--max-tools", type=int, default=None)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--cases", nargs="*", default=())
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    runs = asyncio.run(_run(args))
    summaries = summarize(runs)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "runs.json").write_text(
        json.dumps(
            {
                "label": args.label,
                "max_tools": args.max_tools,
                "rounds": args.rounds,
                "runs": [item.model_dump(mode="json") for item in runs],
                "summaries": [item.model_dump(mode="json") for item in summaries],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    markdown = summary_markdown(args.label, summaries)
    (args.output_dir / "summary.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
