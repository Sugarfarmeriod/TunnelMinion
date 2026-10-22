"""拿用户确认的标准答案给服务筛选规则打分。

    uv run python scripts/evaluate_service_filter.py .data/service-facts/mac-mini.json \
        .data/answer-keys/mac-mini.json

事实文件由 `collect_service_facts.py` 采集；两个文件都含本机信息，只保存在本地。
合格标准见 docs/design/node-agents.md："你要的服务"必须在显示或待确认里，
"显示"里不能混进标准答案以外的东西。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from tunnelminion.agent.service_tiers import ServiceTier, decide_tier
from tunnelminion.platforms.process_origin import ProcessFacts, classify_origin

_PUBLISHED = re.compile(r"(?:(?P<host>[\d.]+|\[[^\]]*\]|::):)?(?P<start>\d+)(?:-(?P<end>\d+))?->")
_RANK = {ServiceTier.SHOW: 2, ServiceTier.REVIEW: 1, ServiceTier.HIDE: 0}


def _compose_project(container: dict[str, Any]) -> str | None:
    for pair in str(container.get("Labels", "")).split(","):
        key, _, value = pair.partition("=")
        if key == "com.docker.compose.project" and value:
            return value
    return None


def _container_ports(docker: list[dict[str, Any]]) -> dict[int, tuple[str, bool, str]]:
    """主机端口 → (容器名, 是否在运行, 合并用的组名)。"""
    ports: dict[int, tuple[str, bool, str]] = {}
    for container in docker:
        running = str(container.get("State", "")).lower() == "running" or str(
            container.get("Status", "")
        ).startswith("Up")
        name = str(container.get("Names", ""))
        group = f"compose:{_compose_project(container) or name}"
        for match in _PUBLISHED.finditer(str(container.get("Ports", ""))):
            start = int(match.group("start"))
            end = int(match.group("end") or start)
            for port in range(start, end + 1):
                ports[port] = (name, running, group)
    return ports


def tier_by_port(facts: dict[str, Any]) -> dict[int, tuple[ServiceTier, str, str]]:
    """每个端口取最高的一档，记下是哪个程序，以及它在界面上会合并到哪一组。"""
    containers = _container_ports(facts["docker"])
    result: dict[int, tuple[ServiceTier, str, str]] = {}
    for listener in facts["listeners"]:
        port = int(listener["port"])
        raw = facts["facts"].get(str(listener["pid"]))
        origin = classify_origin(ProcessFacts(**raw)) if raw else None
        container = containers.get(port)
        tier = decide_tier(
            protocol=listener["protocol"],
            address=listener["address"],
            process_name=listener["name"],
            origin=origin,
            container_running=container[1] if container else None,
        )
        label = f"容器 {container[0]}" if container else f"{listener['name']}（{origin}）"
        group = container[2] if container else f"pid:{listener['pid']}"
        current = result.get(port)
        if current is None or _RANK[tier] > _RANK[current[0]]:
            result[port] = (tier, label, group)
    return result


def evaluate(facts: dict[str, Any], answer: dict[str, Any]) -> dict[str, Any]:
    tiers = tier_by_port(facts)
    wanted_ports = {port for item in answer["show"] for port in item["ports"]}
    # 与标准答案里的服务属于同一进程或同一 compose 项目的端口，界面上会合并成同一项。
    wanted_groups = {tiers[port][2] for port in wanted_ports if port in tiers}
    rows: list[dict[str, Any]] = []
    for item in answer["show"]:
        best = max(
            (tiers[port] for port in item["ports"] if port in tiers),
            key=lambda value: _RANK[value[0]],
            default=(ServiceTier.HIDE, "没有监听", ""),
        )
        rows.append({"name": item["name"], "tier": best[0].value, "by": best[1]})
    extras = sorted(
        f"{port} {label}"
        for port, (tier, label, group) in tiers.items()
        if tier is ServiceTier.SHOW and port not in wanted_ports and group not in wanted_groups
    )
    review = sorted(
        f"{port} {label}"
        for port, (tier, label, group) in tiers.items()
        if tier is ServiceTier.REVIEW and port not in wanted_ports and group not in wanted_groups
    )
    return {
        "machine": answer["machine"],
        "shown": sum(row["tier"] == "show" for row in rows),
        "review": sum(row["tier"] == "review" for row in rows),
        "missed": [row["name"] for row in rows if row["tier"] == "hide"],
        "extras": extras,
        "noise_in_review": review,
        "rows": rows,
        "passed": all(row["tier"] != "hide" for row in rows) and not extras,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("facts", type=Path)
    parser.add_argument("answer", type=Path)
    args = parser.parse_args(argv)
    report = evaluate(
        json.loads(args.facts.read_text(encoding="utf-8")),
        json.loads(args.answer.read_text(encoding="utf-8")),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
