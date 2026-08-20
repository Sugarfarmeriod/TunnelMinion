"""离线验证面试展示的 fixture 与声明分类边界。"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent
EXPECTED_CATEGORIES = {
    "model-unavailable",
    "node-offline",
    "tool-timeout",
    "duplicate-event",
    "out-of-order-event",
    "conflicting-evidence",
    "operation-unapproved",
    "execution-failed",
    "recovery-failed",
}


def load_json(path: Path) -> Any:
    """读取 UTF-8 JSON。"""
    return json.loads(path.read_text(encoding="utf-8"))


def validate_json(instance: Any, schema: dict[str, Any], label: str) -> None:
    """使用 Draft 2020-12 和格式检查器验证一个实例。"""
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(instance),  # pyright: ignore[reportUnknownMemberType]
        key=lambda error: list(error.path),
    )
    if errors:
        details = "; ".join(f"{list(error.path)}: {error.message}" for error in errors)
        raise ValueError(f"{label} 验证失败：{details}")


def verify_fixtures() -> int:
    """验证失败 fixture 的格式、覆盖面和发布禁用标记。"""
    fixture_schema = load_json(ROOT / "fixtures" / "failure-scenarios.schema.json")
    Draft202012Validator.check_schema(fixture_schema)
    fixture_set = load_json(ROOT / "fixtures" / "failure-scenarios.json")
    validate_json(fixture_set, fixture_schema, "failure-scenarios.json")

    scenarios = fixture_set["scenarios"]
    categories = {scenario["category"] for scenario in scenarios}
    if categories != EXPECTED_CATEGORIES:
        missing = sorted(EXPECTED_CATEGORIES - categories)
        extra = sorted(categories - EXPECTED_CATEGORIES)
        raise ValueError(f"fixture 分类不完整：missing={missing}, extra={extra}")
    if len(scenarios) != len(categories):
        raise ValueError("每个失败分类必须且只能有一个基准场景")
    return len(scenarios)


def verify_manifest_boundary(manifest: dict[str, Any], label: str) -> None:
    """根据来源和证据内容检查声明分类，避免只信一个可伪造字段。"""
    publication = manifest["publication"]
    is_publishable = (
        publication["include_in_final_metrics"] or publication["include_in_success_media"]
    )
    source = manifest["source"]
    environment = manifest["scope"]["environment"].lower()
    evidence_kinds = {item["kind"] for item in manifest.get("evidence", [])}
    source_ref = source["ref"].lower()
    serialized = json.dumps(manifest, ensure_ascii=False).lower()
    is_historical = "historical" in serialized or "历史" in serialized
    is_fixture = (
        source["kind"] == "fixture"
        or "fixture" in environment
        or "fixture" in evidence_kinds
        or "/fixtures/" in source_ref.replace("\\", "/")
        or "/fixtures/" in serialized.replace("\\", "/")
        or "failure-scenarios.json" in serialized
        or "离线失败场景" in serialized
    )
    is_draft_pr = (
        not is_historical
        and not is_fixture
        and (
            source["kind"] == "pull-request"
            or "pr_number" in source
            or source_ref.startswith("feature/")
            or re.search(r"\bpr\s*#?\s*\d+\b", serialized) is not None
        )
    )

    if is_fixture and (manifest["status"] != "planned" or is_publishable):
        raise ValueError(f"{label}: fixture 必须保持 planned 且禁止发布")
    if is_draft_pr and (manifest["status"] != "draft-pr-verified" or is_publishable):
        raise ValueError(f"{label}: Draft PR 只能是 draft-pr-verified 且禁止发布")
    if is_historical and (
        manifest["status"] not in {"planned", "prohibited-claim"} or is_publishable
    ):
        raise ValueError(f"{label}: 历史证据不得成为可发布的 main-verified 声明")
    if manifest["status"] == "prohibited-claim" and is_publishable:
        raise ValueError(f"{label}: prohibited-claim 不得发布")


def verify_manifest(manifest: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    """同时执行 JSON Schema 与来源语义检查。"""
    validate_json(manifest, schema, label)
    verify_manifest_boundary(manifest, label)


def verify_rejections(schema: dict[str, Any]) -> int:
    """用错标反例证明 fixture、Draft 和历史证据不能进入发布声明。"""
    cases = [
        ("fixture", ROOT / "manifests" / "fixture-classification.json"),
        ("draft-pr", ROOT / "manifests" / "draft-pr-classification.json"),
        ("historical", ROOT / "manifests" / "historical-classification.json"),
    ]
    for label, path in cases:
        manifest = copy.deepcopy(load_json(path))
        manifest["status"] = "main-verified"
        manifest["source"]["kind"] = "main"
        manifest["source"]["ref"] = "origin/main"
        manifest["source"]["commit_role"] = "contains-claim-source"
        manifest["source"].pop("pr_number", None)
        manifest["scope"]["environment"] = "repository"
        for evidence in manifest.get("evidence", []):
            evidence["kind"] = "report"
        manifest["publication"]["include_in_success_media"] = True
        try:
            verify_manifest(manifest, schema, f"{label}-negative-case")
        except ValueError:
            continue
        raise ValueError(f"{label} 错标反例未被拒绝")
    return len(cases)


def verify_manifests() -> tuple[int, int]:
    """验证所有声明，并运行来源错标反例。"""
    evidence_schema = load_json(ROOT / "evidence-manifest.schema.json")
    Draft202012Validator.check_schema(evidence_schema)

    paths = sorted((ROOT / "manifests").glob("*.json"))
    if not paths:
        raise ValueError("没有可验证的声明分类样例")

    for path in paths:
        manifest = load_json(path)
        verify_manifest(manifest, evidence_schema, path.name)
    return len(paths), verify_rejections(evidence_schema)


def main() -> None:
    """运行全部离线门禁。"""
    fixture_count = verify_fixtures()
    manifest_count, rejection_count = verify_manifests()
    print(f"fixture 场景通过：{fixture_count}")
    print(f"声明分类通过：{manifest_count}")
    print(f"错标反例已拒绝：{rejection_count}")


if __name__ == "__main__":
    main()
