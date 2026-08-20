"""离线验证面试展示图源、SVG 导出物与追溯 manifest。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TypedDict, cast
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent
DIAGRAM_ROOT = ROOT / "diagrams"
MANIFEST_PATH = DIAGRAM_ROOT / "diagram-assets.json"
FORBIDDEN_TAGS = {"script", "style", "foreignObject", "image", "use"}
FORBIDDEN_RAW_MARKERS = ("<!doctype", "<!entity", "<?xml-stylesheet", "@import")


class PenpotState(TypedDict):
    """外部可编辑图源的授权状态。"""

    role: str
    write_status: str
    notes: str


class DiagramAsset(TypedDict):
    """一组 Mermaid 语义源与仓库 SVG 导出物。"""

    id: str
    purpose: str
    source: str
    output: str
    rendering: str
    source_sha256: str
    output_sha256: str
    required_labels: list[str]


class DiagramManifest(TypedDict):
    """图纸追溯 manifest。"""

    schema_version: int
    publication_status: str
    authoring_baseline: str
    generated_at: str
    hash_normalization: str
    penpot: PenpotState
    assets: list[DiagramAsset]


def _digest(path: Path) -> str:
    normalized_text = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()


def _assert_safe_relative_path(relative_path: str) -> Path:
    path = (DIAGRAM_ROOT / relative_path).resolve()
    if DIAGRAM_ROOT.resolve() not in path.parents:
        raise ValueError(f"图纸路径越界：{relative_path}")
    if not path.is_file():
        raise ValueError(f"图纸文件不存在：{relative_path}")
    return path


def _svg_text_and_safety(path: Path) -> str:
    raw_svg = path.read_text(encoding="utf-8")
    normalized_svg = raw_svg.casefold()
    if any(marker in normalized_svg for marker in FORBIDDEN_RAW_MARKERS):
        raise ValueError(f"SVG 含外部样式或实体声明：{path.name}")

    root = ElementTree.parse(path).getroot()
    if root.tag.rsplit("}", 1)[-1] != "svg":
        raise ValueError(f"不是 SVG 根元素：{path.name}")
    if root.attrib.get("role") != "img" or "viewBox" not in root.attrib:
        raise ValueError(f"SVG 缺少可访问角色或 viewBox：{path.name}")

    text_parts: list[str] = []
    tags: set[str] = set()
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        tags.add(tag)
        if element.text:
            text_parts.append(element.text.strip())
        for name, value in element.attrib.items():
            local_name = name.rsplit("}", 1)[-1]
            normalized_value = value.casefold()
            if local_name == "href" and not value.startswith("#"):
                raise ValueError(f"SVG 含外部引用：{path.name}")
            if "url(" in normalized_value and "url(#" not in normalized_value:
                raise ValueError(f"SVG 含非本地 URL：{path.name}")

    risky_tags = tags & FORBIDDEN_TAGS
    if risky_tags:
        raise ValueError(f"SVG 含高风险元素 {sorted(risky_tags)}：{path.name}")
    if "title" not in tags or "desc" not in tags:
        raise ValueError(f"SVG 缺少 title/desc：{path.name}")
    return " ".join(text_parts)


def main() -> None:
    manifest = cast(
        DiagramManifest,
        json.loads(MANIFEST_PATH.read_text(encoding="utf-8")),
    )
    if manifest["schema_version"] != 1:
        raise ValueError("图纸 manifest schema_version 必须为 1")
    if manifest["publication_status"] != "planned":
        raise ValueError("当前图纸只能标记为 planned")
    if manifest["hash_normalization"] != "utf8-lf":
        raise ValueError("图纸 manifest 必须使用跨平台 utf8-lf 哈希")
    if manifest["penpot"]["write_status"] != "not-authorized":
        raise ValueError("未获授权时 Penpot 必须保持 not-authorized")

    assets = manifest["assets"]
    if len(assets) != 2:
        raise ValueError("必须登记生命周期图和授权边界图两项资产")

    for asset in assets:
        source = _assert_safe_relative_path(asset["source"])
        output = _assert_safe_relative_path(asset["output"])
        if source.suffix != ".mmd" or output.suffix != ".svg":
            raise ValueError(f"图源/导出格式不正确：{asset['id']}")
        if _digest(source) != asset["source_sha256"]:
            raise ValueError(f"Mermaid 哈希不匹配：{asset['id']}")
        if _digest(output) != asset["output_sha256"]:
            raise ValueError(f"SVG 哈希不匹配：{asset['id']}")

        source_text = source.read_text(encoding="utf-8")
        svg_text = _svg_text_and_safety(output)
        for label in asset["required_labels"]:
            if label not in source_text or label not in svg_text:
                raise ValueError(f"必需语义标签缺失 {label!r}：{asset['id']}")
        if "planned" not in svg_text or "不代表 main 已交付" not in svg_text:
            raise ValueError(f"SVG 缺少 Draft 发布边界：{asset['id']}")

    print(f"图纸离线验证通过：{len(assets)} 项")


if __name__ == "__main__":
    main()
