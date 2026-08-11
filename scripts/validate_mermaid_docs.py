"""校验受审 Mermaid 源，并生成或复核安全的离线 SVG。"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

RENDERER_PACKAGE = "@mermaid-js/mermaid-cli@11.16.0"
_FENCE = re.compile(r"^\s*```mermaid\s*$", re.IGNORECASE)
_UNSAFE_SOURCE = (
    (re.compile(r"(?i)%%\s*\{"), "Mermaid directive"),
    (re.compile(r"(?im)^\s*click\b"), "click handler"),
    (re.compile(r"(?i)foreignobject|<\s*/?\s*[a-z][^>]*>"), "HTML/foreignObject"),
    (re.compile(r"(?i)(?:https?|ftp|data|javascript):"), "external or executable URL"),
    (re.compile(r"(?i)\bscript\b"), "script token"),
    (re.compile(r"(?i)\bon[a-z]+\s*="), "event handler"),
    (re.compile(r"(?i)\bhref\s*="), "link attribute"),
)
_UNSAFE_SVG_TEXT = re.compile(
    r"(?i)<\s*/?\s*(?:script|foreignObject|iframe|object|embed|a)\b|"
    r"\bon[a-z]+\s*=|\b(?:href|src|action|formaction)\s*="
)
_EXTERNAL_VALUE = re.compile(r"(?i)(?:https?|ftp|data|javascript):")


@dataclass(frozen=True)
class Diagram:
    """一个 Markdown Mermaid 代码块。"""

    ordinal: int
    source: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.source.encode("utf-8")).hexdigest()


def extract_mermaid(text: str) -> list[Diagram]:
    """提取所有 Mermaid fenced blocks，并拒绝未闭合代码块。"""

    diagrams: list[Diagram] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if current is None:
            if _FENCE.match(line):
                current = []
            continue
        if line.strip() == "```":
            diagrams.append(Diagram(len(diagrams) + 1, "\n".join(current).strip() + "\n"))
            current = None
        else:
            current.append(line)
    if current is not None:
        raise ValueError("Mermaid fenced block is not closed")
    if not diagrams:
        raise ValueError("no Mermaid fenced block found")
    return diagrams


def validate_mermaid_source(source: str) -> None:
    """拒绝可执行、联网或可注入 HTML 的 Mermaid 源。"""

    first = next((line.strip() for line in source.splitlines() if line.strip()), "")
    if not re.match(r"^(?:flowchart|graph)\s+(?:LR|RL|TB|BT|TD)\b", first):
        raise ValueError("diagram must start with a flowchart direction")
    for pattern, reason in _UNSAFE_SOURCE:
        if pattern.search(source):
            raise ValueError(f"unsafe Mermaid source: {reason}")


def validate_svg(svg: str) -> ET.Element:
    """拒绝 SVG 中的脚本、HTML、事件处理器、链接和外部资源。"""

    if _UNSAFE_SVG_TEXT.search(svg):
        raise ValueError("unsafe content in generated SVG")
    try:
        root = ET.fromstring(svg)
    except ET.ParseError as exc:
        raise ValueError(f"invalid SVG XML: {exc}") from exc
    if root.tag.rsplit("}", 1)[-1].lower() != "svg":
        raise ValueError("SVG root element is not svg")
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].lower()
        if local_name in {"script", "foreignobject", "iframe", "object", "embed", "a"}:
            raise ValueError(f"unsafe SVG element: {local_name}")
        for name, value in element.attrib.items():
            lowered = name.rsplit("}", 1)[-1].lower()
            if lowered.startswith("on") or lowered in {"href", "src", "action", "formaction"}:
                raise ValueError(f"unsafe SVG attribute: {name}")
            if _EXTERNAL_VALUE.search(value):
                raise ValueError("external or executable SVG resource")
    return root


def _expected_svg_paths(document: Path, output_dir: Path, count: int) -> list[Path]:
    return [output_dir / f"{document.stem}-{index:02d}.svg" for index in range(1, count + 1)]


def stamp_svg(svg: str, diagram: Diagram) -> str:
    validate_svg(svg)
    marker = "<svg "
    if marker not in svg:
        raise ValueError("generated SVG has no root start tag")
    stamped = svg.replace(
        marker,
        (f'<svg data-source-sha256="{diagram.sha256}" data-renderer="{RENDERER_PACKAGE}" '),
        1,
    )
    validate_svg(stamped)
    return stamped


def _render(diagram: Diagram, config: Path) -> str:
    npx = shutil.which("npx")
    if npx is None:
        raise ValueError("npx is required only for --write")
    with tempfile.TemporaryDirectory(prefix="tunnelminion-mermaid-") as directory:
        temporary = Path(directory)
        source = temporary / "diagram.mmd"
        output = temporary / "diagram.svg"
        source.write_text(diagram.source, encoding="utf-8", newline="\n")
        command = [
            npx,
            "--yes",
            "--package",
            RENDERER_PACKAGE,
            "mmdc",
            "--input",
            str(source),
            "--output",
            str(output),
            "--configFile",
            str(config.resolve()),
            "--theme",
            "neutral",
            "--backgroundColor",
            "transparent",
            "--quiet",
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "renderer failed").strip()
            raise ValueError(f"Mermaid renderer failed: {detail}") from exc
        if not output.is_file():
            raise ValueError("Mermaid renderer did not create SVG")
        return stamp_svg(output.read_text(encoding="utf-8"), diagram)


def run(document: Path, output_dir: Path, config: Path, *, write: bool) -> None:
    """生成 SVG，或离线复核现有 SVG 与 Mermaid 源摘要一致。"""

    diagrams = extract_mermaid(document.read_text(encoding="utf-8"))
    for diagram in diagrams:
        validate_mermaid_source(diagram.source)
    if not config.is_file():
        raise ValueError(f"missing Mermaid config: {config}")

    expected = _expected_svg_paths(document, output_dir, len(diagrams))
    output_dir.mkdir(parents=True, exist_ok=True)
    expected_names = {path.name for path in expected}
    extras = sorted(
        path.name for path in output_dir.glob("*.svg") if path.name not in expected_names
    )
    if extras:
        raise ValueError(f"unexpected SVG files: {', '.join(extras)}")

    for diagram, path in zip(diagrams, expected, strict=True):
        if write:
            path.write_text(_render(diagram, config), encoding="utf-8", newline="\n")
            continue
        if not path.is_file():
            raise ValueError(f"missing generated SVG: {path}")
        root = validate_svg(path.read_text(encoding="utf-8"))
        if root.attrib.get("data-source-sha256") != diagram.sha256:
            raise ValueError(f"stale generated SVG: {path}")
        if root.attrib.get("data-renderer") != RENDERER_PACKAGE:
            raise ValueError(f"unexpected SVG renderer: {path}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    parser.add_argument("--svg-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="用固定版本 Mermaid CLI 生成 SVG")
    mode.add_argument("--check", action="store_true", help="离线检查 SVG 摘要与安全属性")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    try:
        run(args.document, args.svg_dir, args.config, write=args.write)
    except (OSError, ValueError) as exc:
        print(f"Mermaid validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Mermaid diagrams passed: {args.document}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
