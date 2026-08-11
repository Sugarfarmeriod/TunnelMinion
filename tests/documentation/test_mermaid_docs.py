from __future__ import annotations

from pathlib import Path

import pytest
from scripts.validate_mermaid_docs import (
    RENDERER_PACKAGE,
    Diagram,
    extract_mermaid,
    run,
    stamp_svg,
    validate_mermaid_source,
    validate_svg,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
ARCHITECTURE_DOC = REPOSITORY_ROOT / "docs" / "architecture.md"
ARCHITECTURE_SVG_DIR = REPOSITORY_ROOT / "docs" / "assets" / "architecture"
MERMAID_CONFIG = REPOSITORY_ROOT / "docs" / "mermaid-config.json"


def test_architecture_mermaid_and_svg_are_current_safe_and_linked() -> None:
    document = ARCHITECTURE_DOC.read_text(encoding="utf-8")
    run(ARCHITECTURE_DOC, ARCHITECTURE_SVG_DIR, MERMAID_CONFIG, write=False)
    diagrams = extract_mermaid(document)
    assert len(diagrams) == 2
    for index, diagram in enumerate(diagrams, start=1):
        relative_path = f"assets/architecture/architecture-{index:02d}.svg"
        assert f"]({relative_path})" in document
        svg_path = ARCHITECTURE_DOC.parent / relative_path
        assert svg_path.is_file()
        svg = svg_path.read_text(encoding="utf-8")
        root = validate_svg(svg)
        assert root.attrib["data-source-sha256"] == diagram.sha256
        assert root.attrib["data-renderer"] == RENDERER_PACKAGE
        assert "marker" in svg
        assert "foreignobject" not in svg.lower()


@pytest.mark.parametrize(
    ("snippet", "reason"),
    [
        ("%%{init: {'theme': 'dark'}}", "directive"),
        ("click node call()", "click"),
        ('node["<b>unsafe</b>"]', "HTML"),
        ('node["https://example.test"]', "URL"),
        ("node[script]", "script"),
        ('node["x"]\nclassDef danger fill:red;\nnode:::danger', "valid style"),
    ],
)
def test_mermaid_source_rejects_unsafe_constructs(snippet: str, reason: str) -> None:
    source = f"flowchart LR\n    {snippet}\n"
    if reason == "valid style":
        validate_mermaid_source(source)
    else:
        with pytest.raises(ValueError, match="unsafe Mermaid source"):
            validate_mermaid_source(source)


@pytest.mark.parametrize(
    "unsafe",
    [
        '<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject/></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg" onclick="run()"/>',
        '<svg xmlns="http://www.w3.org/2000/svg"><a href="https://example.test"/></svg>',
    ],
)
def test_svg_rejects_executable_or_external_content(unsafe: str) -> None:
    with pytest.raises(ValueError, match="unsafe"):
        validate_svg(unsafe)


def test_run_detects_stale_extra_and_wrong_renderer(tmp_path: Path) -> None:
    document = tmp_path / "diagram.md"
    output = tmp_path / "svg"
    config = tmp_path / "mermaid.json"
    source = "flowchart LR\n a[A] --> b[B]\n"
    document.write_text(f"```mermaid\n{source}```\n", encoding="utf-8")
    config.write_text("{}\n", encoding="utf-8")
    output.mkdir()
    diagram = Diagram(1, source)
    generated = output / "diagram-01.svg"
    generated.write_text(
        stamp_svg('<svg xmlns="http://www.w3.org/2000/svg"><text>A</text></svg>', diagram),
        encoding="utf-8",
    )
    run(document, output, config, write=False)

    document.write_text("```mermaid\nflowchart LR\n a[A] --> c[C]\n```\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale generated SVG"):
        run(document, output, config, write=False)

    document.write_text(f"```mermaid\n{source}```\n", encoding="utf-8")
    generated.write_text(
        generated.read_text(encoding="utf-8").replace(RENDERER_PACKAGE, "other-renderer"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unexpected SVG renderer"):
        run(document, output, config, write=False)

    generated.write_text(
        stamp_svg('<svg xmlns="http://www.w3.org/2000/svg"/>', diagram), encoding="utf-8"
    )
    (output / "unexpected.svg").write_text("<svg/>", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected SVG"):
        run(document, output, config, write=False)


def test_extract_mermaid_rejects_unclosed_fence() -> None:
    with pytest.raises(ValueError, match="not closed"):
        extract_mermaid("```mermaid\nflowchart LR\n a[A] --> b[B]\n")
