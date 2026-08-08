"""前端发布暂存区测试。"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.stage_frontend import stage_frontend


def test_stage_frontend_replaces_stale_output(tmp_path: Path) -> None:
    source = tmp_path / "dist"
    assets = source / "assets"
    assets.mkdir(parents=True)
    (source / "index.html").write_text("app", encoding="utf-8")
    (assets / "main-hash.js").write_text("js", encoding="utf-8")
    destination = tmp_path / "build" / "frontend-dist"
    destination.mkdir(parents=True)
    (destination / "stale.js").write_text("stale", encoding="utf-8")

    files = stage_frontend(source, destination)

    assert files == (Path("assets/main-hash.js"), Path("index.html"))
    assert not (destination / "stale.js").exists()
    assert (destination / "assets" / "main-hash.js").read_text(encoding="utf-8") == "js"


def test_stage_frontend_rejects_missing_or_recursive_source(tmp_path: Path) -> None:
    source = tmp_path / "dist"
    source.mkdir()
    with pytest.raises(ValueError, match=r"index\.html"):
        stage_frontend(source, tmp_path / "build")

    (source / "index.html").write_text("app", encoding="utf-8")
    with pytest.raises(ValueError, match="内部"):
        stage_frontend(source, source / "nested")
