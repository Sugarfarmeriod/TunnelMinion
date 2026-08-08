"""唯一前端暂存区及构建回执测试。"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Sequence
from pathlib import Path

import pytest
from scripts import prepare_frontend_dist as frontend_dist


def _frontend_project(root: Path) -> None:
    source = root / "frontend/src"
    source.mkdir(parents=True)
    for relative, content in {
        "frontend/index.html": "<div id='root'></div>",
        "frontend/.npmrc": "engine-strict=true",
        "frontend/package.json": "{}",
        "frontend/package-lock.json": '{"lockfileVersion": 3}',
        "frontend/tsconfig.json": "{}",
        "frontend/vite.config.ts": "export default {};",
        "frontend/src/main.ts": "export {};",
    }.items():
        (root / relative).write_text(content, encoding="utf-8")


def test_prepare_is_clean_first_and_receipt_detects_changes(tmp_path: Path) -> None:
    _frontend_project(tmp_path)
    stale_source = tmp_path / "frontend/dist/stale.js"
    stale_source.parent.mkdir(parents=True)
    stale_source.write_text("stale", encoding="utf-8")
    stale_destination = tmp_path / "build/frontend-dist/stale.js"
    stale_destination.parent.mkdir(parents=True)
    stale_destination.write_text("stale", encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def run(command: Sequence[str], cwd: Path) -> None:
        assert cwd == tmp_path
        commands.append(tuple(command))
        if command[-1] == "build":
            assets = cwd / "frontend/dist/assets"
            assets.mkdir(parents=True)
            (cwd / "frontend/dist/index.html").write_text("fresh", encoding="utf-8")
            (assets / "app.js").write_text("export {};", encoding="utf-8")

    receipt = frontend_dist.prepare_frontend_dist(tmp_path, run=run)
    npm = frontend_dist._npm_executable()  # pyright: ignore[reportPrivateUsage]
    assert commands == [
        (npm, "--prefix", "frontend", "ci"),
        (npm, "--prefix", "frontend", "run", "build"),
    ]
    assert receipt["file_count"] == 2
    assert not stale_source.exists()
    assert not stale_destination.exists()
    assert frontend_dist.verify_frontend_dist(tmp_path) == receipt

    (tmp_path / "frontend/src/main.ts").write_text("export const changed = 1;", encoding="utf-8")
    with pytest.raises(ValueError, match="不匹配"):
        frontend_dist.verify_frontend_dist(tmp_path)


def test_verify_rejects_missing_bad_or_tampered_receipt(tmp_path: Path) -> None:
    _frontend_project(tmp_path)
    with pytest.raises(ValueError, match="缺少可信"):
        frontend_dist.verify_frontend_dist(tmp_path)

    destination = tmp_path / "build/frontend-dist"
    destination.mkdir(parents=True)
    (destination / "index.html").write_text("ok", encoding="utf-8")
    receipt = tmp_path / "build/frontend-dist-receipt.json"
    receipt.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="格式无效"):
        frontend_dist.verify_frontend_dist(tmp_path)

    receipt.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
    with pytest.raises(ValueError, match="不匹配"):
        frontend_dist.verify_frontend_dist(tmp_path)


def test_tree_digest_rejects_empty_and_symlink(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="没有可摘要"):
        frontend_dist.tree_sha256(tmp_path)
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("当前平台不允许创建测试符号链接")
    with pytest.raises(ValueError, match="符号链接"):
        frontend_dist.tree_sha256(tmp_path)


def test_wheel_must_contain_the_exact_staged_frontend(tmp_path: Path) -> None:
    _frontend_project(tmp_path)

    def run(command: Sequence[str], cwd: Path) -> None:
        del command
        destination = cwd / "frontend/dist"
        destination.mkdir(parents=True)
        (destination / "index.html").write_text("wheel-ui", encoding="utf-8")

    frontend_dist.prepare_frontend_dist(tmp_path, install=False, run=run)
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.write(
            tmp_path / "build/frontend-dist/index.html",
            "tunnelminion/web/ui/index.html",
        )
    frontend_dist.verify_wheel_frontend(tmp_path, wheel)

    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("tunnelminion/web/ui/index.html", "tampered")
    with pytest.raises(ValueError, match="wheel"):
        frontend_dist.verify_wheel_frontend(tmp_path, wheel)
