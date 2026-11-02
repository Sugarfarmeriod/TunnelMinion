"""安装器为一键更新新增的查找、入口、指定上一版和清理旧版本的测试。"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from tests.update.conftest import build_package

from tunnelminion.runtime import install as install_module
from tunnelminion.runtime.install import (
    INSTALL_STATE_FILE,
    RuntimePackageInstaller,
    node_install_root,
)


def _stage(installer: RuntimePackageInstaller, tmp_path: Path, package_id: str) -> str:
    package = build_package(tmp_path / package_id, package_id, package_id.encode())
    return installer.stage(package, package / "runtime-package-manifest.json").package_id


def _rewrite_state(root: Path, edit: dict[str, object]) -> None:
    path = root / INSTALL_STATE_FILE
    raw = json.loads(path.read_text(encoding="utf-8"))
    for item in raw["packages"]:
        item.update(edit)
    path.write_text(json.dumps(raw), encoding="utf-8")


def test_node_install_root_is_per_data_dir(tmp_path: Path) -> None:
    one = node_install_root(tmp_path / "a", tmp_path / "base")
    two = node_install_root(tmp_path / "b", tmp_path / "base")
    assert one.parent == two.parent == tmp_path / "base"
    assert one != two and one.name.startswith("node-")
    assert node_install_root(tmp_path / "a").parent == install_module.default_runtime_install_root()


def test_lookup_and_entrypoint(tmp_path: Path) -> None:
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    package_id = _stage(installer, tmp_path, "pkg-a")
    assert installer.executable(package_id).read_bytes() == b"pkg-a"
    for method in (installer.program_dir, installer.executable):
        with pytest.raises(KeyError):
            method("missing")

    _rewrite_state(tmp_path / "install", {"entrypoint": None})
    assert installer.executable(package_id).name == "app.bin"
    _rewrite_state(tmp_path / "install", {"entrypoint": "../../escape"})
    with pytest.raises(ValueError, match="越界"):
        installer.executable(package_id)


def test_activate_with_explicit_previous(tmp_path: Path) -> None:
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    one = _stage(installer, tmp_path, "pkg-one")
    two = _stage(installer, tmp_path, "pkg-two")
    state = installer.activate(two, lambda: True, previous_package_id=one)
    assert (state.current_package_id, state.previous_package_id) == (two, one)
    with pytest.raises(ValueError, match="上一版本"):
        installer.activate(two, lambda: True, previous_package_id=two)


def test_prune_keeps_current_and_previous(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    ids = [_stage(installer, tmp_path, f"pkg-{name}") for name in ("a", "b", "c", "d")]
    installer.activate(ids[3], lambda: True, previous_package_id=ids[2])

    shutil.rmtree(installer.program_dir(ids[1]))
    real_rmtree = shutil.rmtree

    def locked(path: Path, *args: object, **kwargs: object) -> None:
        if Path(path) == installer.program_dir(ids[0]):
            raise PermissionError("in use")
        real_rmtree(path)

    monkeypatch.setattr(install_module.shutil, "rmtree", locked)
    # a 被占用留到下次；b 的目录已经不在，直接移除记录
    assert installer.prune() == (ids[1],)
    assert {item.package_id for item in installer.load().packages} == {ids[0], ids[2], ids[3]}
    monkeypatch.undo()
    assert installer.prune() == (ids[0],)
    assert {item.package_id for item in installer.load().packages} == {ids[2], ids[3]}
    # 没有可删的版本时不改写安装状态
    assert installer.prune() == ()


def test_prune_refuses_out_of_bounds_directory(tmp_path: Path) -> None:
    installer = RuntimePackageInstaller(tmp_path / "install", tmp_path / "data")
    _stage(installer, tmp_path, "pkg-a")
    _rewrite_state(tmp_path / "install", {"program_directory": "../outside"})
    with pytest.raises(ValueError, match="越界"):
        installer.prune()
