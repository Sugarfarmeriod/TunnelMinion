"""电脑显示名的并发读写：同时保存不报错、内容正确、不留临时文件；Windows 上替换被占用时重试。"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tunnelminion.domain.invites import platform_display_name
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway import names
from tunnelminion.gateway.names import NODE_NAME_FILE, load_node_name, save_node_name


def _named(value: str) -> Callable[[Platform], str]:
    def system_name(_platform: Platform) -> str:
        return value

    return system_name


def _files(root: Path) -> list[str]:
    return sorted(item.name for item in root.iterdir())


def test_concurrent_loads_and_saves_do_not_fail_or_leave_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(names, "system_display_name", _named("studio"))
    start = threading.Barrier(16)

    def load() -> str:
        start.wait()
        return load_node_name(tmp_path, Platform.WINDOWS)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = [future.result() for future in [pool.submit(load) for _ in range(16)]]

    assert results == ["studio"] * 16
    assert _files(tmp_path) == [NODE_NAME_FILE]
    assert load_node_name(tmp_path, Platform.WINDOWS) == "studio"


def test_concurrent_saves_of_different_names_leave_one_valid_name(tmp_path: Path) -> None:
    wanted = [f"电脑{index}" for index in range(8)]
    start = threading.Barrier(len(wanted))

    def save(name: str) -> str:
        start.wait()
        return save_node_name(tmp_path, name)

    with ThreadPoolExecutor(max_workers=len(wanted)) as pool:
        assert sorted(pool.map(save, wanted)) == sorted(wanted)
    assert load_node_name(tmp_path, Platform.WINDOWS) in wanted
    assert _files(tmp_path) == [NODE_NAME_FILE]


def test_unchanged_name_is_not_rewritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_node_name(tmp_path, "studio")
    replaced: list[tuple[object, object]] = []

    def record(source: object, target: object) -> None:
        replaced.append((source, target))

    monkeypatch.setattr(names.os, "replace", record)
    assert save_node_name(tmp_path, "studio") == "studio"
    # 存的还是平台默认名、而系统名也取不到时，同样不会每次都重写。
    monkeypatch.undo()
    default = platform_display_name(Platform.WINDOWS)
    save_node_name(tmp_path, default)
    monkeypatch.setattr(names, "system_display_name", _named(default))
    monkeypatch.setattr(names.os, "replace", record)
    assert load_node_name(tmp_path, Platform.WINDOWS) == default
    assert replaced == []


def _flaky_replace(failures: int) -> tuple[Callable[[object, object], None], list[int]]:
    """模拟 Windows：目标文件正被占用时前几次替换报 PermissionError。"""
    calls = [0]
    real = os.replace

    def replace(source: object, target: object) -> None:
        calls[0] += 1
        if calls[0] <= failures:
            raise PermissionError("目标文件正被另一个进程使用")
        real(source, target)  # type: ignore[arg-type]

    return replace, calls


def test_busy_target_is_retried_until_the_replace_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_node_name(tmp_path, "old")
    replace, calls = _flaky_replace(2)
    monkeypatch.setattr(names.os, "replace", replace)
    monkeypatch.setattr(names, "_REPLACE_RETRY_SECONDS", 0)
    assert save_node_name(tmp_path, "new") == "new"
    assert calls[0] == 3
    assert load_node_name(tmp_path, Platform.WINDOWS) == "new"
    assert _files(tmp_path) == [NODE_NAME_FILE]


def test_busy_target_is_skipped_when_disk_already_has_the_same_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """一直替换不了，但另一个请求已经写好了同样的名字：算保存成功。"""
    save_node_name(tmp_path, "old")
    real_read = names._read_saved  # pyright: ignore[reportPrivateUsage]
    reads = [0]

    def read(path: Path) -> str | None:
        reads[0] += 1
        # 第一次读（决定要不要写）还是旧名字；之后另一个请求已经写成了新名字。
        return real_read(path) if reads[0] == 1 else "new"

    def busy(_source: object, _target: object) -> None:
        raise PermissionError("目标文件正被另一个进程使用")

    monkeypatch.setattr(names, "_read_saved", read)
    monkeypatch.setattr(names.os, "replace", busy)
    monkeypatch.setattr(names, "_REPLACE_RETRY_SECONDS", 0)
    assert save_node_name(tmp_path, "new") == "new"
    assert _files(tmp_path) == [NODE_NAME_FILE]


def test_busy_target_with_a_different_name_reports_the_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_node_name(tmp_path, "old")

    def busy(_source: object, _target: object) -> None:
        raise PermissionError("目标文件正被另一个进程使用")

    monkeypatch.setattr(names.os, "replace", busy)
    monkeypatch.setattr(names, "_REPLACE_RETRY_SECONDS", 0)
    with pytest.raises(PermissionError):
        save_node_name(tmp_path, "new")
    monkeypatch.undo()
    assert load_node_name(tmp_path, Platform.WINDOWS) == "old"
    assert _files(tmp_path) == [NODE_NAME_FILE]


def test_reading_while_the_file_is_being_replaced_is_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_node_name(tmp_path, "studio")
    real = Path.read_text
    calls = [0]

    def read_text(self: Path, *args: object, **kwargs: object) -> str:
        calls[0] += 1
        if calls[0] == 1:
            raise PermissionError("正在被替换")
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(names, "_REPLACE_RETRY_SECONDS", 0)
    assert load_node_name(tmp_path, Platform.WINDOWS) == "studio"

    def always_busy(self: Path, *args: object, **kwargs: object) -> str:
        raise PermissionError("一直被占用")

    monkeypatch.setattr(Path, "read_text", always_busy)
    with pytest.raises(PermissionError):
        load_node_name(tmp_path, Platform.WINDOWS)
