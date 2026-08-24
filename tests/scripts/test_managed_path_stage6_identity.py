"""阶段 6 身份入口的固定范围测试。"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts.managed_path_stage6_identity import (
    _APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
    _CONFIGS,  # pyright: ignore[reportPrivateUsage]
    _NETWORK_ID,  # pyright: ignore[reportPrivateUsage]
    _assert_trusted_data_dir,  # pyright: ignore[reportPrivateUsage]
    _PlatformConfig,  # pyright: ignore[reportPrivateUsage]
    _publish_public_identity,  # pyright: ignore[reportPrivateUsage]
    _require_matching_platform,  # pyright: ignore[reportPrivateUsage]
    _require_unprivileged,  # pyright: ignore[reportPrivateUsage]
    main,
)

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.network.contracts import (
    LocalNetworkKeyMaterial,
    ProviderKind,
    canonical_sha256,
)
from tunnelminion.network.ledger import SQLiteManagedResourceLedger


def test_stage6_identity_resources_are_fixed() -> None:
    windows = _CONFIGS["windows"]
    macos = _CONFIGS["macos"]

    assert windows.data_dir == Path(r"F:\Project\codex\tunnelminion-stage6-data\windows")
    assert macos.data_dir == Path(
        "/Volumes/DarkAI/Codex-project/Side project/Tunnelminion-stage6-data/macos"
    )
    assert str(_NETWORK_ID) == "network_60000000000000000000000000000000"
    assert str(windows.node_id) == "node_6000000000000000000000000000000a"
    assert str(macos.node_id) == "node_6000000000000000000000000000000b"
    assert windows.provider.value == "windows"
    assert macos.provider.value == "macos"


def test_stage6_identity_rejects_wrong_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scripts.managed_path_stage6_identity.os.name", "posix")
    with pytest.raises(SystemExit, match="Windows identity"):
        _require_matching_platform("windows")

    monkeypatch.setattr("scripts.managed_path_stage6_identity.sys.platform", "win32")
    with pytest.raises(SystemExit, match="macOS identity"):
        _require_matching_platform("macos")


def test_stage6_identity_rejects_elevated_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shell32 = SimpleNamespace(IsUserAnAdmin=lambda: 1)
    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity.ctypes.windll",
        SimpleNamespace(shell32=shell32),
    )
    with pytest.raises(SystemExit, match="管理员令牌"):
        _require_unprivileged("windows")

    monkeypatch.setattr("scripts.managed_path_stage6_identity.os.geteuid", lambda: 0, raising=False)
    with pytest.raises(SystemExit, match="root"):
        _require_unprivileged("macos")


class _CreateOnlyProvider:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def create_local_identity(self, network_id: object, node_id: object) -> LocalNetworkKeyMaterial:
        self.calls += 1
        assert network_id == _NETWORK_ID
        assert node_id == NodeId("node_6000000000000000000000000000000a")
        if self.fail:
            raise RuntimeError("injected creation failure")
        public_key = "A" * 43 + "="
        return LocalNetworkKeyMaterial(
            secret_reference="keyring:must-not-be-exported",
            public_key=public_key,
            public_key_hash=canonical_sha256({"public_key": public_key}),
        )


def _configure_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    provider: _CreateOnlyProvider,
) -> None:
    config = _PlatformConfig(
        provider=ProviderKind.WINDOWS,
        node_id=NodeId("node_6000000000000000000000000000000a"),
        data_dir=tmp_path / "approved",
    )
    monkeypatch.setitem(_CONFIGS, "windows", config)
    monkeypatch.setitem(_APPROVED_DATA_DIRS, "windows", config.data_dir)

    def accept_platform(_platform: str) -> None:
        return None

    def build_platform(_data_dir: Path, _ledger: SQLiteManagedResourceLedger) -> SimpleNamespace:
        return SimpleNamespace(provider=provider)

    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity._require_matching_platform",
        accept_platform,
    )
    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity._require_unprivileged",
        accept_platform,
    )
    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity.build_windows_managed_path_platform",
        build_platform,
    )


def test_main_creates_once_without_exporting_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = _CreateOnlyProvider()
    _configure_main(monkeypatch, tmp_path, provider)

    assert main(["--platform", "windows"]) == 0

    output = tmp_path / "approved" / "public-identity.json"
    text = output.read_text(encoding="utf-8")
    stdout = capsys.readouterr().out
    assert provider.calls == 1
    assert json.loads(text)["public_key"] == "A" * 43 + "="
    assert "must-not-be-exported" not in text
    assert "must-not-be-exported" not in stdout
    assert "private" not in text.lower()
    assert not (tmp_path / "approved" / ".identity-creation-in-progress").exists()

    with pytest.raises(SystemExit, match="拒绝读取或覆盖"):
        main(["--platform", "windows"])
    assert provider.calls == 1


def test_main_leaves_fail_closed_marker_after_creation_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider = _CreateOnlyProvider(fail=True)
    _configure_main(monkeypatch, tmp_path, provider)

    with pytest.raises(RuntimeError, match="injected"):
        main(["--platform", "windows"])

    assert (tmp_path / "approved" / ".identity-creation-in-progress").is_file()
    with pytest.raises(SystemExit, match="拒绝读取或覆盖"):
        main(["--platform", "windows"])
    assert provider.calls == 1


def test_trusted_data_dir_rejects_reparse_component(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "approved"
    real_lstat = os.lstat

    def fake_lstat(path: os.PathLike[str] | str):
        if Path(path) == target:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            )
        return real_lstat(path)

    target.mkdir()
    monkeypatch.setattr("scripts.managed_path_stage6_identity.os.lstat", fake_lstat)
    with pytest.raises(SystemExit, match="链接或重解析点"):
        _assert_trusted_data_dir(target, target)


def test_trusted_data_dir_rejects_nonapproved_path(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="获准固定路径"):
        _assert_trusted_data_dir(tmp_path / "actual", tmp_path / "approved")


def test_elevated_identity_stops_before_any_write_or_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider = _CreateOnlyProvider()
    config = _PlatformConfig(
        provider=ProviderKind.WINDOWS,
        node_id=NodeId("node_6000000000000000000000000000000a"),
        data_dir=tmp_path / "must-not-exist",
    )
    monkeypatch.setitem(_CONFIGS, "windows", config)
    monkeypatch.setitem(_APPROVED_DATA_DIRS, "windows", config.data_dir)

    def accept_platform(_platform: str) -> None:
        return None

    def reject_elevated(_platform: str) -> None:
        raise SystemExit("禁止使用管理员令牌")

    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity._require_matching_platform",
        accept_platform,
    )
    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity._require_unprivileged",
        reject_elevated,
    )
    builder_calls = 0

    def forbidden_builder(_data_dir: Path, _ledger: SQLiteManagedResourceLedger) -> object:
        nonlocal builder_calls
        builder_calls += 1
        return SimpleNamespace(provider=provider)

    monkeypatch.setattr(
        "scripts.managed_path_stage6_identity.build_windows_managed_path_platform",
        forbidden_builder,
    )

    with pytest.raises(SystemExit, match="管理员令牌"):
        main(["--platform", "windows"])

    assert not config.data_dir.exists()
    assert builder_calls == 0
    assert provider.calls == 0


def test_public_identity_publish_refuses_precreated_temporary_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "public-identity.json"
    temporary = tmp_path / ".public-identity.json.fixed.tmp"
    temporary.write_text("sentinel", encoding="utf-8")

    def fixed_token(_size: int) -> str:
        return "fixed"

    monkeypatch.setattr("scripts.managed_path_stage6_identity.secrets.token_hex", fixed_token)

    with pytest.raises(FileExistsError):
        _publish_public_identity(output, {"public": True})

    assert temporary.read_text(encoding="utf-8") == "sentinel"
    assert not output.exists()
