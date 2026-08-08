"""runtime profile、平台路径和原子仓储测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from tunnelminion.runtime import profile as runtime_profile
from tunnelminion.runtime.profile import (
    FileRuntimeProfileRepository,
    RuntimeBudgets,
    RuntimeComponent,
    RuntimeProfile,
    default_runtime_data_dir,
    default_runtime_profile_path,
    ensure_program_data_separation,
    resolve_runtime_paths,
)


def profile(data_dir: Path) -> RuntimeProfile:
    """创建启用两个组件的标准测试 profile。"""
    return RuntimeProfile(
        data_dir=data_dir,
        enabled_components=frozenset({RuntimeComponent.LOCAL, RuntimeComponent.GATEWAY}),
        local_port=8910,
        budgets=RuntimeBudgets(
            startup_timeout_seconds=20,
            stable_window_seconds=1,
            shutdown_timeout_seconds=25,
            model_health_timeout_seconds=1,
        ),
    )


def test_profile_rejects_relative_traversal_secret_unknown_and_invalid_contract(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError, match="绝对路径"):
        RuntimeProfile(data_dir=Path("relative/data"))
    absolute_traversal = tmp_path / "child" / ".." / "data"
    with pytest.raises(ValidationError, match="父目录跳转"):
        RuntimeProfile(data_dir=absolute_traversal)
    with pytest.raises(ValidationError, match="至少启用一个"):
        RuntimeProfile(data_dir=tmp_path, enabled_components=frozenset())
    with pytest.raises(ValidationError, match="版本不受支持"):
        RuntimeProfile.model_validate(
            {"schema_version": "runtime-profile/v2", "data_dir": str(tmp_path)}
        )
    for secret_field in ("token", "refresh", "api_key", "private_key"):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            RuntimeProfile.model_validate({"data_dir": str(tmp_path), secret_field: "secret"})


def test_profile_schema_contains_only_non_secret_fields(tmp_path: Path) -> None:
    schema = json.loads(Path("schemas/runtime-profile-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    value = profile(tmp_path).model_dump(mode="json")
    Draft202012Validator(schema).validate(  # pyright: ignore[reportUnknownMemberType]
        value
    )
    serialized = json.dumps(schema).lower()
    assert "token" not in serialized
    assert "refresh" not in serialized
    assert "api_key" not in serialized
    assert "private_key" not in serialized


def test_program_data_boundaries_reject_both_overlap_directions(tmp_path: Path) -> None:
    program = tmp_path / "program"
    data = tmp_path / "data"
    ensure_program_data_separation(program, data)
    with pytest.raises(ValueError, match="不得重叠"):
        ensure_program_data_separation(program, program)
    with pytest.raises(ValueError, match="不得重叠"):
        ensure_program_data_separation(program, program / "data")
    with pytest.raises(ValueError, match="不得重叠"):
        ensure_program_data_separation(program / "nested", program)


def test_runtime_paths_preserve_default_and_explicit_data_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default_data = tmp_path / "default-data"
    default_profile = tmp_path / "config" / "runtime-profile.json"
    monkeypatch.setattr(runtime_profile, "default_runtime_data_dir", lambda: default_data)
    monkeypatch.setattr(runtime_profile, "default_runtime_profile_path", lambda: default_profile)
    defaults = resolve_runtime_paths()
    assert defaults.data_dir == default_data.resolve()
    assert defaults.profile_file == default_profile.resolve()
    assert defaults.log_dir == default_data.resolve() / "runtime" / "logs"
    assert defaults.state_dir == default_data.resolve() / "runtime" / "state"

    monkeypatch.chdir(tmp_path)
    explicit = resolve_runtime_paths(Path("custom"), Path("profile.json"))
    assert explicit.data_dir == (tmp_path / "custom").resolve()
    assert explicit.profile_file == (tmp_path / "profile.json").resolve()


def test_default_profile_path_is_absolute_and_versioned() -> None:
    data = default_runtime_data_dir()
    path = default_runtime_profile_path()
    assert data.is_absolute()
    assert path.is_absolute()
    assert path.name == "runtime-profile.json"


def test_profile_repository_round_trip_atomic_delete_and_private_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    program = tmp_path / "program"
    data = tmp_path / "data"
    path = tmp_path / "config" / "runtime-profile.json"
    repository = FileRuntimeProfileRepository(path, program)
    assert repository.load() is None
    expected = profile(data)
    repository.save(expected)
    assert repository.load() == expected
    assert not tuple(path.parent.glob("*.tmp"))

    chmod_calls: list[tuple[Path, int]] = []

    def record_chmod(target: str | Path, mode: int) -> None:
        chmod_calls.append((Path(target), mode))

    monkeypatch.setattr(runtime_profile, "_requires_explicit_permissions", lambda: True)
    monkeypatch.setattr(runtime_profile.os, "chmod", record_chmod)
    repository.save(expected)
    assert {mode for _target, mode in chmod_calls} == {0o600, 0o700}
    repository.delete()
    repository.delete()
    assert not path.exists()


def test_profile_repository_rejects_overlap_and_cleans_failed_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    program = tmp_path / "program"
    repository = FileRuntimeProfileRepository(tmp_path / "profile.json", program)
    with pytest.raises(ValueError, match="不得重叠"):
        repository.save(profile(program / "data"))

    target = tmp_path / "failed" / "runtime-profile.json"
    original_replace = Path.replace

    def fail_replace(self: Path, destination: Path) -> Path:
        del self, destination
        raise OSError("replace failed")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        runtime_profile._atomic_write_private(  # pyright: ignore[reportPrivateUsage]
            target, "{}"
        )
    assert not tuple(target.parent.glob("*.tmp"))
    monkeypatch.setattr(Path, "replace", original_replace)


def test_current_program_dir_handles_source_and_frozen_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = runtime_profile.current_program_dir()
    assert source.is_absolute()
    monkeypatch.setattr(runtime_profile.sys, "frozen", True, raising=False)
    monkeypatch.setattr(runtime_profile.sys, "executable", str(tmp_path / "program" / "app"))
    assert runtime_profile.current_program_dir() == (tmp_path / "program").resolve()


def test_restrict_permissions_is_noop_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Path, int]] = []

    def record_chmod(target: str | Path, mode: int) -> None:
        calls.append((Path(target), mode))

    monkeypatch.setattr(runtime_profile, "_requires_explicit_permissions", lambda: False)
    monkeypatch.setattr(runtime_profile.os, "chmod", record_chmod)
    runtime_profile._restrict_permissions(tmp_path, 0o700)  # pyright: ignore[reportPrivateUsage]
    assert calls == []
