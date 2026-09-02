"""版本化运行包安装、切换、回退和保留数据移除测试。"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from tunnelminion import cli
from tunnelminion.runtime import install as install_module
from tunnelminion.runtime.install import (
    INSTALL_STATE_FILE,
    InstalledPackage,
    RuntimeInstallState,
    RuntimePackageInstaller,
    SwitchOutcome,
    default_runtime_install_root,
)
from tunnelminion.runtime.preflight import canonical_runtime_architecture


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _package(tmp_path: Path, package_id: str, payload: bytes) -> tuple[Path, Path]:
    root = tmp_path / package_id
    root.mkdir(parents=True)
    executable = root / "app.bin"
    executable.write_bytes(payload)
    schemas = root / "schemas"
    schemas.mkdir()
    shutil.copy2(
        "schemas/runtime-package-manifest-v1.schema.json",
        schemas / "runtime-package-manifest-v1.schema.json",
    )
    files = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in sorted(item for item in root.rglob("*") if item.is_file())
    ]
    manifest = {
        "schema_version": "runtime-package-manifest/v1",
        "candidate": {
            "id": package_id,
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": platform.machine().lower(),
            "python_version": "3.11.15",
            "application_version": "0.1.0",
        },
        "build": {
            "source_revision": "a" * 40,
            "source_tree_sha256": hashlib.sha256(payload).hexdigest(),
            "lock_sha256": "b" * 64,
            "builder": "fixture",
        },
        "entrypoint": "app.bin",
        "entrypoint_args": [],
        "files": files,
        "licenses": [],
    }
    manifest_path = tmp_path / f"{package_id}.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return root, manifest_path


def _v2_package(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "package-v2"
    ui = root / "ui"
    schemas = root / "schemas"
    ui.mkdir(parents=True)
    schemas.mkdir()
    executable = root / "app.bin"
    executable.write_bytes(b"v2")
    (ui / "index.html").write_bytes(b"ui")
    shutil.copy2(
        "schemas/runtime-package-manifest-v2.schema.json",
        schemas / "runtime-package-manifest-v2.schema.json",
    )
    files: list[dict[str, object]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        file_type = (
            "entrypoint"
            if relative == "app.bin"
            else "frontend"
            if relative.startswith("ui/")
            else "schema"
        )
        files.append(
            {
                "path": relative,
                "sha256": _sha256(path),
                "size": path.stat().st_size,
                "type": file_type,
            }
        )
    frontend_digest = hashlib.sha256()
    frontend_digest.update(b"index.html\0")
    frontend_digest.update(bytes.fromhex(hashlib.sha256(b"ui").hexdigest()))
    manifest = {
        "schema_version": "runtime-package-manifest/v2",
        "candidate": {
            "id": "package-v2",
            "layout": "onedir-freeze",
            "platform": sys.platform,
            "architecture": canonical_runtime_architecture(),
            "python_version": "3.11.15",
            "application_version": "0.1.0",
        },
        "build": {
            "source_revision": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "python_lock_sha256": "c" * 64,
            "npm_lock_sha256": "d" * 64,
            "builder": "fixture",
        },
        "frontend": {
            "root": "ui",
            "sha256": frontend_digest.hexdigest(),
            "file_count": 1,
        },
        "entrypoint": "app.bin",
        "entrypoint_args": [],
        "files": files,
        "licenses": [
            {
                "ecosystem": ecosystem,
                "name": ecosystem,
                "version": "1",
                "license": "MIT",
                "source": "fixture",
            }
            for ecosystem in ("python", "npm")
        ],
    }
    manifest_path = tmp_path / "package-v2.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return root, manifest_path


def test_stage_activate_is_idempotent_and_state_contains_only_data_digest(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    installer = RuntimePackageInstaller(tmp_path / "program", data_dir)
    package, manifest = _package(tmp_path / "sources", "package-one", b"one")
    assert installer.load().packages == ()
    record = installer.stage(package, manifest)
    assert installer.stage(package, manifest) == record
    with pytest.raises(RuntimeError, match="手工停止"):
        installer.activate(record.package_id, lambda: False)
    state = installer.activate(record.package_id, lambda: True)
    assert state.current_package_id == "package-one"
    assert installer.current_program_dir() == tmp_path / "program" / record.program_directory
    serialized = (tmp_path / "program" / INSTALL_STATE_FILE).read_text(encoding="utf-8")
    assert str(data_dir) not in serialized
    assert "token" not in serialized


def test_stage_and_activate_v2_package_without_rewriting_manifest(tmp_path: Path) -> None:
    package, manifest = _v2_package(tmp_path / "sources")
    before = manifest.read_bytes()
    installer = RuntimePackageInstaller(tmp_path / "program", tmp_path / "data")
    record = installer.stage(package, manifest)
    installer.activate(record.package_id, lambda: True)
    installed = installer.current_program_dir()
    assert installed is not None
    assert (
        json.loads((installed / "runtime-package-manifest.json").read_text(encoding="utf-8"))[
            "schema_version"
        ]
        == "runtime-package-manifest/v2"
    )
    assert manifest.read_bytes() == before


def test_switch_health_failure_rolls_back_program_only_and_success_advances(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = data_dir / "runtime.sqlite3"
    secret = data_dir / "gateway-secrets" / "peer"
    database.write_bytes(b"database-v2")
    secret.parent.mkdir()
    secret.write_text("tmn_secret-value", encoding="utf-8")
    before = (_sha256(database), _sha256(secret))
    installer = RuntimePackageInstaller(tmp_path / "program", data_dir)
    one = installer.stage(*_package(tmp_path / "sources", "package-one", b"one"))
    two = installer.stage(*_package(tmp_path / "sources", "package-two", b"two"))
    installer.activate(one.package_id, lambda: True)

    seen: list[Path] = []

    def unhealthy(program_dir: Path) -> bool:
        seen.append(program_dir)
        return False

    rolled_back = installer.switch_with_health(two.package_id, lambda: True, unhealthy)
    assert rolled_back.outcome is SwitchOutcome.ROLLED_BACK
    assert rolled_back.current_package_id == one.package_id
    assert seen == [tmp_path / "program" / two.program_directory]
    assert (_sha256(database), _sha256(secret)) == before

    def healthy(program_dir: Path) -> bool:
        del program_dir
        return True

    activated = installer.switch_with_health(two.package_id, lambda: True, healthy)
    assert activated.outcome is SwitchOutcome.ACTIVATED
    assert installer.load().current_package_id == two.package_id
    assert (_sha256(database), _sha256(secret)) == before


def test_unhealthy_first_package_has_no_unsafe_rollback_target(tmp_path: Path) -> None:
    installer = RuntimePackageInstaller(tmp_path / "program", tmp_path / "data")
    package = installer.stage(*_package(tmp_path / "sources", "package-one", b"one"))

    def unhealthy(program_dir: Path) -> bool:
        del program_dir
        return False

    with pytest.raises(RuntimeError, match="没有可切回"):
        installer.switch_with_health(package.package_id, lambda: True, unhealthy)


def test_remove_program_requires_stop_preserves_data_and_unknown_install_entries(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = data_dir / "runtime.sqlite3"
    secret = data_dir / "gateway-secrets" / "peer"
    database.write_bytes(b"database")
    secret.parent.mkdir()
    secret.write_text("secret", encoding="utf-8")
    installer = RuntimePackageInstaller(tmp_path / "program", data_dir)
    package = installer.stage(*_package(tmp_path / "sources", "package-one", b"one"))
    installer.activate(package.package_id, lambda: True)
    unknown = tmp_path / "program" / "user-note.txt"
    unknown.write_text("keep", encoding="utf-8")
    with pytest.raises(RuntimeError, match="手工停止"):
        installer.remove_program(lambda: False)
    assert installer.remove_program(lambda: True) == ("package-one",)
    assert database.read_bytes() == b"database"
    assert secret.read_text(encoding="utf-8") == "secret"
    assert unknown.read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "program" / INSTALL_STATE_FILE).exists()


def test_stage_rejects_corruption_conflicting_id_and_cleans_failed_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = RuntimePackageInstaller(tmp_path / "program", tmp_path / "data")
    package, manifest = _package(tmp_path / "sources", "package-one", b"one")
    (package / "app.bin").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="校验失败"):
        installer.stage(package, manifest)

    package, manifest = _package(tmp_path / "valid", "package-one", b"one")
    installer.stage(package, manifest)
    conflicting, conflicting_manifest = _package(
        tmp_path / "conflicting", "package-one", b"different"
    )
    with pytest.raises(ValueError, match="同名运行包"):
        installer.stage(conflicting, conflicting_manifest)

    second, second_manifest = _package(tmp_path / "second", "package-two", b"two")
    original_copytree = shutil.copytree

    def fail_copytree(source: Path, target: Path, **kwargs: object) -> Path:
        target.mkdir(parents=True)
        raise OSError("copy failed")

    monkeypatch.setattr(shutil, "copytree", fail_copytree)
    with pytest.raises(OSError, match="copy failed"):
        installer.stage(second, second_manifest)
    assert not tuple((tmp_path / "program" / "versions").glob("*.staging"))
    monkeypatch.setattr(shutil, "copytree", original_copytree)

    third, third_manifest = _package(tmp_path / "third", "package-three", b"three")

    def fail_save(state: RuntimeInstallState) -> None:
        del state
        raise OSError("state write failed")

    monkeypatch.setattr(installer, "_save", fail_save)
    with pytest.raises(OSError, match="state write failed"):
        installer.stage(third, third_manifest)
    assert [item.package_id for item in installer.load().packages] == ["package-one"]
    assert len(tuple((tmp_path / "program" / "versions").iterdir())) == 1


def test_install_state_and_path_boundaries_fail_closed(tmp_path: Path) -> None:
    package = InstalledPackage(
        package_id="package-one",
        application_version="0.1.0",
        source_revision="a" * 40,
        source_tree_sha256="b" * 64,
        manifest_sha256="c" * 64,
        program_directory="versions/package-one",
    )
    with pytest.raises(ValidationError, match="版本不受支持"):
        RuntimeInstallState(
            schema_version="runtime-install/v2",
            data_dir_sha256="d" * 64,
        )
    with pytest.raises(ValidationError, match="重复"):
        RuntimeInstallState(data_dir_sha256="d" * 64, packages=(package, package))
    with pytest.raises(ValidationError, match="当前程序版本不存在"):
        RuntimeInstallState(data_dir_sha256="d" * 64, current_package_id="missing")
    with pytest.raises(ValidationError, match="上一程序版本不存在"):
        RuntimeInstallState(data_dir_sha256="d" * 64, previous_package_id="missing")
    with pytest.raises(ValueError, match="不得重叠"):
        RuntimePackageInstaller(tmp_path / "program", tmp_path / "program" / "data")

    root = tmp_path / "state-root"
    first = RuntimePackageInstaller(root, tmp_path / "data-one")
    first._save(first.load())  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="另一个数据目录"):
        RuntimePackageInstaller(root, tmp_path / "data-two").load()

    escaped = package.model_copy(update={"program_directory": "../foreign"})
    malicious = RuntimeInstallState(data_dir_sha256="e" * 64, packages=(escaped,))
    installer = RuntimePackageInstaller(tmp_path / "malicious", tmp_path / "data")
    installer._save(  # pyright: ignore[reportPrivateUsage]
        malicious.model_copy(update={"data_dir_sha256": installer._data_dir_sha256()})  # pyright: ignore[reportPrivateUsage]
    )
    with pytest.raises(ValueError, match="越界"):
        installer.remove_program(lambda: True)


def test_default_install_root_is_absolute_and_separate_name() -> None:
    root = default_runtime_install_root()
    assert root.is_absolute()
    assert "TunnelMinionRuntime" in str(root)


def test_empty_missing_and_malformed_install_state_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installer = RuntimePackageInstaller(tmp_path / "program", tmp_path / "data")
    assert installer.current_program_dir() is None
    assert installer.remove_program(lambda: True) == ()
    with pytest.raises(KeyError, match="runtime_package_not_installed"):
        installer.activate("missing", lambda: True)

    invalid_root, invalid_manifest = _package(tmp_path / "invalid", "invalid-id", b"invalid")
    body = json.loads(invalid_manifest.read_text(encoding="utf-8"))
    body["candidate"]["id"] = "INVALID ID"
    invalid_manifest.write_text(json.dumps(body), encoding="utf-8")

    def accept_manifest(*args: object) -> None:
        del args

    monkeypatch.setattr(install_module, "verify_runtime_package", accept_manifest)
    with pytest.raises(ValueError, match="ID 无效"):
        RuntimePackageInstaller(tmp_path / "other-program", tmp_path / "other-data").stage(
            invalid_root, invalid_manifest
        )


def test_missing_installed_directory_and_program_path_escape_fail_closed(
    tmp_path: Path,
) -> None:
    installer = RuntimePackageInstaller(tmp_path / "program", tmp_path / "data")
    package = installer.stage(*_package(tmp_path / "sources", "package-one", b"one"))
    installer.activate(package.package_id, lambda: True)
    shutil.rmtree(tmp_path / "program" / package.program_directory)
    assert installer.remove_program(lambda: True) == ()

    escaped = package.model_copy(update={"program_directory": "../foreign"})
    state = RuntimeInstallState(
        data_dir_sha256="e" * 64,
        current_package_id=package.package_id,
        packages=(escaped,),
    )
    malicious = RuntimePackageInstaller(tmp_path / "malicious", tmp_path / "safe-data")
    malicious._save(  # pyright: ignore[reportPrivateUsage]
        state.model_copy(update={"data_dir_sha256": malicious._data_dir_sha256()})  # pyright: ignore[reportPrivateUsage]
    )
    with pytest.raises(ValueError, match="程序目录越界"):
        malicious.current_program_dir()


def test_runtime_package_cli_stages_activates_reports_and_preserves_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile = tmp_path / "config" / "runtime-profile.json"
    data_dir = tmp_path / "data"
    install_root = tmp_path / "installed-program"
    package_root, manifest = _package(tmp_path / "sources", "package-one", b"one")
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile),
                "--data-dir",
                str(data_dir),
            ]
        )
        == 0
    )
    _ = capsys.readouterr()
    common = ["--profile", str(profile), "--install-root", str(install_root)]
    assert (
        cli.main(
            [
                "runtime-package",
                "stage",
                *common,
                "--package-root",
                str(package_root),
                "--manifest",
                str(manifest),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "staged"
    assert (
        cli.main(
            [
                "runtime-package",
                "activate",
                *common,
                "--package-id",
                "package-one",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["current_package_id"] == "package-one"
    assert cli.main(["runtime-package", "status", *common]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["installed_package_ids"] == ["package-one"]
    assert "versions" in status["current_program_directory"]
    assert "pkg-" in status["current_program_directory"]

    data_dir.mkdir(exist_ok=True)
    database = data_dir / "runtime.sqlite3"
    database.write_bytes(b"keep")
    assert cli.main(["runtime-package", "remove", *common]) == 0
    removed = json.loads(capsys.readouterr().out)
    assert removed["data_preserved"] is True
    assert removed["secret_store_preserved"] is True
    assert database.read_bytes() == b"keep"


def test_runtime_package_cli_fails_closed_for_missing_profile(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        cli.main(
            [
                "runtime-package",
                "status",
                "--profile",
                str(tmp_path / "missing.json"),
                "--install-root",
                str(tmp_path / "program"),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error_code"] == "runtime_profile_invalid"


def test_runtime_package_cli_reports_invalid_package_and_uncertain_process_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = tmp_path / "config" / "runtime-profile.json"
    data_dir = tmp_path / "data"
    install_root = tmp_path / "program"
    assert (
        cli.main(
            [
                "runtime",
                "configure",
                "--profile",
                str(profile),
                "--data-dir",
                str(data_dir),
            ]
        )
        == 0
    )
    _ = capsys.readouterr()
    common = ["--profile", str(profile), "--install-root", str(install_root)]
    assert cli.main(["runtime-package", "activate", *common, "--package-id", "missing"]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "runtime_package_invalid"

    package_root, manifest = _package(tmp_path / "sources", "package-one", b"one")
    assert (
        cli.main(
            [
                "runtime-package",
                "stage",
                *common,
                "--package-root",
                str(package_root),
                "--manifest",
                str(manifest),
            ]
        )
        == 0
    )
    _ = capsys.readouterr()

    def unreadable_record(repository: object, component: object) -> object:
        del repository, component
        raise OSError("state unreadable")

    monkeypatch.setattr(
        "tunnelminion.runtime.process.ProcessRecordRepository.load", unreadable_record
    )
    assert cli.main(["runtime-package", "activate", *common, "--package-id", "package-one"]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "runtime_components_running"
