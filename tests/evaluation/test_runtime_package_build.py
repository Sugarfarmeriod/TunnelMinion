"""正式运行包构建器的确定性清单与路径边界测试。"""

from __future__ import annotations

import json
import shutil
import tomllib
import zipfile
from collections.abc import Sequence
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import JsonValue
from scripts import build_runtime_package as builder


def _fake_builder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    epochs: list[str] = []
    frontend = tmp_path / "frontend-dist"
    (frontend / "assets").mkdir(parents=True)
    (frontend / "index.html").write_text("<main></main>", encoding="utf-8")
    (frontend / "assets/app.js").write_text("export {};", encoding="utf-8")
    (frontend / "assets/app.css").write_text("main{}", encoding="utf-8")
    monkeypatch.setattr(builder, "FRONTEND_DIST", frontend)

    def receipt(root: Path) -> dict[str, JsonValue]:
        del root
        return {
            "dist_sha256": builder._frontend_digest(  # pyright: ignore[reportPrivateUsage]
                frontend
            ),
            "file_count": 3,
        }

    monkeypatch.setattr(
        builder,
        "verify_frontend_dist",
        receipt,
    )

    def run(command: Sequence[str], *, environment: dict[str, str]) -> None:
        epochs.append(environment["SOURCE_DATE_EPOCH"])
        dist = Path(command[command.index("--distpath") + 1]) / "tunnelminion"
        dist.mkdir(parents=True)
        executable = dist / (
            "tunnelminion.exe" if builder.sys.platform == "win32" else "tunnelminion"
        )
        executable.write_bytes(b"deterministic-runtime")
        internal = dist / "_internal"
        internal.mkdir()
        add_data = command[command.index("--add-data") + 1]
        assert add_data == f"{frontend.resolve()}:tunnelminion/web/ui"
        shutil.copytree(
            frontend,
            internal / "tunnelminion/web/ui",
        )
        order = ("b.pyc", "a.pyc") if len(epochs) == 1 else ("a.pyc", "b.pyc")
        with zipfile.ZipFile(internal / "base_library.zip", "w") as archive:
            for name in order:
                archive.writestr(name, name.encode())

    def revision(explicit: str | None = None) -> str:
        del explicit
        return "a" * 40

    def epoch(source_revision: str) -> str:
        del source_revision
        return "1700000000"

    def licenses(work: Path) -> list[dict[str, JsonValue]]:
        del work
        return [
            {"name": "known", "version": "1", "license": "Apache-2.0"},
            {"name": "unknown", "version": "2", "license": "UNKNOWN"},
        ]

    monkeypatch.setattr(builder, "_run", run)
    monkeypatch.setattr(builder, "git_revision", revision)
    monkeypatch.setattr(builder, "_source_date_epoch", epoch)
    monkeypatch.setattr(builder, "license_inventory", licenses)
    return epochs


def test_formal_build_is_deterministic_and_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    epochs = _fake_builder(monkeypatch, tmp_path)
    first_manifest = tmp_path / "first.manifest.json"
    first_summary = tmp_path / "first.summary.json"
    first = builder.build_runtime_package(tmp_path / "first-output", first_manifest, first_summary)
    second_manifest = tmp_path / "second.manifest.json"
    second_summary = tmp_path / "second.summary.json"
    second = builder.build_runtime_package(
        tmp_path / "second-output", second_manifest, second_summary
    )
    assert first == second
    assert first_manifest.read_bytes() == second_manifest.read_bytes()
    assert first_summary.read_bytes() == second_summary.read_bytes()
    assert epochs == ["1700000000", "1700000000"]
    assert first["unknown_license_count"] == 1
    manifest = json.loads(first_manifest.read_text(encoding="utf-8"))
    schema = json.loads(
        Path("schemas/runtime-package-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(manifest)  # pyright: ignore[reportUnknownMemberType]
    package_root = next((tmp_path / "first-output").iterdir())
    assert (package_root / "THIRD_PARTY_LICENSES.json").exists()
    assert (package_root / "schemas" / "runtime-profile-v1.schema.json").exists()
    assert (package_root / "_internal/tunnelminion/web/ui/index.html").is_file()
    assert first["frontend_file_count"] == 3
    assert len(str(first["frontend_dist_sha256"])) == 64


def test_wheel_force_includes_the_unique_frontend_dist() -> None:
    configuration = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    wheel = configuration["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["force-include"] == {"build/frontend-dist": "tunnelminion/web/ui"}


def test_formal_build_rejects_missing_or_linked_frontend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(builder, "FRONTEND_DIST", tmp_path / "missing")
    with pytest.raises(ValueError, match=r"frontend-dist/index\.html"):
        builder.build_runtime_package(
            tmp_path / "output",
            tmp_path / "manifest.json",
            tmp_path / "summary.json",
        )


def test_formal_build_main_rejects_repository_targets_and_prints_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        builder.main(
            [
                "--output-root",
                "build/inside",
                "--manifest",
                str(tmp_path / "manifest.json"),
                "--summary",
                str(tmp_path / "summary.json"),
            ]
        )

    _fake_builder(monkeypatch, tmp_path)
    assert (
        builder.main(
            [
                "--output-root",
                str(tmp_path / "output"),
                "--manifest",
                str(tmp_path / "manifest.json"),
                "--summary",
                str(tmp_path / "summary.json"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["schema_version"] == "runtime-package-build/v1"
