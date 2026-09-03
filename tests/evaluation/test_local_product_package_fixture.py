"""正式运行包 A/B 数据夹具的无秘密与作用域契约。"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue
from scripts import prepare_local_product_package_fixture as fixture

from tunnelminion.incident.storage import SQLiteIncidentStore
from tunnelminion.memory.sqlite import SQLiteStores


def _native_platform() -> str:
    return "windows" if sys.platform == "win32" else "macos"


def test_real_factory_prepares_scoped_secret_free_fixture(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    report = fixture.prepare_fixture(data_dir, tmp_path, _native_platform())

    assert report["schema_version"] == fixture.FIXTURE_SCHEMA
    assert report["platform"] == _native_platform()
    assert report["operation_id"] == str(fixture.FIXTURE_OPERATION_ID)
    assert report["contains_secrets"] is False
    incident_summary = cast(dict[str, JsonValue], report["incident"])
    assert incident_summary["scenario_id"] == "loopback-listener"
    assert incident_summary["provider_name"] == "offline-script"
    assert incident_summary["status"] == "confirmed"
    assert incident_summary["real_model_calls"] == 0
    normal = cast(dict[str, JsonValue], incident_summary["normal_refresh"])
    assert normal["incident_count"] == 0
    assert normal["model_calls"] == 0
    files = cast(list[dict[str, JsonValue]], report["files"])
    assert {cast(str, item["path"]) for item in files} == fixture.ALLOWED_DATA_FILES
    scopes = cast(list[dict[str, JsonValue]], report["memory_scopes"])
    assert [scope["network"] for scope in scopes] == ["home", "lab"]
    assert len({cast(str, scope["node_id"]) for scope in scopes}) == 1

    stores = SQLiteStores.open(data_dir / "runtime.sqlite3")
    assert stores.operations.get(fixture.FIXTURE_OPERATION_ID) is not None
    memories = stores.memories.list_all()
    assert len(memories) == 2
    assert {memory.namespace.network for memory in memories} == {"home", "lab"}
    incidents = SQLiteIncidentStore(data_dir / "incidents.sqlite3").list_recent()
    assert len(incidents) == 1
    assert str(incidents[0].incident_id) == incident_summary["incident_id"]
    assert incidents[0].report is not None
    assert incidents[0].report.conclusion == "服务只监听环回地址，远端探测因此失败"


def test_cli_writes_receipt_outside_product_data(tmp_path: Path) -> None:
    output = tmp_path / "evidence" / "fixture.json"

    assert (
        fixture.main(
            (
                "--data-dir",
                str(tmp_path / "data"),
                "--allowed-root",
                str(tmp_path),
                "--platform",
                _native_platform(),
                "--output",
                str(output),
            )
        )
        == 0
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["contains_secrets"] is False
    assert not (tmp_path / "data" / "fixture.json").exists()


def test_rejecting_store_fails_every_secret_operation() -> None:
    store = fixture.RejectingSecretStore()

    with pytest.raises(RuntimeError, match="禁止读取秘密"):
        store.get("model-key")
    with pytest.raises(RuntimeError, match="禁止写入秘密"):
        store.set("model-key", "must-not-be-reported")
    with pytest.raises(RuntimeError, match="禁止删除秘密"):
        store.delete("model-key")


def test_keyring_patch_is_always_restored() -> None:
    original_windows = fixture.windows_app.KeyringSecretStore
    original_macos = fixture.macos_app.KeyringSecretStore

    with pytest.raises(RuntimeError, match="stop"), fixture.rejecting_product_keyrings():
        assert fixture.windows_app.KeyringSecretStore is fixture.RejectingSecretStore
        assert fixture.macos_app.KeyringSecretStore is fixture.RejectingSecretStore
        raise RuntimeError("stop")

    assert fixture.windows_app.KeyringSecretStore is original_windows
    assert fixture.macos_app.KeyringSecretStore is original_macos


def test_data_directory_must_be_empty_and_inside_allowed_root(tmp_path: Path) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "existing").write_text("keep", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"

    with pytest.raises(ValueError, match="必须不存在或为空"):
        fixture.prepare_fixture(occupied, tmp_path, _native_platform())
    with pytest.raises(ValueError, match="逃出"):
        fixture.prepare_fixture(outside, tmp_path, _native_platform())
    with pytest.raises(ValueError, match="未知验收平台"):
        fixture.prepare_fixture(tmp_path / "unknown", tmp_path, "linux")


def test_missing_allowed_root_is_created_before_fixture_data(tmp_path: Path) -> None:
    allowed_root = tmp_path / "new-sandbox"
    data_dir = allowed_root / "data"

    report = fixture.prepare_fixture(data_dir, allowed_root, _native_platform())

    assert allowed_root.is_dir()
    assert data_dir.is_dir()
    assert report["contains_secrets"] is False


def test_cli_rejects_receipt_inside_data_dir_before_writing(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    with pytest.raises(SystemExit):
        fixture.main(
            (
                "--data-dir",
                str(data_dir),
                "--allowed-root",
                str(tmp_path),
                "--output",
                str(data_dir / "receipt.json"),
            )
        )

    assert not data_dir.exists()


@pytest.mark.skipif(sys.platform not in {"win32", "darwin"}, reason="只支持正式目标平台")
def test_platform_defaults_to_native_target() -> None:
    assert fixture.resolve_platform_name() == _native_platform()
