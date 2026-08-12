"""正式运行包 Playwright 启动器的夹具与环境契约。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import run_runtime_package_browser_server as server
from scripts.run_runtime_package_clean_acceptance import file_sha256


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "data"
    data.mkdir()
    (data / "node-id").write_text("node_" + "1" * 32, encoding="utf-8")
    (data / "runtime.sqlite3").write_bytes(b"SQLite format 3\0acceptance")
    receipt = tmp_path / "fixture.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": server.FIXTURE_SCHEMA,
                "platform": server.resolve_platform_name(),
                "contains_secrets": False,
                "files": [
                    {
                        "path": path.name,
                        "sha256": file_sha256(path),
                        "size": path.stat().st_size,
                    }
                    for path in sorted(data.iterdir())
                ],
            }
        ),
        encoding="utf-8",
    )
    return data, receipt


def test_fixture_receipt_is_verified_as_closed_set(tmp_path: Path) -> None:
    data, receipt = _fixture(tmp_path)

    report = server.load_and_verify_fixture(data, receipt)

    assert report["contains_secrets"] is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "unknown", "schema"),
        ("platform", "unknown", "平台"),
        ("contains_secrets", True, "无秘密"),
        ("files", None, "文件清单"),
        ("files", ["bad"], "文件项"),
        ("files", [{"path": "node-id"}], "文件字段"),
        ("files", [], "closed set"),
    ],
)
def test_invalid_fixture_receipt_fails_closed(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    data, receipt = _fixture(tmp_path)
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload[field] = value
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        server.load_and_verify_fixture(data, receipt)


def test_fixture_rejects_extra_non_file_and_digest_tampering(tmp_path: Path) -> None:
    data, receipt = _fixture(tmp_path)
    (data / "extra").write_text("unexpected", encoding="utf-8")
    with pytest.raises(ValueError, match="目录与回执"):
        server.load_and_verify_fixture(data, receipt)

    (data / "extra").unlink()
    (data / "nested").mkdir()
    with pytest.raises(ValueError, match="普通文件"):
        server.load_and_verify_fixture(data, receipt)

    (data / "nested").rmdir()
    (data / "node-id").write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="摘要"):
        server.load_and_verify_fixture(data, receipt)


def test_package_environment_hides_build_and_network_inputs(tmp_path: Path) -> None:
    environment = server.package_process_environment(
        tmp_path,
        {
            "PATH": "node-is-visible-here",
            "PYTHONPATH": "source-checkout",
            "UV_CACHE_DIR": "developer-cache",
            "KEEP": "yes",
        },
    )

    assert environment["PATH"] == str((tmp_path / "empty-path").resolve())
    assert "PYTHONPATH" not in environment
    assert "UV_CACHE_DIR" not in environment
    assert environment["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert environment["KEEP"] == "yes"
