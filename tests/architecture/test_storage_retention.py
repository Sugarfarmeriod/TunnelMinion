"""每张 SQLite 表都要登记清理规则，拦住“表只增不减、数据库越来越大”。

只扫描源码里的建表语句，不打开任何真实数据库，结果与运行环境无关。
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

from tunnelminion.domain.storage_retention import SQLITE_TABLE_RETENTION, TableGrowth

SOURCE = Path(__file__).resolve().parents[2] / "src" / "tunnelminion"
_CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:\{self\.(?P<attribute>\w+)\}|(?P<name>\w+))",
    re.IGNORECASE,
)


def _created_tables() -> dict[str, set[str]]:
    tables: dict[str, set[str]] = {}
    for path in sorted(SOURCE.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in _CREATE_TABLE.finditer(text):
            name = match.group("name")
            if name is None:
                # 表名写在类属性里，例如 `_TABLE = "..."`。
                attribute = re.search(rf'\b{match.group("attribute")}\s*=\s*"(\w+)"', text)
                assert attribute is not None, f"{path.name} 的表名属性找不到"
                name = attribute.group(1)
            tables.setdefault(name, set()).add(path.relative_to(SOURCE).as_posix())
    return tables


def test_scanner_reads_literal_and_attribute_table_names() -> None:
    tables = _created_tables()
    assert tables["incident_snapshots"] == {"incident/storage.py"}
    assert tables["network_authorization_grants"] == {"network/governance.py"}


def test_every_sqlite_table_has_a_registered_retention_rule() -> None:
    created = set(_created_tables())
    registered = set(SQLITE_TABLE_RETENTION)
    assert sorted(created - registered) == [], "新建的表要在 storage_retention 里登记清理规则"
    assert sorted(registered - created) == [], "登记了源码里已经没有的表"


def test_pruned_tables_name_a_real_cleanup_and_others_name_none() -> None:
    for table, retention in SQLITE_TABLE_RETENTION.items():
        assert retention.rule.strip(), table
        if retention.growth is not TableGrowth.PRUNED:
            assert retention.cleanup is None, table
            continue
        assert retention.cleanup is not None, table
        module_name, _, qualified = retention.cleanup.partition(":")
        target: object = importlib.import_module(module_name)
        for part in qualified.split("."):
            target = getattr(target, part)
        assert callable(target), table


def test_background_written_stores_are_never_left_growing() -> None:
    # 事件观察和巡检每轮都写库，它们的表必须有自动清理或按对象有界。
    background = {
        name
        for name, paths in _created_tables().items()
        if paths & {"incident/storage.py", "patrol/storage.py"}
    }
    assert background
    assert {
        name for name in background if SQLITE_TABLE_RETENTION[name].growth is TableGrowth.GROWING
    } == set()
