"""本地受管网络所有权账本与秘密边界测试。"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.network.factories import NETWORK_ID, NODE_A, observation, ownership

from tunnelminion.domain.identifiers import ResourceId
from tunnelminion.network.contracts import OwnershipState
from tunnelminion.network.ledger import (
    ManagedResourceLedgerEntry,
    SQLiteManagedResourceLedger,
)

NOW = datetime(2026, 7, 26, 11, 0, tzinfo=UTC)


def entry(**updates: object) -> ManagedResourceLedgerEntry:
    observed = observation(ownership_state=OwnershipState.MANAGED_OWNED)
    values: dict[str, object] = {
        "ownership": ownership(observed),
        "secret_reference": "keyring:wireguard/tmn-test-a",
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(updates)
    return ManagedResourceLedgerEntry.model_validate(values)


def test_ledger_persists_reopens_and_exports_without_secret_reference(tmp_path: Path) -> None:
    path = tmp_path / "managed-network.sqlite3"
    ledger = SQLiteManagedResourceLedger(path)
    first = entry()
    ledger.put(first)
    updated = first.model_copy(update={"updated_at": NOW + timedelta(seconds=1)})
    ledger.put(updated)

    reopened = SQLiteManagedResourceLedger(path)
    assert reopened.get(NETWORK_ID, NODE_A) == updated
    assert reopened.list_all() == (updated,)
    exported = reopened.export_public()
    assert exported[0].secret_reference_configured
    assert "secret_reference" not in exported[0].model_dump()
    assert "wireguard/tmn-test-a" not in exported[0].model_dump_json()
    reopened.assert_no_secret_material()


def test_ledger_rejects_secret_fields_timestamps_and_resource_replacement(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError):
        ManagedResourceLedgerEntry.model_validate(
            {
                **entry().model_dump(mode="python"),
                "private_key": "forbidden",
            }
        )
    with pytest.raises(ValidationError):
        entry(secret_reference="keyring:wireguard_private_key/material")
    with pytest.raises(ValidationError):
        entry(updated_at=NOW - timedelta(seconds=1))

    ledger = SQLiteManagedResourceLedger(tmp_path / "managed-network.sqlite3")
    first = entry()
    ledger.put(first)
    replacement = first.model_copy(
        update={"ownership": first.ownership.model_copy(update={"resource_id": ResourceId.new()})}
    )
    with pytest.raises(ValueError, match="另一受管资源"):
        ledger.put(replacement)


def test_ledger_delete_requires_matching_live_fingerprint_and_is_idempotent(
    tmp_path: Path,
) -> None:
    ledger = SQLiteManagedResourceLedger(tmp_path / "managed-network.sqlite3")
    saved = entry()
    ledger.put(saved)
    with pytest.raises(ValueError, match="系统指纹"):
        ledger.delete(
            NETWORK_ID,
            NODE_A,
            expected_system_fingerprint="sha256:" + "0" * 64,
        )
    assert ledger.delete(
        NETWORK_ID,
        NODE_A,
        expected_system_fingerprint=saved.ownership.system_fingerprint,
    )
    assert not ledger.delete(
        NETWORK_ID,
        NODE_A,
        expected_system_fingerprint=saved.ownership.system_fingerprint,
    )
    assert ledger.get(NETWORK_ID, NODE_A) is None


def test_ledger_integrity_check_detects_corrupted_secret_payload(tmp_path: Path) -> None:
    path = tmp_path / "managed-network.sqlite3"
    ledger = SQLiteManagedResourceLedger(path)
    saved = entry()
    ledger.put(saved)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """UPDATE managed_network_resources
            SET payload=? WHERE network_id=? AND node_id=?""",
            ('{"private_key":"forbidden"}', str(NETWORK_ID), str(NODE_A)),
        )
    with pytest.raises(ValueError, match="禁止的秘密字段"):
        ledger.assert_no_secret_material()

    with sqlite3.connect(path) as connection:
        connection.execute(
            """UPDATE managed_network_resources
            SET payload=? WHERE network_id=? AND node_id=?""",
            ('["not-a-ledger"]', str(NETWORK_ID), str(NODE_A)),
        )
    with pytest.raises(ValueError, match="结构无效"):
        ledger.assert_no_secret_material()
