"""阶段 6.2 固定预览入口测试。"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import managed_path_stage6_preview as subject
from tunnelminion.network.contracts import (
    NetworkObservation,
    OwnershipState,
    ProviderKind,
    ProviderMode,
    canonical_sha256,
)
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.network.ledger import SQLiteManagedResourceLedger

NOW = datetime(2026, 8, 24, 5, 0, tzinfo=UTC)


def test_platform_route_overlaps_are_independently_bound() -> None:
    windows = subject._CONFIGS["windows"]  # pyright: ignore[reportPrivateUsage]
    macos = subject._CONFIGS["macos"]  # pyright: ignore[reportPrivateUsage]

    assert windows.allowed_route_overlaps[0].route == "192.0.0.0/9"
    assert windows.allowed_route_overlaps[0].observation_fingerprint == (
        "sha256:43938c1ef2e9e749462dc899a7e408f759f575dc472bfe412763f7c9244814bf"
    )
    assert macos.allowed_route_overlaps[0].route == "192.0.0.0/9"
    assert macos.allowed_route_overlaps[0].observation_fingerprint == (
        "sha256:1721e91dee1ef4cc0dfa0212feb6e94938c6296d6e73c1f38018c1a6ed1e9bae"
    )
    assert windows.allowed_route_overlaps != macos.allowed_route_overlaps


def _public_identity(*, node_id: str, provider: str) -> dict[str, object]:
    public_key = "A" * 43 + "="
    return {
        "schema_version": "managed-path-stage6-public-identity/v1",
        "network_id": "network_60000000000000000000000000000000",
        "node_id": node_id,
        "provider": provider,
        "public_key": public_key,
        "public_key_hash": canonical_sha256({"public_key": public_key}),
        "secret_reference_configured": True,
    }


def _configure_windows_preview(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, InMemoryNetworkProvider]:
    data_dir = tmp_path / "approved"
    data_dir.mkdir()
    monkeypatch.setitem(subject._APPROVED_DATA_DIRS, "windows", data_dir)  # pyright: ignore[reportPrivateUsage]
    peer = data_dir / "macos-peer-public-identity.json"
    peer.write_text(
        json.dumps(
            _public_identity(
                node_id="node_6000000000000000000000000000000b",
                provider="macos",
            )
        ),
        encoding="utf-8",
    )
    observation = NetworkObservation(
        provider=ProviderKind.WINDOWS,
        mode=ProviderMode.MANAGED,
        interface_name="tmn-stage6-a",
        ownership=OwnershipState.ABSENT,
        system_fingerprint=canonical_sha256({"fixture": "stage6-preview"}),
        observed_at=NOW,
    )
    provider = InMemoryNetworkProvider(observation)

    def build(
        _data_dir: Path,
        _ledger: SQLiteManagedResourceLedger,
    ) -> SimpleNamespace:
        return SimpleNamespace(provider=provider)

    monkeypatch.setattr(subject, "build_windows_managed_path_platform", build)
    monkeypatch.setattr(subject, "_git_commit", lambda: "a" * 40)
    return data_dir, provider


def test_preview_runs_lifecycle_recheck_without_apply(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)

    result = asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]

    evidence_text = (data_dir / "stage6-preview-evidence.json").read_text(encoding="utf-8")
    evidence = json.loads(evidence_text)
    assert result == {
        "authorization_rechecked": True,
        "platform": "windows",
        "provider_apply_calls": 0,
        "real_network_writes_performed": False,
    }
    assert provider.apply_calls == 0
    assert provider.observe_calls == 1
    assert evidence["authorization_reads"] == 3
    assert evidence["authorization_ttl_seconds"] == 900
    assert evidence["authorization"]["approved_by"].startswith("stage6-explicit")
    assert evidence["authorization"]["approved_at"] == NOW.isoformat()
    assert evidence["initial_phase"] == "awaiting_authorization"
    assert evidence["recheck_phase"] == "cancelled"
    assert "rechecking" in evidence["journal_phases"]
    assert evidence["provider_apply_calls"] == 0
    assert evidence["real_network_writes_performed"] is False
    assert evidence["plan"]["allowed_route_overlaps"] == [
        {
            "route": "192.0.0.0/9",
            "observation_fingerprint": (
                "sha256:43938c1ef2e9e749462dc899a7e408f759f575dc472bfe412763f7c9244814bf"
            ),
        }
    ]
    assert "secret_reference" not in evidence_text
    assert "private_key" not in evidence_text
    assert "public_key" not in evidence_text

    with pytest.raises(SystemExit, match="拒绝覆盖或复用"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]
    assert provider.apply_calls == 0


def test_preview_rejects_mismatched_peer_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)
    del provider
    (data_dir / "macos-peer-public-identity.json").write_text(
        json.dumps(
            _public_identity(
                node_id="node_6000000000000000000000000000000a",
                provider="macos",
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="固定绑定"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]

    assert not (data_dir / "stage6-preview-evidence.json").exists()
    assert not (data_dir / "stage6-preview-governance.sqlite3").exists()


def test_preview_rejects_mismatched_public_key_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)
    del provider
    payload = _public_identity(
        node_id="node_6000000000000000000000000000000b",
        provider="macos",
    )
    payload["public_key_hash"] = canonical_sha256({"public_key": "different"})
    (data_dir / "macos-peer-public-identity.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="固定绑定"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]

    assert not (data_dir / "stage6-preview-governance.sqlite3").exists()


def test_preview_rejects_reparse_peer_file_before_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)
    del provider
    peer = data_dir / "macos-peer-public-identity.json"
    real_lstat = os.lstat

    def fake_lstat(path: os.PathLike[str] | str):
        if Path(path) == peer:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            )
        return real_lstat(path)

    monkeypatch.setattr(subject.os, "lstat", fake_lstat)
    with pytest.raises(SystemExit, match="链接、重解析点"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]

    assert not (data_dir / "stage6-preview-governance.sqlite3").exists()


def test_preview_rejects_hard_linked_peer_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)
    del provider
    peer = data_dir / "macos-peer-public-identity.json"
    linked = tmp_path / "same-inode.json"
    os.link(peer, linked)

    with pytest.raises(SystemExit, match="多重硬链接"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]

    assert not (data_dir / "stage6-preview-governance.sqlite3").exists()


def test_preview_rejects_reparse_ledger_before_builder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)
    del provider
    ledger = data_dir / "managed-network-ledger.sqlite3"
    ledger.touch()
    real_lstat = os.lstat

    def fake_lstat(path: os.PathLike[str] | str):
        if Path(path) == ledger:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            )
        return real_lstat(path)

    monkeypatch.setattr(subject.os, "lstat", fake_lstat)
    with pytest.raises(SystemExit, match="链接、重解析点"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]

    assert not (data_dir / "stage6-preview-governance.sqlite3").exists()


def test_preview_refuses_existing_rollback_journal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data_dir, provider = _configure_windows_preview(monkeypatch, tmp_path)
    del provider
    (data_dir / "stage6-preview-governance.sqlite3-journal").touch()

    with pytest.raises(SystemExit, match="拒绝覆盖或复用"):
        asyncio.run(subject._run("windows", now=NOW))  # pyright: ignore[reportPrivateUsage]
