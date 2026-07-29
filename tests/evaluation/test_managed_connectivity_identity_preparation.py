"""受管连接隔离身份准备入口测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import prepare_managed_connectivity_identity as subject

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import LocalNetworkKeyMaterial

NETWORK_ID = NetworkId("network_0123456789abcdef0123456789abcdef")
NODE_ID = NodeId("node_0123456789abcdef0123456789abcdef")


def authorization_plan(path: Path, *, confirmed: bool = True) -> Path:
    path.write_text(
        json.dumps(
            {
                "status": "explicit_user_authorization_received",
                "required_user_confirmation": "completed" if confirmed else "pending",
            }
        ),
        encoding="utf-8",
    )
    return path


def fake_material(
    platform: str,
    root: Path,
    network_id: NetworkId,
    node_id: NodeId,
) -> LocalNetworkKeyMaterial:
    assert platform == "macos"
    assert root.is_absolute()
    assert network_id == NETWORK_ID
    assert node_id == NODE_ID
    return LocalNetworkKeyMaterial(
        secret_reference="file:isolated-secret",
        public_key="A" * 43 + "=",
        public_key_hash="sha256:" + "a" * 64,
    )


def test_prepare_identity_initializes_empty_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "prepare_material", fake_material)
    report = subject.prepare_identity(
        platform="macos",
        data_directory=tmp_path / "data",
        authorization_plan=authorization_plan(tmp_path / "authorization.json"),
        network_id=NETWORK_ID,
        node_id=NODE_ID,
    )
    assert report.public_key_hash == "sha256:" + "a" * 64
    assert report.network_writes_performed is False
    assert Path(report.ownership_ledger).exists()


def test_prepare_identity_rejects_unconfirmed_plan(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="尚未记录"):
        subject.prepare_identity(
            platform="macos",
            data_directory=tmp_path / "data",
            authorization_plan=authorization_plan(
                tmp_path / "authorization.json",
                confirmed=False,
            ),
            network_id=NETWORK_ID,
            node_id=NODE_ID,
        )


def test_windows_material_rejects_non_windows_host(tmp_path: Path) -> None:
    if subject.os.name == "nt":
        pytest.skip("仅验证非 Windows 拒绝分支")
    with pytest.raises(RuntimeError, match="只能在 Windows"):
        subject.prepare_material("windows", tmp_path, NETWORK_ID, NODE_ID)
