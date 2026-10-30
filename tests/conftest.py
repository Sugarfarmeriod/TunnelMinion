"""全部测试共用的夹具。"""

from __future__ import annotations

import pytest

from tunnelminion.model import secrets


@pytest.fixture(autouse=True)
def isolated_keyring_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """每个测试用自己的钥匙串队列，缓存不会把上一个测试替换的密钥环带进来。"""
    monkeypatch.setattr(secrets, "_shared_access", secrets.KeyringAccess())
