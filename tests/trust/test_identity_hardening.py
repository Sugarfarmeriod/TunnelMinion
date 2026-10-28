"""加入应答绑定地址与时效、旧式配对不能被冒用或绕过名单权限。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from tests.trust.test_own_devices import NOW, computer, request_for

from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.trust import PassScope
from tunnelminion.gateway.security import GatewayPeerPolicy
from tunnelminion.trust.contracts import DevicePermissions, IdentityError
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.passes import issue_pass

LEGACY_TOKEN = "tmn_" + "l" * 40
OTHER_TOKEN = "tmn_" + "o" * 40


def legacy(
    node_id: NodeId,
    host: str,
    token: str = LEGACY_TOKEN,
    *,
    allow_delegation: bool = False,
    allow_model_borrowing: bool = False,
    allow_proxy_repair_approval: bool = False,
) -> GatewayPeerPolicy:
    return GatewayPeerPolicy.from_token(
        node_id,
        token,
        ("get_node_summary",),
        ("restart_container",),
        source_host=host,
        allow_delegation=allow_delegation,
        allow_model_borrowing=allow_model_borrowing,
        allow_proxy_repair_approval=allow_proxy_repair_approval,
    )


def test_join_proof_is_bound_to_reported_address(tmp_path: Path) -> None:
    a = computer(tmp_path / "a", 1, {})
    code = a.service.invite()
    request = request_for(code, NodeId.new(), PrivateKey.generate(), "10.20.0.9")
    moved = request.model_copy(update={"host": "10.20.0.7"})
    with pytest.raises(IdentityError):
        a.service.accept_join(code.token, moved, "10.20.0.7")
    moved_port = request.model_copy(update={"port": 9999})
    with pytest.raises(IdentityError):
        a.service.accept_join(code.token, moved_port, "10.20.0.9")
    # 地址没被改过的原应答仍然可以用，说明前两次失败没有烧掉加入码。
    assert a.service.accept_join(code.token, request, "10.20.0.9").roster is not None
    # 同一个加入码只能用一次，换一台电脑、换一份新应答也不行。
    again = request_for(code, NodeId.new(), PrivateKey.generate(), "10.20.0.10")
    with pytest.raises(IdentityError):
        a.service.accept_join(code.token, again, "10.20.0.10")


@pytest.mark.parametrize("offset", [timedelta(minutes=6), -timedelta(minutes=6)])
def test_join_proof_must_be_fresh(tmp_path: Path, offset: timedelta) -> None:
    a = computer(tmp_path / "a", 1, {})
    code = a.service.invite()
    request = request_for(code, NodeId.new(), PrivateKey.generate(), "10.20.0.9")
    a.service.clock = lambda: NOW + offset
    with pytest.raises(IdentityError):
        a.service.accept_join(code.token, request, "10.20.0.9")


def test_join_cannot_take_over_legacy_node_id(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    taken = NodeId.new()
    a.policy.upsert_static_peer(legacy(taken, "10.20.0.8"))
    code = a.service.invite()

    async def post(node_id: NodeId) -> int:
        body = request_for(code, node_id, PrivateKey.generate(), "10.20.0.9").model_dump_json()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(apps[a.host], client=("10.20.0.9", 1234)),
            base_url="http://10.20.0.1:8787",
        ) as client:
            response = await client.post(
                "/v1/owner:join",
                content=body,
                headers={"Authorization": f"Bearer {code.token}"},
            )
        return response.status_code

    async def scenario() -> None:
        assert await post(taken) == 401
        # 冒用被拒时加入码没被消费，正常的新电脑仍能加入。
        assert await post(NodeId.new()) == 200

    asyncio.run(scenario())
    assert a.service.roster().device(taken) is None


@pytest.mark.parametrize(
    ("same_host", "expected"), [(True, frozenset({"restart_container"})), (False, frozenset[str]())]
)
def test_pass_inherits_legacy_operations_only_from_same_address(
    tmp_path: Path, same_host: bool, expected: frozenset[str]
) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    a.policy.upsert_static_peer(legacy(b.service.node_id, b.host if same_host else "10.20.0.99"))
    credential = issue_pass(b.service, a.service.node_id, PassScope.TOOL_GATEWAY)
    peer = a.policy.authenticate(f"Bearer {credential}", source_host=b.host)
    assert peer is not None
    assert peer.allowed_operations == expected


def test_legacy_token_cannot_exceed_local_restrictions(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    a.policy.upsert_static_peer(
        legacy(
            b.service.node_id,
            b.host,
            allow_delegation=True,
            allow_model_borrowing=True,
            allow_proxy_repair_approval=True,
        )
    )
    a.service.restrict(
        b.service.node_id,
        DevicePermissions(allow_proxy_repair_approval=False, daily_quota=1000),
    )
    peer = a.policy.authenticate(f"Bearer {LEGACY_TOKEN}", source_host=b.host)
    assert peer is not None
    assert peer.allow_proxy_repair_approval is False
    assert peer.allow_delegation is True
    assert peer.daily_quota == 1000


def test_removed_computer_legacy_token_is_revoked(tmp_path: Path) -> None:
    apps: dict[str, FastAPI] = {}
    a = computer(tmp_path / "a", 1, apps)
    b = computer(tmp_path / "b", 2, apps, a)
    a.policy.upsert_static_peer(legacy(b.service.node_id, b.host))
    assert a.policy.authenticate(f"Bearer {LEGACY_TOKEN}", source_host=b.host) is not None
    a.service.remove(b.service.node_id)
    assert a.policy.authenticate(f"Bearer {LEGACY_TOKEN}", source_host=b.host) is None
    # 从没进过名单的旧式配对不受影响。
    a.policy.upsert_static_peer(legacy(NodeId.new(), "10.20.0.50", OTHER_TOKEN))
    assert a.policy.authenticate(f"Bearer {OTHER_TOKEN}", source_host="10.20.0.50") is not None
