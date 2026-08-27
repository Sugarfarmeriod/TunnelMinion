"""阶段 6.3 真实 apply 入口的无网络安全门禁测试。"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from scripts import managed_path_stage6_apply as subject
from scripts import managed_path_stage6_preview as preview
from tunnelminion.domain.identifiers import AuthorizationId, NetworkId, NodeId
from tunnelminion.model.secrets import SecretStoreError
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    EndpointCandidate,
    LocalNetworkKeyMaterial,
    NetworkAction,
    NetworkObservation,
    NetworkPlan,
    OwnershipState,
    ProviderKind,
    ProviderMode,
    canonical_sha256,
)
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.network.governance import (
    NetworkAuthorizationGrant,
    NetworkAuthorizationScope,
)
from tunnelminion.network.path_controller import DirectPathErrorCode, DirectPathEvidence
from tunnelminion.network.path_probe import PathProbePolicy, PlatformPathProbe
from tunnelminion.platforms.macos.official_backend import (
    OfficialMacOSManagedBackend,
    RestrictedMacOSConfigStore,
)
from tunnelminion.platforms.windows.network_provider import WindowsNetworkProvider
from tunnelminion.platforms.windows.official_backend import (
    AclRestrictedWindowsConfigStore,
    OfficialWindowsManagedBackend,
)

NOW = datetime(2026, 8, 26, 8, 0, tzinfo=UTC)
BARRIER_ID = "a" * 32


class _Probe:
    def __init__(
        self,
        calls: list[tuple[str, int]],
        *,
        primary_succeeds: bool,
        error: DirectPathErrorCode | None = None,
    ) -> None:
        self._calls = calls
        self._primary_succeeds = primary_succeeds
        self._error = error

    async def probe(
        self,
        *,
        network_id: NetworkId,
        node_id: NodeId,
        plan_hash: str,
        authorization_revision: int,
        revision: int,
        candidates: tuple[EndpointCandidate, ...],
        expected_host_route: str,
        target_host: str,
        target_port: int,
        now: datetime,
        cancel_event: asyncio.Event | None = None,
    ) -> DirectPathEvidence:
        del candidates, cancel_event
        self._calls.append((target_host, target_port))
        verified = (self._primary_succeeds or target_port == 47990) and self._error is None
        return DirectPathEvidence(
            network_id=network_id,
            node_id=node_id,
            plan_hash=plan_hash,
            authorization_revision=authorization_revision,
            provider=ProviderKind.MACOS,
            revision=revision,
            target_host_hash=canonical_sha256({"host": target_host}),
            target_port=target_port,
            route_identity_hash=canonical_sha256({"host_route": expected_host_route}),
            candidate_count=1,
            selected_candidate_hash=f"sha256:{'b' * 64}",
            endpoint_probe_at=now,
            endpoint_probe_succeeded=True,
            last_handshake_at=now,
            handshake_fresh=True,
            host_route_probe_at=now,
            host_route_present=True,
            target_probe_at=now,
            target_probe_succeeded=verified,
            verified=verified,
            stable_error_code=(
                None if verified else self._error or DirectPathErrorCode.TARGET_UNREACHABLE
            ),
            observed_at=now,
            expires_at=now + timedelta(seconds=180),
        )

    async def target(self, host: str, port: int, timeout_seconds: float) -> bool:
        del timeout_seconds
        self._calls.append((host, port))
        return port == 47990


def _plan() -> NetworkPlan:
    config = preview._CONFIGS["macos"]  # pyright: ignore[reportPrivateUsage]
    public_key = "A" * 43 + "="
    identity = preview._PublicIdentity.model_validate(  # pyright: ignore[reportPrivateUsage]
        {
            "schema_version": "managed-path-stage6-public-identity/v1",
            "network_id": "network_60000000000000000000000000000000",
            "node_id": "node_6000000000000000000000000000000a",
            "provider": "windows",
            "public_key": public_key,
            "public_key_hash": canonical_sha256({"public_key": public_key}),
            "secret_reference_configured": True,
        }
    )
    desired = preview._desired_config(  # pyright: ignore[reportPrivateUsage]
        config, identity, now=NOW
    )
    observation = NetworkObservation(
        provider=ProviderKind.MACOS,
        mode=ProviderMode.MANAGED,
        interface_name=desired.interface_name,
        ownership=OwnershipState.ABSENT,
        system_fingerprint=canonical_sha256({"fixture": "stage6-apply"}),
        observed_at=NOW,
    )
    provider = InMemoryNetworkProvider(observation)

    async def build():
        observed = await provider.observe(desired.interface_name)
        return await provider.plan(
            action=NetworkAction.CREATE,
            desired=desired,
            observed=observed,
            ownership=None,
        )

    return asyncio.run(build())


def _grant(plan: NetworkPlan) -> NetworkAuthorizationGrant:
    expires_at = datetime.now(UTC) + timedelta(minutes=15)
    return NetworkAuthorizationGrant(
        authorization_id=AuthorizationId.new(),
        scope=NetworkAuthorizationScope.from_plan(
            plan, address_pool="192.0.2.0/30", interface_prefix="tmn-stage6-"
        ),
        approved_by="test",
        approved_at=NOW,
        expires_at=expires_at,
    )


def _release(
    data_dir: Path,
    plan: NetworkPlan,
    verifier: subject._BarrierPathVerifier,  # pyright: ignore[reportPrivateUsage]
) -> NetworkAuthorizationGrant:
    grant = _grant(plan)
    verifier.bind_authorization(grant)
    authorization_hash = verifier._authorization_hash  # pyright: ignore[reportPrivateUsage]
    local: dict[str, object] = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "macos",
        "barrier_id_hash": canonical_sha256({"barrier_id": BARRIER_ID}),
        "plan_hash": plan.plan_hash,
        "authorization_hash": authorization_hash,
        "authorization_expires_at": grant.expires_at.isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    peer: dict[str, object] = {
        **local,
        "platform": "windows",
        "plan_hash": f"sha256:{'d' * 64}",
        "authorization_hash": f"sha256:{'e' * 64}",
    }
    (data_dir / "stage6-apply-ready.json").write_text(json.dumps(local), encoding="utf-8")
    (data_dir / "stage6-apply-peer-ready.json").write_text(json.dumps(peer), encoding="utf-8")
    release = subject._go_marker(  # pyright: ignore[reportPrivateUsage]
        "macos", BARRIER_ID, local, peer
    )
    (data_dir / "stage6-apply-go.json").write_text(json.dumps(release), encoding="utf-8")
    return grant


def test_barrier_verifier_uses_fallback_only_after_primary_failure(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=False))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    _release(tmp_path, plan, verifier)
    evidence = asyncio.run(verifier.verify(plan, now=NOW))

    assert evidence.verified
    assert calls == [("192.0.2.1", 7899), ("192.0.2.1", 47990)]
    assert verifier.probe_runs == 1
    assert verifier.target_attempts == [7899, 47990]


def test_barrier_verifier_stops_after_primary_success(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=True))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    _release(tmp_path, plan, verifier)

    assert asyncio.run(verifier.verify(plan, now=NOW)).verified
    assert calls == [("192.0.2.1", 7899)]


def test_targets_match_authorization_and_are_not_discovery_ranges() -> None:
    assert {  # pyright: ignore[reportPrivateUsage]
        "windows": (subject._ApprovedTarget("192.0.2.2", 8787),),  # pyright: ignore[reportPrivateUsage]
        "macos": (
            subject._ApprovedTarget("192.0.2.1", 7899),  # pyright: ignore[reportPrivateUsage]
            subject._ApprovedTarget("192.0.2.1", 47990),  # pyright: ignore[reportPrivateUsage]
        ),
    } == subject._TARGETS  # pyright: ignore[reportPrivateUsage]


def test_release_requires_matching_local_and_peer_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(
        subject._APPROVED_DATA_DIRS,  # pyright: ignore[reportPrivateUsage]
        "windows",
        tmp_path,
    )
    barrier_hash = canonical_sha256({"barrier_id": BARRIER_ID})
    local = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'c' * 64}",
        "authorization_hash": f"sha256:{'e' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    peer = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "macos",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'d' * 64}",
        "authorization_hash": f"sha256:{'f' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    (tmp_path / "stage6-apply-ready.json").write_text(json.dumps(local), encoding="utf-8")
    with pytest.raises(SystemExit, match="peer-ready"):
        subject._release_barrier("windows", BARRIER_ID)  # pyright: ignore[reportPrivateUsage]
    (tmp_path / "stage6-apply-peer-ready.json").write_text(json.dumps(peer), encoding="utf-8")

    subject._release_barrier("windows", BARRIER_ID)  # pyright: ignore[reportPrivateUsage]

    released = json.loads((tmp_path / "stage6-apply-go.json").read_text(encoding="utf-8"))
    assert released["release_after_both_provider_verified"] is True
    assert released["local_plan_hash"] == local["plan_hash"]
    assert released["peer_plan_hash"] == peer["plan_hash"]
    assert "barrier_id" not in released


def test_authorization_expiry_after_barrier_makes_zero_target_calls(
    tmp_path: Path,
) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []
    clock = [NOW]

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=True))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: clock[0],
    )
    grant = _release(tmp_path, plan, verifier)
    clock[0] = grant.expires_at

    with pytest.raises(RuntimeError, match="授权已过期"):
        asyncio.run(verifier.verify(plan, now=NOW))
    assert calls == []


def test_fallback_rechecks_ttl_and_does_not_connect_after_expiry(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []
    clock_values: list[datetime] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=False))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: clock_values.pop(0),
    )
    grant = _release(tmp_path, plan, verifier)
    clock_values.extend((NOW, NOW, grant.expires_at))

    with pytest.raises(RuntimeError, match="授权已过期"):
        asyncio.run(verifier.verify(plan, now=NOW))
    assert calls == [("192.0.2.1", 7899)]


def test_non_target_unreachable_error_never_uses_fallback(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(
            PlatformPathProbe,
            _Probe(
                calls,
                primary_succeeds=False,
                error=DirectPathErrorCode.PERMISSION_DENIED,
            ),
        )

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    _release(tmp_path, plan, verifier)

    evidence = asyncio.run(verifier.verify(plan, now=NOW))
    assert evidence.stable_error_code is DirectPathErrorCode.PERMISSION_DENIED
    assert calls == [("192.0.2.1", 7899)]


def test_started_target_attempt_without_result_is_never_replayed(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[tuple[str, int]] = []

    def factory(desired: DesiredNetworkConfig, policy: PathProbePolicy) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(calls, primary_succeeds=True))

    verifier = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=factory,
        clock=lambda: NOW,
    )
    grant = _release(tmp_path, plan, verifier)
    go = json.loads((tmp_path / "stage6-apply-go.json").read_text(encoding="utf-8"))
    subject._target_attempt(  # pyright: ignore[reportPrivateUsage]
        data_dir=tmp_path,
        label="primary",
        platform="macos",
        barrier_id=BARRIER_ID,
        pair_hash=go["pair_hash"],
        plan_hash=plan.plan_hash,
        authorization_hash=cast(
            str,
            verifier._authorization_hash,  # pyright: ignore[reportPrivateUsage]
        ),
        target=subject._TARGETS["macos"][0],  # pyright: ignore[reportPrivateUsage]
        now=grant.approved_at,
    )

    with pytest.raises(RuntimeError, match="结果不确定"):
        asyncio.run(verifier.verify(plan, now=NOW))
    assert calls == []


def test_completed_fallback_recovery_keeps_original_stale_time_and_never_reconnects(
    tmp_path: Path,
) -> None:
    plan = _plan()
    initial_calls: list[tuple[str, int]] = []

    def initial_factory(
        desired: DesiredNetworkConfig, policy: PathProbePolicy
    ) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(initial_calls, primary_succeeds=False))

    initial = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=initial_factory,
        clock=lambda: NOW,
    )
    grant = _release(tmp_path, plan, initial)
    original = asyncio.run(initial.verify(plan, now=NOW))
    assert original.verified
    assert initial_calls == [("192.0.2.1", 7899), ("192.0.2.1", 47990)]

    recovery_calls: list[tuple[str, int]] = []

    def recovery_factory(
        desired: DesiredNetworkConfig, policy: PathProbePolicy
    ) -> PlatformPathProbe:
        del desired, policy
        return cast(PlatformPathProbe, _Probe(recovery_calls, primary_succeeds=True))

    stale_now = NOW + timedelta(seconds=181)
    recovery = subject._BarrierPathVerifier(  # pyright: ignore[reportPrivateUsage]
        platform="macos",
        barrier_id=BARRIER_ID,
        data_dir=tmp_path,
        probe_factory=recovery_factory,
        clock=lambda: stale_now,
    )
    recovery.bind_authorization(grant)
    recovered = asyncio.run(recovery.verify(plan, now=stale_now))

    assert recovery_calls == []
    assert recovered.observed_at == original.observed_at
    assert recovered.target_probe_at == original.target_probe_at
    assert recovered.expires_at == original.expires_at
    assert recovered.expires_at <= stale_now


class _VanishingSecretStore:
    def __init__(self, value: str) -> None:
        self._values = [value, None]
        self.set_calls = 0
        self.delete_calls = 0

    def get(self, name: str) -> str | None:
        del name
        return self._values.pop(0)

    def set(self, name: str, value: str) -> None:
        del name, value
        self.set_calls += 1

    def delete(self, name: str) -> None:
        del name
        self.delete_calls += 1


def test_existing_only_identity_disappearance_never_creates_or_deletes(
    tmp_path: Path,
) -> None:
    private = X25519PrivateKey.generate()
    private_text = base64.b64encode(
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    backend = _VanishingSecretStore(private_text)
    name = (
        "wireguard/network_60000000000000000000000000000000/node_6000000000000000000000000000000a"
    )
    store = subject._ExistingOnlySecretStore(  # pyright: ignore[reportPrivateUsage]
        backend,
        expected_name=name,
        expected_public_key=public,
        expected_public_key_hash=canonical_sha256({"public_key": public}),
    )
    assert store.get(name) is not None
    materials = RestrictedMacOSConfigStore(tmp_path.resolve(), store)

    with pytest.raises(SecretStoreError, match="拒绝创建替代身份"):
        materials.ensure_identity(
            NetworkId("network_60000000000000000000000000000000"),
            NodeId("node_6000000000000000000000000000000a"),
        )
    assert backend.set_calls == 0
    assert backend.delete_calls == 0
    assert list(tmp_path.iterdir()) == []


def test_go_marker_rejects_wrong_peer_platform_and_extra_fields(tmp_path: Path) -> None:
    expires_at = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
    base: dict[str, object] = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": canonical_sha256({"barrier_id": BARRIER_ID}),
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_hash": f"sha256:{'b' * 64}",
        "authorization_expires_at": expires_at,
        "provider_verified": True,
        "network_writes_completed": True,
    }
    wrong_peer = {**base, "plan_hash": f"sha256:{'c' * 64}"}
    with pytest.raises(RuntimeError, match="绑定"):
        subject._go_marker(  # pyright: ignore[reportPrivateUsage]
            "windows", BARRIER_ID, base, wrong_peer
        )
    marker_path = tmp_path / "marker.json"
    marker_path.write_text(json.dumps({**base, "extra": True}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="schema"):
        subject._load_exact_marker(  # pyright: ignore[reportPrivateUsage]
            marker_path,
            subject._READY_KEYS,  # pyright: ignore[reportPrivateUsage]
        )


def test_main_returns_nonzero_when_acceptance_is_not_successful(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failed_run(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        return {"platform": "windows", "success": False}

    def matching_platform(platform: str) -> None:
        del platform

    monkeypatch.setattr(subject, "_require_matching_platform", matching_platform)
    monkeypatch.setattr(subject, "_run", failed_run)
    assert subject.main(["--platform", "windows", "--barrier-id", BARRIER_ID]) == 2


def test_ready_marker_rejects_non_hex_hash_naive_expiry_and_replay() -> None:
    barrier_hash = canonical_sha256({"barrier_id": BARRIER_ID})
    base: dict[str, object] = {
        "schema_version": "managed-path-stage6-barrier/v2",
        "platform": "windows",
        "barrier_id_hash": barrier_hash,
        "plan_hash": f"sha256:{'a' * 64}",
        "authorization_hash": f"sha256:{'b' * 64}",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        "provider_verified": True,
        "network_writes_completed": True,
    }
    with pytest.raises(RuntimeError, match="绑定"):
        subject._validate_ready_marker(  # pyright: ignore[reportPrivateUsage]
            {**base, "plan_hash": f"sha256:{'g' * 64}"},
            platform="windows",
            barrier_hash=barrier_hash,
        )
    with pytest.raises(RuntimeError, match="绑定"):
        subject._validate_ready_marker(  # pyright: ignore[reportPrivateUsage]
            {
                **base,
                "authorization_expires_at": (datetime.now() + timedelta(minutes=15)).isoformat(),
            },
            platform="windows",
            barrier_hash=barrier_hash,
        )
    with pytest.raises(RuntimeError, match="绑定"):
        subject._validate_ready_marker(  # pyright: ignore[reportPrivateUsage]
            base,
            platform="windows",
            barrier_hash=canonical_sha256({"barrier_id": "replayed"}),
        )


def test_platform_identity_delegates_remain_available_for_default_factories() -> None:
    material = LocalNetworkKeyMaterial(
        secret_reference="keyring:test",
        public_key="A" * 43 + "=",
        public_key_hash=f"sha256:{'a' * 64}",
    )

    class IdentityFactory:
        def create_identity(
            self, network_id: NetworkId, node_id: NodeId
        ) -> LocalNetworkKeyMaterial:
            del network_id, node_id
            return material

    macos = object.__new__(OfficialMacOSManagedBackend)
    macos._materials = cast(  # pyright: ignore[reportPrivateUsage]
        RestrictedMacOSConfigStore, IdentityFactory()
    )
    windows = object.__new__(OfficialWindowsManagedBackend)
    windows._materials = cast(  # pyright: ignore[reportPrivateUsage]
        AclRestrictedWindowsConfigStore, IdentityFactory()
    )
    provider = object.__new__(WindowsNetworkProvider)
    provider._backend = windows  # pyright: ignore[reportPrivateUsage]

    network_id = NetworkId("network_60000000000000000000000000000000")
    node_id = NodeId("node_6000000000000000000000000000000a")
    assert macos.create_identity(network_id, node_id) is material
    assert windows.create_identity(network_id, node_id) is material
    assert provider.create_local_identity(network_id, node_id) is material


def test_macos_root_reads_only_approved_login_keychain_item_without_secret_in_argv() -> None:
    captured: list[tuple[tuple[str, ...], dict[str, object]]] = []
    private_text = "private-material-only-in-stdout"

    def run_process(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, f"{private_text}\n", "ignored")

    name = "wireguard/network/node"
    store = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name=name,
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=lambda: 501,
        run_process=run_process,
    )

    assert store.get(name) == private_text
    command, kwargs = captured[0]
    assert command == (
        "/bin/launchctl",
        "asuser",
        "501",
        "/usr/bin/sudo",
        "-u",
        "#501",
        "-H",
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        "TunnelMinion",
        "-a",
        name,
        "-w",
    )
    assert private_text not in command
    assert kwargs["timeout"] == 15
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    with pytest.raises(SecretStoreError, match="禁止创建"):
        store.set(name, private_text)
    with pytest.raises(SecretStoreError, match="禁止删除"):
        store.delete(name)


@pytest.mark.parametrize(
    ("platform_name", "effective_uid", "console_uid", "requested_name", "message"),
    [
        ("win32", 0, 501, "wireguard/network/node", "上下文无效"),
        ("darwin", 501, 501, "wireguard/network/node", "上下文无效"),
        ("darwin", 0, 501, "wireguard/other/node", "非批准名称"),
        ("darwin", 0, 0, "wireguard/network/node", "普通登录用户"),
        ("darwin", 0, 2**31, "wireguard/network/node", "普通登录用户"),
    ],
)
def test_macos_login_keychain_store_rejects_wrong_boundary(
    platform_name: str,
    effective_uid: int,
    console_uid: int,
    requested_name: str,
    message: str,
) -> None:
    store = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name=platform_name,
        effective_uid=lambda: effective_uid,
        console_uid=lambda: console_uid,
    )
    with pytest.raises(SecretStoreError, match=message):
        store.get(requested_name)


def test_macos_login_keychain_store_redacts_failures() -> None:
    def missing_console() -> int:
        raise OSError("sensitive console detail")

    missing = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=missing_console,
    )
    with pytest.raises(SecretStoreError, match="无法确认") as console_error:
        missing.get("wireguard/network/node")
    assert "sensitive" not in str(console_error.value)

    def failed_process(
        command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(command, 1, "private-output", "sensitive error")

    failed = subject._MacOSLoginKeychainSecretStore(  # pyright: ignore[reportPrivateUsage]
        expected_name="wireguard/network/node",
        platform_name="darwin",
        effective_uid=lambda: 0,
        console_uid=lambda: 501,
        run_process=failed_process,
    )
    with pytest.raises(SecretStoreError, match="无法读取") as process_error:
        failed.get("wireguard/network/node")
    assert "private-output" not in str(process_error.value)
    assert "sensitive error" not in str(process_error.value)
