"""Windows 官方 tunnel service 后端和 ACL 配置材料测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from tests.network.factories import NETWORK_ID, NODE_A, desired, observation

from tunnelminion.network.contracts import (
    ApprovedRouteOverlap,
    NetworkAction,
    NetworkErrorCode,
    NetworkPlanStep,
    PlanStepKind,
    canonical_sha256,
)
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.platforms.windows.managed_system import (
    FixedWindowsWireGuardCommands,
    WindowsProviderPaths,
    WindowsTunnelSnapshot,
)
from tunnelminion.platforms.windows.network_provider import WindowsBackendError
from tunnelminion.platforms.windows.official_backend import (
    AclRestrictedWindowsConfigStore,
    OfficialWindowsManagedBackend,
)
from tunnelminion.platforms.windows.system import CommandResult


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class FakeRunner:
    def __init__(self) -> None:
        self.returncode = 0
        self.commands: list[tuple[str, ...]] = []
        self.stdout = ""

    async def run(
        self,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> CommandResult:
        assert timeout_seconds > 0
        self.commands.append(command)
        return CommandResult(returncode=self.returncode, stdout=self.stdout, stderr="")


class FakeObserver:
    def __init__(self) -> None:
        self.snapshot = WindowsTunnelSnapshot(
            interface_name="tmn-test-a",
            interface_present=False,
            interface_up=False,
            service_present=False,
            service_running=False,
        )

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        assert interface_name in {"tmn-test-a", "HomeMac"}
        return self.snapshot.model_copy(update={"interface_name": interface_name})


def fixed(tmp_path: Path, runner: FakeRunner) -> FixedWindowsWireGuardCommands:
    paths = WindowsProviderPaths(
        wireguard_exe=tmp_path / "wireguard.exe",
        wg_exe=tmp_path / "wg.exe",
        sc_exe=tmp_path / "sc.exe",
        route_exe=tmp_path / "route.exe",
        config_root=tmp_path / "configs",
    )
    return FixedWindowsWireGuardCommands(
        paths,
        runner,
        path_exists=lambda _path: True,
        is_administrator=lambda: True,
        platform_name="nt",
    )


def materials(
    tmp_path: Path,
    secrets_store: MemorySecrets,
    runner: FakeRunner,
) -> AclRestrictedWindowsConfigStore:
    return AclRestrictedWindowsConfigStore(
        tmp_path / "configs",
        secrets_store,
        runner,
        tmp_path / "icacls.exe",
        account_name="TEST\\owner",
    )


def test_material_store_generates_reuses_writes_and_deletes_secret(tmp_path: Path) -> None:
    secrets_store = MemorySecrets()
    runner = FakeRunner()
    store = materials(tmp_path, secrets_store, runner)
    config = desired()
    material = store.ensure_secret(config)
    repeated = store.ensure_secret(config)
    assert material == repeated
    assert material.public_key.endswith("=")
    assert len(secrets_store.values) == 1

    receipt_hash = asyncio.run(store.write(config, material.secret_reference, "a" * 32))
    config_path = store.config_path("tmn-test-a", 1)
    text = config_path.read_text(encoding="utf-8")
    assert receipt_hash.startswith("sha256:")
    assert "[Interface]" in text
    assert "Address = 10.203.0.1/32" in text
    assert "AllowedIPs = 10.203.0.2/32" in text
    assert "PrivateKey =" in text
    assert store.read_creation_nonce("tmn-test-a") == "a" * 32
    assert all(isinstance(command, tuple) for command in runner.commands)

    deleted = asyncio.run(store.delete_config("tmn-test-a", 1))
    assert deleted.startswith("sha256:")
    assert not config_path.exists()
    asyncio.run(store.delete_config("tmn-test-a", 1))
    asyncio.run(store.delete_secret(config, material.secret_reference))
    asyncio.run(store.delete_secret(config, material.secret_reference))
    assert secrets_store.values == {}
    assert store.read_creation_nonce("tmn-test-a") is None


def test_material_store_rejects_paths_accounts_refs_acl_and_corrupt_marker(
    tmp_path: Path,
) -> None:
    secrets_store = MemorySecrets()
    runner = FakeRunner()
    with pytest.raises(ValueError, match="绝对路径"):
        AclRestrictedWindowsConfigStore(
            Path("relative"),
            secrets_store,
            runner,
            tmp_path / "icacls.exe",
        )
    with pytest.raises(ValueError, match="账户"):
        AclRestrictedWindowsConfigStore(
            tmp_path / "configs",
            secrets_store,
            runner,
            tmp_path / "icacls.exe",
            account_name="bad;&",
        )
    store = materials(tmp_path, secrets_store, runner)
    with pytest.raises(ValueError, match="身份"):
        store.config_path("HomeMac", 1)
    with pytest.raises(ValueError, match="身份"):
        store.config_path("tmn-test-a", 0)
    with pytest.raises(ValueError, match="接口名称"):
        store.marker_path("bad;&")
    with pytest.raises(ValueError, match="keyring"):
        asyncio.run(store.write(desired(), "file:wrong", "a" * 32))

    reference = store.ensure_secret(desired()).secret_reference
    runner.returncode = 5
    with pytest.raises(WindowsBackendError) as denied:
        asyncio.run(store.write(desired(), reference, "a" * 32))
    assert denied.value.code is NetworkErrorCode.PERMISSION_DENIED
    assert not any(path.suffix == ".tmp" for path in store.root.glob("*"))

    runner.returncode = 0
    secrets_store.delete(reference.removeprefix("keyring:"))
    with pytest.raises(WindowsBackendError) as missing:
        asyncio.run(store.write(desired(), reference, "a" * 32))
    assert missing.value.code is NetworkErrorCode.RECOVERY_REQUIRED

    store.root.mkdir(parents=True, exist_ok=True)
    marker = store.marker_path("tmn-test-a")
    marker.write_text('{"creation_nonce":"bad"}', encoding="utf-8")
    with pytest.raises(ValueError, match="marker"):
        store.read_creation_nonce("tmn-test-a")
    marker.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="marker"):
        store.read_creation_nonce("tmn-test-a")


def test_official_backend_maps_fixed_steps_and_observation_nonce(tmp_path: Path) -> None:
    secrets_store = MemorySecrets()
    runner = FakeRunner()
    command_boundary = fixed(tmp_path, runner)
    store = materials(tmp_path, secrets_store, runner)
    observer = FakeObserver()
    backend = OfficialWindowsManagedBackend(command_boundary, observer, store)
    assert backend.preflight().administrator
    assert backend.ensure_identity(NETWORK_ID, NODE_A).public_key.endswith("=")
    reference = backend.ensure_secret(desired()).secret_reference
    asyncio.run(backend.validate_no_conflicts(desired()))
    plan = asyncio.run(
        InMemoryNetworkProvider(observation()).plan(
            action=NetworkAction.CREATE,
            desired=desired(),
            observed=observation(),
            ownership=None,
        )
    )
    for step in plan.steps:
        result = asyncio.run(
            backend.execute_step(
                plan,
                step,
                secret_reference=reference,
                creation_nonce="b" * 32,
                idempotency_key=f"netop_{'a' * 64}",
            )
        )
        assert result.startswith("sha256:")
    snapshot = asyncio.run(backend.observe("tmn-test-a"))
    assert snapshot.creation_nonce == "b" * 32
    assert asyncio.run(backend.observe("HomeMac")).creation_nonce is None
    assert any("/installtunnelservice" in command for command in runner.commands)

    for step in reversed(plan.steps):
        result = asyncio.run(
            backend.rollback_step(
                plan,
                step,
                secret_reference=reference,
                creation_nonce="b" * 32,
                idempotency_key=f"netop_{'a' * 64}",
            )
        )
        assert result.startswith("sha256:")


def test_official_backend_route_table_conflict_and_unavailable(tmp_path: Path) -> None:
    secrets_store = MemorySecrets()
    runner = FakeRunner()
    backend = OfficialWindowsManagedBackend(
        fixed(tmp_path, runner),
        FakeObserver(),
        materials(tmp_path, secrets_store, runner),
    )
    runner.stdout = """
      Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       192.0.2.1      192.0.2.2     25
       10.128.0.0        255.128.0.0         On-link       198.18.0.1      0
       malformed row
    """
    with pytest.raises(WindowsBackendError) as conflict:
        asyncio.run(backend.validate_no_conflicts(desired()))
    assert conflict.value.code is NetworkErrorCode.ROUTE_NOT_ALLOWED
    overlap = ApprovedRouteOverlap(
        route="10.128.0.0/9",
        observation_fingerprint=canonical_sha256(
            {
                "route": "10.128.0.0/9",
                "interface_locator": "198.18.0.1",
            }
        ),
    )
    asyncio.run(backend.validate_no_conflicts(desired(allowed_route_overlaps=(overlap,))))
    with pytest.raises(WindowsBackendError):
        asyncio.run(
            backend.validate_no_conflicts(
                desired(
                    allowed_route_overlaps=(
                        overlap.model_copy(
                            update={"observation_fingerprint": "sha256:" + "f" * 64}
                        ),
                    )
                )
            )
        )

    runner.returncode = 1
    with pytest.raises(WindowsBackendError) as unavailable:
        asyncio.run(backend.validate_no_conflicts(desired()))
    assert unavailable.value.code is NetworkErrorCode.PROVIDER_UNAVAILABLE


def test_official_backend_stop_remove_delete_failure_and_parent_restore(
    tmp_path: Path,
) -> None:
    secrets_store = MemorySecrets()
    runner = FakeRunner()
    command_boundary = fixed(tmp_path, runner)
    store = materials(tmp_path, secrets_store, runner)
    backend = OfficialWindowsManagedBackend(command_boundary, FakeObserver(), store)
    reference = backend.ensure_secret(desired()).secret_reference
    base_plan = asyncio.run(
        InMemoryNetworkProvider(observation()).plan(
            action=NetworkAction.CREATE,
            desired=desired(revision=2, parent_revision=1),
            observed=observation(),
            ownership=None,
        )
    )
    asyncio.run(store.write(base_plan.desired, reference, "c" * 32))
    steps = (
        NetworkPlanStep(
            index=0,
            kind=PlanStepKind.STOP_INTERFACE,
            target="tmn-test-a",
            expected_effect="stop",
            rollback_kind=PlanStepKind.CREATE_INTERFACE,
        ),
        NetworkPlanStep(
            index=1,
            kind=PlanStepKind.REMOVE_INTERFACE,
            target="tmn-test-a",
            expected_effect="remove",
            rollback_kind=PlanStepKind.CREATE_INTERFACE,
        ),
        NetworkPlanStep(
            index=2,
            kind=PlanStepKind.DELETE_CONFIG,
            target="tmn-test-a",
            expected_effect="delete config",
            rollback_kind=PlanStepKind.WRITE_CONFIG,
        ),
        NetworkPlanStep(
            index=3,
            kind=PlanStepKind.DELETE_SECRET,
            target="tmn-test-a",
            expected_effect="delete secret",
        ),
    )
    for step in steps:
        assert asyncio.run(
            backend.execute_step(
                base_plan,
                step,
                secret_reference=reference,
                creation_nonce="c" * 32,
                idempotency_key=f"netop_{'b' * 64}",
            )
        ).startswith("sha256:")

    # parent revision 存在时只能使用固定配置路径恢复。
    runner.returncode = 0
    assert asyncio.run(
        backend.rollback_step(
            base_plan,
            steps[0],
            secret_reference=reference,
            creation_nonce="c" * 32,
            idempotency_key=f"netop_{'b' * 64}",
        )
    ).startswith("sha256:")

    no_parent = base_plan.model_copy(
        update={"desired": base_plan.desired.model_copy(update={"parent_revision": 0})}
    )
    assert asyncio.run(
        backend.rollback_step(
            no_parent,
            steps[0],
            secret_reference=reference,
            creation_nonce="c" * 32,
            idempotency_key=f"netop_{'b' * 64}",
        )
    ).startswith("sha256:")

    runner.returncode = 1
    with pytest.raises(WindowsBackendError) as failed:
        asyncio.run(
            backend.execute_step(
                base_plan,
                steps[0],
                secret_reference=reference,
                creation_nonce="c" * 32,
                idempotency_key=f"netop_{'b' * 64}",
            )
        )
    assert failed.value.retryable

    runner.returncode = 0
    with pytest.raises(WindowsBackendError) as irreversible:
        asyncio.run(
            backend.rollback_step(
                base_plan,
                steps[3],
                secret_reference=reference,
                creation_nonce="c" * 32,
                idempotency_key=f"netop_{'b' * 64}",
            )
        )
    assert irreversible.value.code is NetworkErrorCode.ROLLBACK_FAILED


def test_rendered_marker_contains_only_nonce_and_revision(tmp_path: Path) -> None:
    secrets_store = MemorySecrets()
    runner = FakeRunner()
    store = materials(tmp_path, secrets_store, runner)
    reference = store.ensure_secret(desired()).secret_reference
    asyncio.run(store.write(desired(), reference, "d" * 32))
    marker = json.loads(store.marker_path("tmn-test-a").read_text(encoding="utf-8"))
    assert marker == {"creation_nonce": "d" * 32, "revision": 1}

    no_optional_peer = desired(
        revision=2,
        parent_revision=1,
        peers=tuple(
            peer.model_copy(update={"candidates": (), "persistent_keepalive_seconds": None})
            for peer in desired().peers
        ),
    )
    asyncio.run(store.write(no_optional_peer, reference, "d" * 32))
    rendered = store.config_path("tmn-test-a", 2).read_text(encoding="utf-8")
    assert "Endpoint =" not in rendered
    assert "PersistentKeepalive =" not in rendered


def test_marker_temporary_is_cleaned_when_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tunnelminion.platforms.windows.official_backend as module

    secrets_store = MemorySecrets()
    runner = FakeRunner()
    store = materials(tmp_path, secrets_store, runner)
    reference = store.ensure_secret(desired()).secret_reference
    real_replace = module.os.replace
    calls = 0

    def fail_marker_replace(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected marker replace failure")
        real_replace(source, target)

    monkeypatch.setattr(module.os, "replace", fail_marker_replace)
    with pytest.raises(OSError, match="marker replace"):
        asyncio.run(store.write(desired(), reference, "e" * 32))
    assert not tuple(store.root.glob("*.tmp"))
