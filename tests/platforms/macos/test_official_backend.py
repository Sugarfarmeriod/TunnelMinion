"""macOS `wg-quick` 后端和 0600 配置材料测试。"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.network.factories import NETWORK_ID, NODE_A, desired, observation

from tunnelminion.network.contracts import (
    ApprovedRouteOverlap,
    NetworkAction,
    NetworkErrorCode,
    NetworkPlanStep,
    PlanStepKind,
    ProviderKind,
    canonical_sha256,
)
from tunnelminion.network.fakes import InMemoryNetworkProvider
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSProviderPaths,
    MacOSTunnelSnapshot,
)
from tunnelminion.platforms.macos.network_provider import MacOSBackendError
from tunnelminion.platforms.macos.official_backend import (
    OfficialMacOSManagedBackend,
    RestrictedMacOSConfigStore,
)
from tunnelminion.platforms.macos.system import CommandResult


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.get_calls = 0

    def get(self, name: str) -> str | None:
        self.get_calls += 1
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


def test_create_identity_does_not_read_secret_store(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    materials = RestrictedMacOSConfigStore(tmp_path / "configs", secrets)

    material = materials.create_identity(NETWORK_ID, NODE_A)

    assert secrets.get_calls == 0
    assert material.public_key.endswith("=")
    assert len(secrets.values) == 1


class FakeRunner:
    def __init__(self) -> None:
        self.returncode = 0
        self.stdout = ""
        self.queues: dict[tuple[str, ...], list[CommandResult]] = {}
        self.commands: list[tuple[str, ...]] = []
        self.bindings: list[tuple[str, str]] = []

    def bind_operation(self, plan_hash: str, creation_nonce: str) -> None:
        self.bindings.append((plan_hash, creation_nonce))

    async def run(
        self,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> CommandResult:
        assert timeout_seconds > 0
        self.commands.append(command)
        queue = self.queues.get(command)
        if queue:
            return queue.pop(0)
        return CommandResult(returncode=self.returncode, stdout=self.stdout, stderr="")


class FakeObserver:
    def __init__(self) -> None:
        self.snapshot = MacOSTunnelSnapshot(
            interface_name="utun9",
            interface_present=True,
            interface_up=True,
            service_present=True,
            service_running=True,
            public_key_hash=f"sha256:{'a' * 64}",
            stable_interface_id="utun9",
        )

    async def observe(self, interface_name: str) -> MacOSTunnelSnapshot:
        return self.snapshot.model_copy(update={"interface_name": interface_name})


def fixed(tmp_path: Path, runner: FakeRunner) -> FixedMacOSWireGuardCommands:
    return FixedMacOSWireGuardCommands(
        MacOSProviderPaths(
            wg=tmp_path / "wg",
            wg_quick=tmp_path / "wg-quick",
            ifconfig=tmp_path / "ifconfig",
            netstat=tmp_path / "netstat",
            config_root=tmp_path / "configs",
        ),
        runner,
        path_exists=lambda _path: True,
        effective_uid=lambda: 0,
        platform_name="darwin",
    )


def config(**updates: object):
    values: dict[str, object] = {
        "provider": ProviderKind.MACOS,
        "interface_name": "tmn-test-b",
    }
    values.update(updates)
    return desired(**values)


def store(tmp_path: Path, secrets: MemorySecrets) -> RestrictedMacOSConfigStore:
    return RestrictedMacOSConfigStore(tmp_path / "configs", secrets)


def plan(action: NetworkAction = NetworkAction.CREATE):
    wanted = config().model_copy(update={"listen_port": 18889})
    observed = observation(
        provider=ProviderKind.MACOS,
        interface_name="tmn-test-b",
    )
    return asyncio.run(
        InMemoryNetworkProvider(observed).plan(
            action=action,
            desired=wanted,
            observed=observed,
            ownership=None,
        )
    )


def test_material_store_secret_config_marker_and_cleanup(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    materials = store(tmp_path, secrets)
    wanted = config().model_copy(update={"listen_port": 18889})
    material = materials.ensure_secret(wanted)
    assert materials.ensure_secret(wanted) == material
    assert material.public_key.endswith("=")
    receipt = materials.write(wanted, material.secret_reference, "a" * 32)
    config_path = materials.config_path("tmn-test-b", 1)
    marker = materials.read_marker("tmn-test-b")
    assert receipt.startswith("sha256:")
    assert marker is not None and marker["runtime_interface"] is None
    rendered = config_path.read_text(encoding="utf-8")
    assert "PrivateKey =" in rendered
    assert "ListenPort = 18889" in rendered
    if os.name != "nt":
        materials.assert_restricted(config_path)
        materials.assert_restricted(materials.marker_path("tmn-test-b"))

    materials.record_runtime_interface(
        "tmn-test-b",
        creation_nonce="a" * 32,
        revision=1,
        runtime_interface="utun9",
    )
    assert materials.read_marker("tmn-test-b")["runtime_interface"] == "utun9"  # type: ignore[index]
    assert materials.delete_config("tmn-test-b", 1).startswith("sha256:")
    materials.delete_config("tmn-test-b", 1)
    materials.delete_secret(wanted, material.secret_reference)
    materials.delete_secret(wanted, material.secret_reference)
    assert secrets.values == {}


def test_material_store_rejects_unsafe_inputs_and_permissions(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    with pytest.raises(ValueError, match="绝对路径"):
        RestrictedMacOSConfigStore(Path("relative"), secrets)
    materials = store(tmp_path, secrets)
    with pytest.raises(ValueError):
        materials.config_path("utun4", 1)
    with pytest.raises(ValueError):
        materials.config_path("tmn-test-b", 0)
    with pytest.raises(ValueError):
        materials.marker_path("utun4")
    with pytest.raises(ValueError):
        materials.write(config(), "file:wrong", "a" * 32)
    with pytest.raises(MacOSBackendError):
        materials.write(config(), "keyring:missing", "a" * 32)

    materials.root.mkdir()
    loose = materials.root / "loose"
    loose.write_text("x", encoding="utf-8")
    os.chmod(loose, 0o644)
    with pytest.raises(PermissionError):
        materials.assert_restricted(loose)
    marker = materials.marker_path("tmn-test-b")
    marker.write_text("[]", encoding="utf-8")
    assert materials.read_marker("tmn-test-b") is None


def test_backend_observe_conflicts_and_unavailable(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    runner = FakeRunner()
    materials = store(tmp_path, secrets)
    backend = OfficialMacOSManagedBackend(fixed(tmp_path, runner), FakeObserver(), materials)
    assert backend.preflight().administrator
    assert backend.ensure_identity(NETWORK_ID, NODE_A).public_key.endswith("=")
    assert backend.ensure_secret(config()).secret_reference.startswith("keyring:")
    assert asyncio.run(backend.observe("utun4")).interface_name == "utun4"
    assert not asyncio.run(backend.observe("tmn-test-b")).interface_present
    runner.stdout = "utun4 utun9\n"
    assert asyncio.run(backend.runtime_interfaces("tmn-test-b")) == ("utun4", "utun9")

    reference = materials.ensure_secret(config()).secret_reference
    materials.write(config(), reference, "a" * 32)
    materials.record_runtime_interface(
        "tmn-test-b",
        creation_nonce="a" * 32,
        revision=1,
        runtime_interface="utun9",
    )
    managed = asyncio.run(backend.observe("tmn-test-b"))
    assert managed.stable_interface_id == "utun9"
    assert managed.creation_nonce == "a" * 32

    runner.stdout = "Destination Gateway Flags Netif\ndefault 192.0.2.1 UGSc en0\n"
    asyncio.run(backend.validate_no_conflicts(config()))
    runner.stdout = (
        "Destination Gateway Flags Netif Expire\n"
        "default 192.0.2.1 UGSc en0\n"
        "10.128/9 link#23 UCS utun1024\n"
        "1.2.3.4.5/24 link#23 UCS utun1024\n"
        "malformed row\n"
    )
    with pytest.raises(MacOSBackendError) as conflict:
        asyncio.run(backend.validate_no_conflicts(config()))
    assert conflict.value.code is NetworkErrorCode.ROUTE_NOT_ALLOWED
    overlap = ApprovedRouteOverlap(
        route="10.128.0.0/9",
        observation_fingerprint=canonical_sha256(
            {
                "route": "10.128.0.0/9",
                "interface_locator": "utun1024",
            }
        ),
    )
    asyncio.run(
        backend.validate_no_conflicts(
            config().model_copy(update={"allowed_route_overlaps": (overlap,)})
        )
    )
    with pytest.raises(MacOSBackendError):
        asyncio.run(
            backend.validate_no_conflicts(
                config().model_copy(
                    update={
                        "allowed_route_overlaps": (
                            overlap.model_copy(
                                update={"observation_fingerprint": "sha256:" + "f" * 64}
                            ),
                        )
                    }
                )
            )
        )
    runner.returncode = 1
    with pytest.raises(MacOSBackendError) as unavailable:
        asyncio.run(backend.validate_no_conflicts(config()))
    assert unavailable.value.code is NetworkErrorCode.PROVIDER_UNAVAILABLE


def test_backend_execute_and_rollback_fixed_steps(tmp_path: Path) -> None:
    secrets = MemorySecrets()
    runner = FakeRunner()
    commands = fixed(tmp_path, runner)
    materials = store(tmp_path, secrets)
    backend = OfficialMacOSManagedBackend(commands, FakeObserver(), materials)
    wanted = config()
    reference = materials.ensure_secret(wanted).secret_reference
    value = plan()
    interfaces = (str(commands.paths.wg), "show", "interfaces")
    runner.queues[interfaces] = [
        CommandResult(returncode=0, stdout="utun4\n", stderr=""),
        CommandResult(returncode=0, stdout="utun4 utun9\n", stderr=""),
    ]
    for step in value.steps:
        result = asyncio.run(
            backend.execute_step(
                value,
                step,
                secret_reference=reference,
                creation_nonce="a" * 32,
                idempotency_key=f"netop_{'a' * 64}",
            )
        )
        assert result.startswith("sha256:")

    for step in reversed(value.steps):
        result = asyncio.run(
            backend.rollback_step(
                value,
                step,
                secret_reference=reference,
                creation_nonce="a" * 32,
                idempotency_key=f"netop_{'a' * 64}",
            )
        )
        assert result.startswith("sha256:")

    assert runner.bindings == [(value.plan_hash, "a" * 32)] * 2

    for kind in (
        PlanStepKind.STOP_INTERFACE,
        PlanStepKind.REMOVE_INTERFACE,
        PlanStepKind.DELETE_CONFIG,
        PlanStepKind.DELETE_SECRET,
    ):
        step = NetworkPlanStep(
            index=0,
            kind=kind,
            target="tmn-test-b",
            expected_effect="test",
            rollback_kind=None,
        )
        assert asyncio.run(
            backend.execute_step(
                value,
                step,
                secret_reference=reference,
                creation_nonce="a" * 32,
                idempotency_key=f"netop_{'a' * 64}",
            )
        ).startswith("sha256:")


def test_backend_failures_parent_restore_delete_secret_and_interface_ambiguity(
    tmp_path: Path,
) -> None:
    secrets = MemorySecrets()
    runner = FakeRunner()
    commands = fixed(tmp_path, runner)
    materials = store(tmp_path, secrets)
    backend = OfficialMacOSManagedBackend(commands, FakeObserver(), materials)
    wanted = config(revision=2, parent_revision=1)
    reference = materials.ensure_secret(wanted).secret_reference
    materials.write(wanted, reference, "b" * 32)
    value = plan().model_copy(update={"desired": wanted})
    stop = NetworkPlanStep(
        index=0,
        kind=PlanStepKind.STOP_INTERFACE,
        target="tmn-test-b",
        expected_effect="test",
        rollback_kind=PlanStepKind.CREATE_INTERFACE,
    )
    assert asyncio.run(
        backend.rollback_step(
            value,
            stop,
            secret_reference=reference,
            creation_nonce="b" * 32,
            idempotency_key=f"netop_{'b' * 64}",
        )
    ).startswith("sha256:")

    delete_secret = stop.model_copy(update={"kind": PlanStepKind.DELETE_SECRET})
    with pytest.raises(MacOSBackendError) as deleted:
        asyncio.run(
            backend.rollback_step(
                value,
                delete_secret,
                secret_reference=reference,
                creation_nonce="b" * 32,
                idempotency_key=f"netop_{'b' * 64}",
            )
        )
    assert deleted.value.code is NetworkErrorCode.ROLLBACK_FAILED

    create = stop.model_copy(update={"kind": PlanStepKind.CREATE_INTERFACE})
    runner.queues[(str(commands.paths.wg), "show", "interfaces")] = [
        CommandResult(returncode=0, stdout="utun4\n", stderr=""),
        CommandResult(returncode=0, stdout="utun4\n", stderr=""),
    ]
    with pytest.raises(MacOSBackendError, match="唯一"):
        asyncio.run(
            backend.execute_step(
                value,
                create,
                secret_reference=reference,
                creation_nonce="b" * 32,
                idempotency_key=f"netop_{'b' * 64}",
            )
        )
    runner.returncode = 1
    with pytest.raises(MacOSBackendError):
        asyncio.run(
            backend.execute_step(
                value,
                stop,
                secret_reference=reference,
                creation_nonce="b" * 32,
                idempotency_key=f"netop_{'b' * 64}",
            )
        )
    with pytest.raises(MacOSBackendError, match="接口清单"):
        asyncio.run(backend._interfaces())  # pyright: ignore[reportPrivateUsage]


def test_material_optional_peer_fields_replace_cleanup_and_restricted_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = MemorySecrets()
    materials = store(tmp_path, secrets)
    wanted = config()
    reference = materials.ensure_secret(wanted).secret_reference
    without_optional = wanted.model_copy(
        update={
            "revision": 2,
            "peers": tuple(
                peer.model_copy(update={"candidates": (), "persistent_keepalive_seconds": None})
                for peer in wanted.peers
            ),
        }
    )
    materials.write(without_optional, reference, "c" * 32)

    def restricted_stat(_path: Path) -> SimpleNamespace:
        return SimpleNamespace(st_mode=0o100600)

    monkeypatch.setattr(Path, "stat", restricted_stat)
    materials.assert_restricted(materials.config_path("tmn-test-b", 2))
    monkeypatch.undo()

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        materials.write(
            without_optional.model_copy(update={"revision": 3}),
            reference,
            "c" * 32,
        )
    assert not tuple(materials.root.glob("*.tmp"))
    with pytest.raises(OSError, match="replace failed"):
        materials.record_runtime_interface(
            "tmn-test-b",
            creation_nonce="c" * 32,
            revision=2,
            runtime_interface="utun11",
        )
    assert not tuple(materials.root.glob("*.tmp"))
