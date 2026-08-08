"""真实组件命令、健康探针和脱敏控制视图测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from uuid import UUID

import httpx
import pytest

from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfiguration,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig
from tunnelminion.runtime import control
from tunnelminion.runtime.control import (
    RuntimeCommandFactory,
    RuntimeComponentHealthProbe,
    application_version,
    profile_summary,
    runtime_control_view,
)
from tunnelminion.runtime.lifecycle import (
    ComponentLaunchError,
    ComponentRuntimeState,
    ComponentRuntimeStatus,
    LifecycleReport,
    OverallRuntimeState,
    ReadinessResult,
)
from tunnelminion.runtime.profile import (
    RuntimeComponent,
    RuntimePaths,
    RuntimeProfile,
)


def _profile(tmp_path: Path, *components: RuntimeComponent) -> tuple[RuntimeProfile, RuntimePaths]:
    data_dir = (tmp_path / "data").resolve()
    profile = RuntimeProfile(
        data_dir=data_dir,
        enabled_components=frozenset(components or (RuntimeComponent.LOCAL,)),
        local_port=8123,
    )
    return profile, RuntimePaths(
        profile_file=tmp_path / "profile.json",
        data_dir=data_dir,
        log_dir=data_dir / "runtime" / "logs",
        state_dir=data_dir / "runtime" / "state",
    )


class FakeListenerProbe:
    def __init__(self, result: ReadinessResult) -> None:
        self.result = result
        self.calls: list[tuple[RuntimeComponent, int, float]] = []

    def readiness(
        self,
        component: RuntimeComponent,
        pid: int,
        timeout_seconds: float,
    ) -> ReadinessResult:
        self.calls.append((component, pid, timeout_seconds))
        return self.result


def test_local_health_accepts_non_server_error_and_rejects_failure(tmp_path: Path) -> None:
    profile, _paths = _profile(tmp_path)
    statuses = iter((200, 503))

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://127.0.0.1:8123/"
        return httpx.Response(next(statuses), request=request, text="untrusted-secret-body")

    probe = RuntimeComponentHealthProbe(
        profile, profile.data_dir, transport=httpx.MockTransport(handler)
    )
    assert probe.healthy(RuntimeComponent.LOCAL, 1)
    assert not probe.healthy(RuntimeComponent.LOCAL, 1)


def test_health_rejects_network_error_and_never_requires_gateway_token(tmp_path: Path) -> None:
    profile, _paths = _profile(tmp_path, RuntimeComponent.GATEWAY)
    FileGatewayConfigurationRepository(profile.data_dir / "gateway.json").save(
        GatewayConfiguration(bind=GatewayBindConfig(host="10.77.0.1", port=8787))
    )

    listener = FakeListenerProbe(ReadinessResult(True))
    healthy = RuntimeComponentHealthProbe(
        profile,
        profile.data_dir,
        transport=httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(AssertionError(request.url))
        ),
        listener_probe=listener,
    )
    assert healthy.healthy(RuntimeComponent.GATEWAY, 2)
    assert listener.calls == [(RuntimeComponent.GATEWAY, 2, 0.5)]

    wrong_listener = FakeListenerProbe(ReadinessResult(False, "ownership_conflict"))
    wrong_status = RuntimeComponentHealthProbe(
        profile,
        profile.data_dir,
        listener_probe=wrong_listener,
    )
    assert not wrong_status.healthy(RuntimeComponent.GATEWAY, 2)

    unavailable_listener = FakeListenerProbe(
        ReadinessResult(False, "listener_ownership_unverified")
    )
    unavailable = RuntimeComponentHealthProbe(
        profile,
        profile.data_dir,
        listener_probe=unavailable_listener,
    )
    assert not unavailable.healthy(RuntimeComponent.GATEWAY, 2)


def test_gateway_health_requires_valid_nonsecret_configuration(tmp_path: Path) -> None:
    profile, _paths = _profile(tmp_path, RuntimeComponent.GATEWAY)
    probe = RuntimeComponentHealthProbe(
        profile,
        profile.data_dir,
        transport=httpx.MockTransport(lambda request: httpx.Response(401, request=request)),
    )
    assert not probe.healthy(RuntimeComponent.GATEWAY, 1)
    profile.data_dir.mkdir()
    (profile.data_dir / "gateway.json").write_text("{}", encoding="utf-8")
    assert not probe.healthy(RuntimeComponent.GATEWAY, 1)


def test_runtime_command_factory_contains_only_identity_and_local_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, paths = _profile(tmp_path)
    command = RuntimeCommandFactory(profile, paths)(RuntimeComponent.LOCAL, UUID(int=1))
    serialized = " ".join(command)
    assert "runtime-child" in command
    assert "--runtime-component=local" in command
    assert "--runtime-instance-id=00000000-0000-0000-0000-000000000001" in command
    assert str(paths.data_dir) in command
    assert "token" not in serialized
    assert "refresh" not in serialized

    monkeypatch.setattr(control.sys, "frozen", True, raising=False)
    frozen = RuntimeCommandFactory(profile, paths)(RuntimeComponent.LOCAL, UUID(int=2))
    assert frozen[0] == sys.executable
    assert frozen[1] == "runtime-child"


def test_gateway_command_factory_fails_before_spawn_when_config_is_missing_or_invalid(
    tmp_path: Path,
) -> None:
    profile, paths = _profile(tmp_path, RuntimeComponent.GATEWAY)
    factory = RuntimeCommandFactory(profile, paths)
    with pytest.raises(ComponentLaunchError) as missing:
        factory(RuntimeComponent.GATEWAY, UUID(int=1))
    assert missing.value.code == "gateway_unconfigured"

    profile.data_dir.mkdir()
    (profile.data_dir / "gateway.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ComponentLaunchError) as invalid:
        factory(RuntimeComponent.GATEWAY, UUID(int=1))
    assert invalid.value.code == "gateway_config_invalid"

    FileGatewayConfigurationRepository(profile.data_dir / "gateway.json").save(
        GatewayConfiguration(bind=GatewayBindConfig(host="10.77.0.1", port=8787))
    )
    command = factory(RuntimeComponent.GATEWAY, UUID(int=1))
    assert "--runtime-component=gateway" in command


def test_control_view_and_profile_summary_never_echo_model_endpoint(tmp_path: Path) -> None:
    profile, paths = _profile(tmp_path)
    endpoint = "http://127.0.0.1:1/private-endpoint-value"
    FileModelConfigurationRepository(paths.data_dir / "model.json").save(
        OpenAICompatibleConfig(endpoint=endpoint, model="fixture")
    )
    report = LifecycleReport(
        state=OverallRuntimeState.STOPPED,
        components=(
            ComponentRuntimeStatus(
                component=RuntimeComponent.LOCAL,
                state=ComponentRuntimeState.STOPPED,
            ),
        ),
        exit_code=0,
    )
    view = runtime_control_view(report, profile, paths)
    summary = profile_summary(profile)
    serialized = view.model_dump_json()
    assert view.model.status == "unavailable"
    assert str(profile.data_dir) not in summary
    assert json.loads(summary)["data_dir_sha256"]
    assert endpoint not in serialized
    assert "private-endpoint-value" not in serialized


def test_application_version_has_source_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(distribution: str) -> str:
        del distribution
        raise control.PackageNotFoundError

    monkeypatch.setattr(control, "version", missing)
    assert application_version() == "0.1.0"


def test_runtime_preflight_factory_distinguishes_source_and_frozen_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_program = tmp_path / "src"
    source_program.mkdir()
    monkeypatch.setattr(control, "current_program_dir", lambda: source_program)
    source = control.build_runtime_preflight()
    assert source._manifest_path is None  # pyright: ignore[reportPrivateUsage]

    manifest = source_program / "runtime-package-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    packaged = control.build_runtime_preflight()
    assert packaged._manifest_path == manifest  # pyright: ignore[reportPrivateUsage]

    manifest.unlink()
    monkeypatch.setattr(control.sys, "frozen", True, raising=False)
    frozen = control.build_runtime_preflight()
    assert frozen._manifest_path == manifest  # pyright: ignore[reportPrivateUsage]
