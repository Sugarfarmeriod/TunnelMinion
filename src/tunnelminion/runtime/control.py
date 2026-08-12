"""真实组件命令生成、健康探测与脱敏 runtime 控制输出。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict

from tunnelminion.gateway.configuration import FileGatewayConfigurationRepository
from tunnelminion.runtime.health import ModelHealthResult, probe_external_model
from tunnelminion.runtime.lifecycle import (
    ComponentLaunchError,
    ComponentReadinessProbe,
    LifecycleReport,
    ManualLifecycleManager,
    ReadinessResult,
)
from tunnelminion.runtime.listener import GatewayListenerOwnershipProbe
from tunnelminion.runtime.preflight import RuntimePreflight
from tunnelminion.runtime.process import DetachedProcessAdapter
from tunnelminion.runtime.profile import (
    RuntimeComponent,
    RuntimePaths,
    RuntimeProfile,
    current_program_dir,
)

_PACKAGE_MANIFEST_FILE = "runtime-package-manifest.json"
_PROFILE_SCHEMA_FILE = "runtime-profile-v1.schema.json"


class RuntimeComponentHealthProbe:
    """不读取秘密或响应正文的本地应用/Gateway HTTP 探针。"""

    def __init__(
        self,
        profile: RuntimeProfile,
        data_dir: Path,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 0.5,
        listener_probe: ComponentReadinessProbe | None = None,
    ) -> None:
        self._profile = profile
        self._data_dir = data_dir
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._listener_probe = listener_probe or GatewayListenerOwnershipProbe(data_dir)

    def healthy(self, component: RuntimeComponent, pid: int) -> bool:
        return self.readiness(component, pid, self._timeout_seconds).ready

    def readiness(
        self,
        component: RuntimeComponent,
        pid: int,
        timeout_seconds: float,
    ) -> ReadinessResult:
        if component is RuntimeComponent.GATEWAY:
            return self._listener_probe.readiness(component, pid, timeout_seconds)
        target = self._target(component)
        url, expected_status = target
        try:
            with httpx.Client(
                transport=self._transport,
                trust_env=False,
                follow_redirects=False,
                timeout=max(0.01, timeout_seconds),
            ) as client:
                response = client.get(url)
        except httpx.HTTPError:
            return ReadinessResult(False, "startup_unstable")
        ready = (
            response.status_code == expected_status
            if expected_status is not None
            else response.status_code < 500
        )
        return ReadinessResult(ready, None if ready else "startup_unstable")

    def _target(self, component: RuntimeComponent) -> tuple[str, int | None]:
        del component
        return f"http://127.0.0.1:{self._profile.local_port}/", None


class RuntimeCommandFactory:
    """只生成非秘密子进程参数，并在 Gateway 未配置时提前分域失败。"""

    def __init__(self, profile: RuntimeProfile, paths: RuntimePaths) -> None:
        self._profile = profile
        self._paths = paths

    def __call__(self, component: RuntimeComponent, instance_id: UUID) -> tuple[str, ...]:
        if component is RuntimeComponent.GATEWAY:
            try:
                gateway = FileGatewayConfigurationRepository(
                    self._paths.data_dir / "gateway.json"
                ).load()
            except (OSError, ValueError) as exc:
                raise ComponentLaunchError("gateway_config_invalid") from exc
            if gateway is None:
                raise ComponentLaunchError("gateway_unconfigured")
        base = (
            (sys.executable,)
            if getattr(sys, "frozen", False)
            else (sys.executable, "-m", "tunnelminion")
        )
        return (
            *base,
            "runtime-child",
            f"--runtime-component={component.value}",
            f"--runtime-instance-id={instance_id}",
            "--data-dir",
            str(self._paths.data_dir),
            "--local-port",
            str(self._profile.local_port),
            "--runtime-log-file",
            str(self._paths.log_dir / f"{component.value}.log"),
        )


class RuntimeControlView(BaseModel):
    """CLI 使用的脱敏运行状态。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime: LifecycleReport
    model: ModelHealthResult
    logs: dict[str, str]


def application_version() -> str:
    """返回安装包版本；源码测试环境保持稳定回退值。"""
    try:
        return version("tunnelminion")
    except PackageNotFoundError:
        return "0.1.0"


def build_lifecycle_manager(
    profile: RuntimeProfile,
    paths: RuntimePaths,
) -> ManualLifecycleManager:
    """组装真实 detached 进程、命令与零秘密健康探针。"""
    return ManualLifecycleManager(
        profile,
        paths,
        application_version(),
        DetachedProcessAdapter(),
        RuntimeCommandFactory(profile, paths),
        health=RuntimeComponentHealthProbe(
            profile,
            paths.data_dir,
            listener_probe=GatewayListenerOwnershipProbe(paths.data_dir),
        ),
    )


def build_runtime_preflight() -> RuntimePreflight:
    """按冻结包或源码运行方式组装同一套启动前检查。"""
    program = current_program_dir()
    manifest = program / _PACKAGE_MANIFEST_FILE
    if getattr(sys, "frozen", False) or manifest.is_file():
        schema_dir = program / "schemas"
        return RuntimePreflight(
            program,
            manifest,
            schema_dir,
            schema_dir / _PROFILE_SCHEMA_FILE,
        )
    source_root = Path(__file__).resolve().parents[3]
    return RuntimePreflight(
        program,
        None,
        None,
        source_root / "schemas" / _PROFILE_SCHEMA_FILE,
    )


def runtime_control_view(
    report: LifecycleReport,
    profile: RuntimeProfile,
    paths: RuntimePaths,
) -> RuntimeControlView:
    """合并生命周期、外部模型与受限日志位置。"""
    model = asyncio.run(
        probe_external_model(
            paths.data_dir,
            profile.budgets.model_health_timeout_seconds,
        )
    )
    return RuntimeControlView(
        runtime=report,
        model=model,
        logs={
            component.value: str(paths.log_dir / f"{component.value}.log")
            for component in sorted(profile.enabled_components)
        },
    )


def profile_summary(profile: RuntimeProfile) -> str:
    """输出不含完整数据路径的 profile 摘要 JSON。"""
    return json.dumps(
        {
            "schema_version": profile.schema_version,
            "enabled_components": sorted(profile.enabled_components),
            "local_port": profile.local_port,
            "data_dir_sha256": hashlib.sha256(str(profile.data_dir).encode()).hexdigest(),
        },
        ensure_ascii=False,
    )
