"""按固定参数查询、启动、重启和停下已有容器。"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from tunnelminion.platforms.windows.system import CommandRunner
from tunnelminion.repair.compose_order import parse_depends_on
from tunnelminion.repair.contracts import ContainerSnapshot, RepairCommand
from tunnelminion.repair.processes import redact_log_text

_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")


def _validate_ids(container_ids: tuple[str, ...]) -> None:
    if not container_ids or any(_CONTAINER_ID.fullmatch(value) is None for value in container_ids):
        raise ValueError("容器编号无效")


class DockerContainerRuntime:
    """只操作现有容器，不创建或更新部署。"""

    def __init__(
        self,
        runner: CommandRunner,
        docker_path: str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._runner = runner
        self._docker_path = docker_path
        self._clock = clock or (lambda: datetime.now(UTC))

    async def list_containers(
        self, *, compose_project: str | None = None, container_name: str | None = None
    ) -> tuple[ContainerSnapshot, ...] | None:
        if (compose_project is None) == (container_name is None):
            raise ValueError("必须且只能指定项目或容器名")
        scope = compose_project if compose_project is not None else container_name
        if _SCOPE.fullmatch(scope or "") is None:
            raise ValueError("项目或容器名无效")
        try:
            result = await self._runner.run(
                (self._docker_path, "ps", "-a", "--no-trunc", "--format", "{{json .}}"), 15
            )
            if result.returncode != 0:
                return None
            ids: list[str] = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                raw_labels: str = item.get("Labels") or ""
                labels = dict(
                    label.split("=", 1) for label in raw_labels.split(",") if "=" in label
                )
                if (
                    labels.get("com.docker.compose.project") == compose_project
                    if compose_project is not None
                    else item["Names"] == container_name
                ):
                    ids.append(item["ID"])
            if not ids:
                return ()
            _validate_ids(tuple(ids))
            inspected = await self._runner.run((self._docker_path, "inspect", *ids), 15)
            if inspected.returncode != 0:
                return None
            decoded: object = json.loads(inspected.stdout)
            if not isinstance(decoded, list):
                return None
            snapshots: list[ContainerSnapshot] = []
            for item in cast(list[Any], decoded):
                state = item["State"]
                port_bindings = cast(
                    dict[str, list[dict[str, str]] | None],
                    item["HostConfig"].get("PortBindings") or {},
                )
                config_labels = cast(dict[str, str], item["Config"].get("Labels") or {})
                status = state["Status"]
                if status == "exited":
                    status = f"{status} ({state['ExitCode']})"
                health = cast(dict[str, Any], state.get("Health") or {}).get("Status") or None
                snapshots.append(
                    ContainerSnapshot(
                        container_id=item["Id"],
                        name=item["Name"].lstrip("/"),
                        image=item["Config"]["Image"],
                        running=state["Running"],
                        status=status,
                        published_ports=tuple(
                            sorted(
                                {
                                    int(binding["HostPort"])
                                    for bindings in port_bindings.values()
                                    for binding in bindings or []
                                    if binding["HostPort"]
                                }
                            )
                        ),
                        compose_project=config_labels.get("com.docker.compose.project"),
                        compose_service=config_labels.get("com.docker.compose.service") or None,
                        depends_on=parse_depends_on(
                            config_labels.get("com.docker.compose.depends_on")
                        ),
                        health=health,
                    )
                )
            return tuple(sorted(snapshots, key=lambda value: value.name))
        except (
            OSError,
            subprocess.TimeoutExpired,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
        ):
            return None

    async def start(self, container_ids: tuple[str, ...]) -> RepairCommand:
        return await self._execute("start", container_ids)

    async def restart(self, container_ids: tuple[str, ...]) -> RepairCommand:
        return await self._execute("restart", container_ids)

    async def stop(self, container_ids: tuple[str, ...]) -> RepairCommand:
        return await self._execute("stop", container_ids)

    async def _execute(self, action: str, container_ids: tuple[str, ...]) -> RepairCommand:
        _validate_ids(container_ids)
        argv = (self._docker_path, action, *container_ids)
        started_at = self._clock()
        exit_code: int | None = None
        try:
            result = await self._runner.run(argv, 120)
            exit_code = result.returncode
            output = result.stdout + result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = str(exc)
        return RepairCommand(
            argv=argv,
            exit_code=exit_code,
            output_excerpt=redact_log_text(output)[-2000:],
            started_at=started_at,
            finished_at=self._clock(),
        )

    async def logs_tail(self, container_id: str, *, lines: int) -> str:
        _validate_ids((container_id,))
        if lines <= 0:
            return ""
        try:
            result = await self._runner.run(
                (self._docker_path, "logs", "--tail", str(lines), container_id), 15
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if result.returncode != 0:
            return ""
        return "\n".join(redact_log_text(result.stdout + result.stderr).splitlines()[-lines:])[
            -4000:
        ]
