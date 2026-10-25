"""固定 Docker 命令、输入校验和日志隐私测试。"""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from tunnelminion.platforms.windows.system import CommandResult
from tunnelminion.repair.contracts import ContainerRuntime
from tunnelminion.repair.docker import DockerContainerRuntime

NOW = datetime(2026, 10, 25, tzinfo=UTC)
FIRST = "a" * 64
SECOND = "b" * 64


class FakeRunner:
    def __init__(self, *results: CommandResult | Exception) -> None:
        self.results = list(results)
        self.calls: list[tuple[tuple[str, ...], float]] = []

    async def run(self, command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
        assert command[0] == "docker-fixture"
        assert command[1] in {"ps", "inspect", "start", "restart", "logs"}
        self.calls.append((command, timeout_seconds))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def result(stdout: str = "", *, stderr: str = "", code: int = 0) -> CommandResult:
    return CommandResult(returncode=code, stdout=stdout, stderr=stderr)


def ps_row(container_id: str, name: str, project: str | None = "photos") -> str:
    return json.dumps(
        {
            "ID": container_id,
            "Names": name,
            "Labels": f"other=value,com.docker.compose.project={project},bare"
            if project is not None
            else None,
        }
    )


def inspect_row(
    container_id: str, name: str, *, running: bool = False, project: str | None = "photos"
) -> dict[str, object]:
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "Config": {
            "Image": "fixture:latest",
            "Labels": {"com.docker.compose.project": project} if project else None,
        },
        "State": {"Running": running, "Status": "running" if running else "exited", "ExitCode": 1},
        "HostConfig": {
            "PortBindings": {
                "80/tcp": [{"HostPort": "8080"}, {"HostPort": "8080"}, {"HostPort": ""}],
                "443/tcp": [{"HostPort": "8443"}],
                "53/udp": None,
            }
        },
    }


def test_project_is_exact_and_stopped_ports_come_from_bindings() -> None:
    runner = FakeRunner(
        result(
            "\n".join(
                (
                    "",
                    ps_row(SECOND, "web"),
                    ps_row(FIRST, "database"),
                    ps_row("c" * 64, "other", "photos-extra"),
                    ps_row("d" * 64, "bare", None),
                )
            )
        ),
        result(
            json.dumps([inspect_row(SECOND, "web"), inspect_row(FIRST, "database", running=True)])
        ),
    )
    runtime: ContainerRuntime = DockerContainerRuntime(runner, "docker-fixture")
    snapshots = asyncio.run(runtime.list_containers(compose_project="photos", container_name=None))
    assert snapshots is not None
    assert [item.name for item in snapshots] == ["database", "web"]
    assert snapshots[0].status == "running" and snapshots[0].running
    assert snapshots[1].status == "exited (1)" and not snapshots[1].running
    assert snapshots[1].published_ports == (8080, 8443)
    assert snapshots[1].image == "fixture:latest"
    assert snapshots[1].compose_project == "photos"
    assert runner.calls == [
        (("docker-fixture", "ps", "-a", "--no-trunc", "--format", "{{json .}}"), 15),
        (("docker-fixture", "inspect", SECOND, FIRST), 15),
    ]


def test_name_is_exact_and_null_bindings_and_labels_are_empty() -> None:
    row = inspect_row(FIRST, "web", project=None)
    row["HostConfig"] = {"PortBindings": None}
    runner = FakeRunner(
        result(ps_row(SECOND, "web-extra") + "\n" + ps_row(FIRST, "web", None)),
        result(json.dumps([row])),
    )
    snapshots = asyncio.run(
        DockerContainerRuntime(runner, "docker-fixture").list_containers(container_name="web")
    )
    assert snapshots is not None and len(snapshots) == 1
    assert snapshots[0].published_ports == () and snapshots[0].compose_project is None
    assert runner.calls[1][0] == ("docker-fixture", "inspect", FIRST)


@pytest.mark.parametrize("scope", (None, "", "bad name", "-web", "a;b", "a\n", "a" * 129))
@pytest.mark.parametrize("by_project", (True, False))
def test_bad_scope_is_rejected_before_running(scope: str | None, by_project: bool) -> None:
    runner = FakeRunner()
    runtime = DockerContainerRuntime(runner, "docker-fixture")
    with pytest.raises(ValueError):
        asyncio.run(
            runtime.list_containers(
                compose_project=scope if by_project else None,
                container_name=None if by_project else scope,
            )
        )
    assert not runner.calls


def test_two_scopes_are_rejected_and_missing_container_is_empty() -> None:
    runner = FakeRunner(result(ps_row(FIRST, "web-extra")))
    runtime = DockerContainerRuntime(runner, "docker-fixture")
    with pytest.raises(ValueError):
        asyncio.run(runtime.list_containers(compose_project="photos", container_name="web"))
    assert not runner.calls
    assert asyncio.run(runtime.list_containers(container_name="web")) == ()
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    "results",
    (
        (result(code=1),),
        (OSError("unavailable"),),
        (subprocess.TimeoutExpired("ps", 15),),
        (result("not-json"),),
        (result("null"),),
        (result("{}"),),
        (result(ps_row("--bad", "web")),),
        (result(ps_row(FIRST, "web")), result(code=1)),
        (result(ps_row(FIRST, "web")), OSError("inspect unavailable")),
        (result(ps_row(FIRST, "web")), result("{}")),
        (result(ps_row(FIRST, "web")), result("[null]")),
        (result(ps_row(FIRST, "web")), result('[{"State": {}}]')),
    ),
)
def test_docker_unavailable_or_invalid_reply_returns_none(
    results: tuple[CommandResult | Exception, ...],
) -> None:
    runtime = DockerContainerRuntime(FakeRunner(*results), "docker-fixture")
    assert asyncio.run(runtime.list_containers(container_name="web")) is None


def test_start_restart_group_ids_and_record_times_and_redacted_tail() -> None:
    times = iter((NOW, NOW + timedelta(seconds=2), NOW, NOW))
    runner = FakeRunner(
        result(
            "x" * 2100 + "\nAuthorization: fixture-auth\n", stderr="password=fixture-pass", code=1
        ),
        result("started"),
    )
    runtime = DockerContainerRuntime(runner, "docker-fixture", clock=lambda: next(times))
    restarted = asyncio.run(runtime.restart((FIRST, SECOND)))
    assert restarted.argv == ("docker-fixture", "restart", FIRST, SECOND)
    assert restarted.exit_code == 1
    assert restarted.started_at == NOW
    assert restarted.finished_at == NOW + timedelta(seconds=2)
    assert len(restarted.output_excerpt) == 2000
    assert "fixture-auth" not in restarted.output_excerpt
    assert "fixture-pass" not in restarted.output_excerpt
    started = asyncio.run(runtime.start((FIRST, SECOND)))
    assert started.output_excerpt == "started"
    assert runner.calls == [(restarted.argv, 120), (started.argv, 120)]


@pytest.mark.parametrize("ids", ((), ("A" * 12,), ("a" * 11,), ("a" * 65,), (FIRST, "-bad")))
@pytest.mark.parametrize("action", ("start", "restart"))
def test_invalid_ids_never_reach_commands(ids: tuple[str, ...], action: str) -> None:
    runner = FakeRunner()
    runtime = DockerContainerRuntime(runner, "docker-fixture")
    with pytest.raises(ValueError):
        asyncio.run(getattr(runtime, action)(ids))
    with pytest.raises(ValueError):
        asyncio.run(runtime.logs_tail("bad\n", lines=2))
    assert not runner.calls


@pytest.mark.parametrize(
    "error", (OSError("token=fixture-value"), subprocess.TimeoutExpired("start", 120))
)
def test_command_failure_is_recorded(error: Exception) -> None:
    command = asyncio.run(
        DockerContainerRuntime(FakeRunner(error), "docker-fixture").start((FIRST,))
    )
    assert command.exit_code is None
    assert command.started_at.tzinfo is UTC and command.finished_at >= command.started_at
    assert "fixture-value" not in command.output_excerpt


def test_logs_merge_streams_redact_then_bound_lines_and_characters() -> None:
    runner = FakeRunner(
        result("old\ntoken=fixture-token\n", stderr="Bearer fixture-bearer\nlast"),
        result("x" * 5000),
        result(code=1),
        OSError("unavailable"),
        subprocess.TimeoutExpired("logs", 15),
    )
    runtime = DockerContainerRuntime(runner, "docker-fixture")
    assert asyncio.run(runtime.logs_tail(FIRST, lines=3)) == (
        "token=[REDACTED]\nBearer [REDACTED]\nlast"
    )
    assert asyncio.run(runtime.logs_tail(FIRST, lines=1)) == "x" * 4000
    for _ in range(3):
        assert asyncio.run(runtime.logs_tail(FIRST, lines=1)) == ""
    assert asyncio.run(runtime.logs_tail(FIRST, lines=0)) == ""
    assert len(runner.calls) == 5
    assert runner.calls[0][0] == ("docker-fixture", "logs", "--tail", "3", FIRST)
