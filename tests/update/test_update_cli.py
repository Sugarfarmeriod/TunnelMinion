"""`tunnelminion update`、换包进程入口和 `runtime start` 转交的测试。"""

# pyright: reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from tests.update.conftest import build_archive, build_package
from tests.update.test_update_apply import FakeControl

from tunnelminion import cli
from tunnelminion.runtime.install import RuntimePackageInstaller
from tunnelminion.runtime.profile import FileRuntimeProfileRepository, RuntimeProfile
from tunnelminion.update import cli as update_cli
from tunnelminion.update.apply import NO_REDIRECT_ENV, UpdateBusy, load_update_record
from tunnelminion.update.redirect import forward_to_current_version
from tunnelminion.update.release import (
    Availability,
    ReleaseAsset,
    ReleaseFeedError,
    ReleaseInfo,
)

OLD_REVISION = "1" * 40
NEW_REVISION = "2" * 40


class FakeFeed:
    def __init__(self, release: ReleaseInfo) -> None:
        self.release = release
        self.availability = Availability.UPDATE_AVAILABLE
        self.error: ReleaseFeedError | None = None

    @property
    def allows_loopback_http(self) -> bool:
        return True

    def latest(self, target: str) -> ReleaseInfo:
        if self.error is not None:
            raise self.error
        return self.release

    def compare(self, current_revision: str, release_revision: str) -> Availability:
        return self.availability


class Env:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp_path = tmp_path
        self.data_dir = (tmp_path / "data").resolve()
        self.profile_path = tmp_path / "profile.json"
        self.program = build_package(tmp_path / "running", "pkg-old", b"old", revision=OLD_REVISION)
        FileRuntimeProfileRepository(self.profile_path, self.program).save(
            RuntimeProfile(data_dir=self.data_dir)
        )
        new_package = build_package(tmp_path / "new", "pkg-new", b"new", revision=NEW_REVISION)
        self.body = build_archive(new_package, tmp_path / "served" / "tm.tar.gz").read_bytes()
        self.feed = FakeFeed(
            ReleaseInfo(
                tag="build-2",
                source_revision=NEW_REVISION,
                asset=ReleaseAsset(
                    name="tm.tar.gz",
                    url="http://127.0.0.1:9/tm.tar.gz",
                    size=len(self.body),
                    sha256=hashlib.sha256(self.body).hexdigest(),
                ),
            )
        )
        self.install_root = tmp_path / "install"
        self.control = FakeControl()
        self.answers: list[str] = []
        monkeypatch.setattr(update_cli, "runtime_target", lambda: "windows-amd64")
        monkeypatch.setattr(update_cli, "_over_ssh_on_windows", lambda: False)
        monkeypatch.setattr(update_cli, "current_program_dir", lambda: self.program)
        real_client = httpx.Client

        def client(**kwargs: object) -> httpx.Client:
            kwargs["transport"] = httpx.MockTransport(
                lambda request: httpx.Response(200, content=self.body)
            )
            return real_client(**kwargs)  # pyright: ignore[reportArgumentType]

        monkeypatch.setattr("tunnelminion.update.package.httpx.Client", client)

    def run(self, *extra: str, **overrides: object) -> int:
        options: dict[str, object] = {
            "feed": self.feed,
            "control": self.control,
            "confirm": lambda prompt: self.answers.pop(0) if self.answers else "",
            "frozen": True,
            "program_dir": self.program,
        }
        options.update(overrides)
        return update_cli.update_command(
            [
                "--profile",
                str(self.profile_path),
                "--install-root",
                str(self.install_root),
                *extra,
            ],
            **options,  # pyright: ignore[reportArgumentType]
        )

    def installer(self) -> RuntimePackageInstaller:
        return RuntimePackageInstaller(self.install_root, self.data_dir)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(tmp_path, monkeypatch)


def test_check_only_prints_versions(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    assert env.run("--check") == 0
    out = capsys.readouterr().out
    assert "提交 1111111" in out and "build-2" in out and "有新版本" in out
    assert not env.install_root.exists()

    env.feed.availability = Availability.UNKNOWN
    assert env.run("--check") == 0
    assert "无法确认" in capsys.readouterr().out

    env.feed.availability = Availability.DIVERGED
    assert env.run("--check") == 0
    assert "不在发布线上" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("availability", "text"),
    [
        (Availability.UP_TO_DATE, "已是最新版本"),
        (Availability.UNRELEASED_BUILD, "比最新发布版还新"),
    ],
)
def test_nothing_to_update(
    env: Env, capsys: pytest.CaptureFixture[str], availability: Availability, text: str
) -> None:
    env.feed.availability = availability
    assert env.run() == 0
    assert text in capsys.readouterr().out


def test_update_after_confirmation(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.answers.append("y")
    assert env.run() == 0
    captured = capsys.readouterr()
    assert "已更新" in captured.out and "下载中 100%" in captured.err
    state = env.installer().load()
    assert (state.current_package_id, state.previous_package_id) == ("pkg-new", "pkg-old")
    record = load_update_record(env.data_dir / "runtime" / "state" / "update.json")
    assert record is not None and record.release_tag == "build-2"


def test_update_can_be_declined(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    assert env.run() == 1
    assert "已取消" in capsys.readouterr().out

    def no_input(prompt: str) -> str:
        raise EOFError

    assert env.run(confirm=no_input) == 1
    assert env.control.calls == []


def test_unhealthy_update_rolls_back(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    def refuse_new(executable: Path) -> bool:
        env.control.calls.append(f"start:{executable.parent.name}")
        env.control.running = True
        return executable.read_bytes() == b"old"

    env.control.start = refuse_new  # type: ignore[method-assign]
    assert env.run("--yes") == 1
    assert "已自动退回" in capsys.readouterr().out
    assert env.installer().load().current_package_id == "pkg-old"


def test_rollback_command(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    assert env.run("--rollback") == 2
    assert "还没有可以退回" in capsys.readouterr().out
    assert env.run("--yes") == 0
    assert env.run("--rollback") == 1
    assert "已取消" in capsys.readouterr().out
    env.answers.append("y")
    assert env.run("--rollback") == 0
    assert "已退回上一个版本" in capsys.readouterr().out
    state = env.installer().load()
    assert (state.current_package_id, state.previous_package_id) == ("pkg-old", "pkg-new")


def test_busy_lock_is_reported(
    env: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert env.run("--yes") == 0

    def busy(self: object) -> None:
        raise UpdateBusy("busy")

    monkeypatch.setattr(update_cli.UpdateLock, "__enter__", busy)
    assert env.run("--yes", "--rollback") == 2
    env.feed.availability = Availability.UPDATE_AVAILABLE
    assert env.run("--yes") == 2
    assert capsys.readouterr().out.count("已经有一次更新在进行") == 2


def test_download_and_install_failures(
    env: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    env.feed.release = env.feed.release.model_copy(
        update={"asset": env.feed.release.asset.model_copy(update={"sha256": "0" * 64})}
    )
    assert env.run("--yes") == 2
    assert "checksum_mismatch" in capsys.readouterr().out

    def broken(*args: object, **kwargs: object) -> None:
        raise OSError("disk")

    monkeypatch.setattr(update_cli, "adopt_running_package", broken)
    assert env.run("--yes") == 2
    assert "OSError" in capsys.readouterr().out
    assert env.control.calls == []


def test_same_package_is_already_current(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.body = build_archive(env.program, env.tmp_path / "same" / "tm.tar.gz").read_bytes()
    env.feed.release = env.feed.release.model_copy(
        update={
            "asset": env.feed.release.asset.model_copy(
                update={"size": len(env.body), "sha256": hashlib.sha256(env.body).hexdigest()}
            )
        }
    )
    assert env.run("--yes") == 0
    assert "已是最新版本" in capsys.readouterr().out


def test_preconditions(
    env: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert env.run(frozen=False) == 2
    assert env.run(program_dir=env.tmp_path) == 2
    assert "源码" in capsys.readouterr().out
    assert (
        update_cli.update_command(
            ["--profile", str(env.tmp_path / "missing.json")],
            frozen=True,
            program_dir=env.program,
        )
        == 2
    )
    assert "runtime profile" in capsys.readouterr().out
    broken = env.tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert (
        update_cli.update_command(["--profile", str(broken)], frozen=True, program_dir=env.program)
        == 2
    )
    env.feed.error = ReleaseFeedError("no_release")
    assert env.run() == 2
    assert "no_release" in capsys.readouterr().out
    monkeypatch.setattr(update_cli, "_over_ssh_on_windows", lambda: True)
    assert env.run() == 2
    assert "桌面" in capsys.readouterr().out
    monkeypatch.setattr(update_cli, "runtime_target", lambda: None)
    assert env.run() == 2
    assert "平台" in capsys.readouterr().out


def test_defaults_use_real_feed_and_control(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        update_cli.GitHubReleaseFeed, "from_environment", classmethod(lambda cls: env.feed)
    )
    assert env.run("--check", feed=None, control=None) == 0
    assert "build-2" in capsys.readouterr().out


def test_update_is_forwarded_to_current_version(env: Env) -> None:
    seen: list[tuple[Path, list[str], Path]] = []

    def forward(data_dir: Path, argv: list[str], *, install_root: Path) -> int:
        seen.append((data_dir, argv, install_root))
        return 3

    assert env.run("--check", forward=forward) == 3
    assert seen[0][1][:2] == ["update", "--profile"]
    assert seen[0][1][-1] == "--check"
    assert seen[0][2] == env.install_root.resolve()


def test_ssh_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_cli.sys, "platform", "win32")
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    assert not update_cli._over_ssh_on_windows()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setenv("SSH_CLIENT", "10.0.0.1 1 22")
    assert update_cli._over_ssh_on_windows()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(update_cli.sys, "platform", "darwin")
    assert not update_cli._over_ssh_on_windows()  # pyright: ignore[reportPrivateUsage]


def test_update_apply_command(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    installer = env.installer()
    installer.stage(env.program, env.program / "runtime-package-manifest.json")
    new = build_package(env.tmp_path / "staged", "pkg-new", b"new", revision=NEW_REVISION)
    installer.stage(new, new / "runtime-package-manifest.json")
    arguments = [
        "--profile",
        str(env.profile_path),
        "--install-root",
        str(env.install_root),
        "--target",
        "pkg-new",
        "--fallback",
        "pkg-old",
        "--release-tag",
        "build-2",
    ]
    assert update_cli.update_apply_command(arguments, control=env.control, settle_seconds=0) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "updated"

    failing = FakeControl(stop_ok=False)
    assert update_cli.update_apply_command(arguments, control=failing, settle_seconds=0) == 1

    missing = [*arguments]
    missing[1] = str(env.tmp_path / "missing.json")
    assert update_cli.update_apply_command(missing, settle_seconds=0) == 2

    unknown = [*arguments]
    unknown[unknown.index("--target") + 1] = "pkg-unknown"
    assert update_cli.update_apply_command(unknown, control=env.control, settle_seconds=0) == 2
    assert "update_apply_failed" in capsys.readouterr().err


def test_update_apply_command_reports_busy(
    env: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def busy(self: object) -> None:
        raise UpdateBusy("busy")

    monkeypatch.setattr(update_cli.UpdateLock, "__enter__", busy)
    arguments = [
        "--profile",
        str(env.profile_path),
        "--install-root",
        str(env.install_root),
        "--target",
        "a",
        "--fallback",
        "b",
    ]
    assert update_cli.update_apply_command(arguments, settle_seconds=0) == 2
    assert "update_in_progress" in capsys.readouterr().err


def test_main_dispatches_update_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        update_cli, "update_command", lambda argv: seen.append(("update", list(argv))) or 0
    )
    monkeypatch.setattr(
        update_cli,
        "update_apply_command",
        lambda argv: seen.append(("apply", list(argv))) or 0,
    )
    assert cli.main(["update", "--check"]) == 0
    assert cli.main(["update-apply", "--target", "x"]) == 0
    assert seen == [("update", ["--check"]), ("apply", ["--target", "x"])]


def _installed(tmp_path: Path) -> tuple[Path, RuntimePackageInstaller]:
    data = (tmp_path / "data").resolve()
    installer = RuntimePackageInstaller(tmp_path / "install", data)
    package = build_package(tmp_path / "pkg", "pkg-current", b"cur")
    record = installer.stage(package, package / "runtime-package-manifest.json")
    installer.activate(record.package_id, lambda: True)
    return data, installer


def test_runtime_start_forwards_to_current_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data, installer = _installed(tmp_path)
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def runner(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        calls.append((command, environment))  # pyright: ignore[reportUnknownArgumentType]
        return SimpleNamespace(returncode=7)

    monkeypatch.delenv(NO_REDIRECT_ENV, raising=False)
    code = forward_to_current_version(
        data,
        ["runtime", "start"],
        executable=tmp_path / "old" / "tunnelminion",
        frozen=True,
        install_root=tmp_path / "install",
        runner=runner,  # pyright: ignore[reportArgumentType]
    )
    assert code == 7
    command, environment = calls[0]
    assert Path(command[0]) == installer.executable("pkg-current")
    assert command[1:] == ("runtime", "start")
    assert environment[NO_REDIRECT_ENV] == "1"
    assert "转交" in capsys.readouterr().err


def test_runtime_start_does_not_forward_when_not_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, installer = _installed(tmp_path)
    current = installer.executable("pkg-current")

    def forward(**overrides: object) -> int | None:
        options: dict[str, object] = {
            "executable": tmp_path / "old" / "tunnelminion",
            "frozen": True,
            "install_root": tmp_path / "install",
            "runner": lambda *args, **kwargs: pytest.fail("不应转交"),
        }
        options.update(overrides)
        return forward_to_current_version(data, ["runtime", "start"], **options)  # pyright: ignore[reportArgumentType]

    monkeypatch.setenv(NO_REDIRECT_ENV, "1")
    assert forward() is None
    monkeypatch.delenv(NO_REDIRECT_ENV)
    assert forward(frozen=False) is None
    assert forward(executable=current) is None
    assert forward(install_root=tmp_path / "empty") is None
    monkeypatch.setattr(installer.__class__, "executable", lambda self, package_id: tmp_path / "x")
    assert forward() is None
    monkeypatch.undo()
    (tmp_path / "install" / "runtime-install.json").write_text("{", encoding="utf-8")
    assert forward() is None
    monkeypatch.setattr("tunnelminion.update.redirect.sys.frozen", False, raising=False)
    assert (
        forward_to_current_version(data, ["runtime", "start"], install_root=tmp_path / "x") is None
    )


def test_runtime_cli_start_uses_forwarded_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path = tmp_path / "profile.json"
    FileRuntimeProfileRepository(profile_path, tmp_path / "program").save(
        RuntimeProfile(data_dir=(tmp_path / "data").resolve())
    )
    monkeypatch.setattr(
        "tunnelminion.runtime.profile.current_program_dir", lambda: tmp_path / "program"
    )
    monkeypatch.setattr(
        "tunnelminion.update.redirect.forward_to_current_version",
        lambda data_dir, values: 5,
    )
    assert cli.main(["runtime", "start", "--profile", str(profile_path)]) == 5
