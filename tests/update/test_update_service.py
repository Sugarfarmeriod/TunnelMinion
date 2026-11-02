"""本机网页更新服务和接口的测试。"""

# pyright: reportUnknownLambdaType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.update.conftest import build_archive, build_package

from tunnelminion.runtime.install import RuntimePackageInstaller
from tunnelminion.runtime.profile import FileRuntimeProfileRepository, RuntimeProfile
from tunnelminion.update import service as service_module
from tunnelminion.update.apply import UpdateBusy
from tunnelminion.update.release import (
    Availability,
    ReleaseAsset,
    ReleaseFeedError,
    ReleaseInfo,
)
from tunnelminion.update.service import (
    UnsupportedReason,
    UpdatePhase,
    UpdateService,
)
from tunnelminion.web.request_guard import install_local_request_guard
from tunnelminion.web.update import create_update_router

OLD_REVISION = "1" * 40
NEW_REVISION = "2" * 40


class FakeFeed:
    def __init__(self, release: ReleaseInfo, availability: Availability) -> None:
        self.release = release
        self.availability = availability
        self.error: ReleaseFeedError | None = None
        self.compared: list[tuple[str, str]] = []

    @property
    def allows_loopback_http(self) -> bool:
        return True

    def latest(self, target: str) -> ReleaseInfo:
        assert target == "windows-amd64"
        if self.error is not None:
            raise self.error
        return self.release

    def compare(self, current_revision: str, release_revision: str) -> Availability:
        self.compared.append((current_revision, release_revision))
        return self.availability


class Setup:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.data_dir = (tmp_path / "data").resolve()
        self.data_dir.mkdir()
        self.profile_path = tmp_path / "profile.json"
        self.program = build_package(tmp_path / "running", "pkg-old", b"old", revision=OLD_REVISION)
        FileRuntimeProfileRepository(self.profile_path, self.program).save(
            RuntimeProfile(data_dir=self.data_dir)
        )
        new_package = build_package(tmp_path / "new", "pkg-new", b"new", revision=NEW_REVISION)
        self.archive = build_archive(new_package, tmp_path / "served" / "tm.tar.gz")
        body = self.archive.read_bytes()
        self.body = body
        self.release = ReleaseInfo(
            tag="build-2",
            source_revision=NEW_REVISION,
            asset=ReleaseAsset(
                name="tm.tar.gz",
                url="http://127.0.0.1:9/tm.tar.gz",
                size=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
            ),
        )
        self.feed = FakeFeed(self.release, Availability.UPDATE_AVAILABLE)
        self.install_root = tmp_path / "install"
        self.launched: list[tuple[tuple[str, ...], Path]] = []

    def service(self, **overrides: object) -> UpdateService:
        options: dict[str, object] = {
            "profile_path": self.profile_path,
            "feed": self.feed,
            "program_dir": self.program,
            "executable": self.program / "app.bin",
            "frozen": True,
            "target": "windows-amd64",
            "install_root": self.install_root,
            "launcher": lambda command, log: self.launched.append((command, log)),
            "background": False,
        }
        options.update(overrides)
        return UpdateService(self.data_dir, **options)  # pyright: ignore[reportArgumentType]


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Setup:
    context = Setup(tmp_path)
    real_client = httpx.Client

    def client(**kwargs: object) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(200, content=context.body)
        )
        return real_client(**kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr("tunnelminion.update.package.httpx.Client", client)
    return context


def test_unsupported_reasons(setup: Setup) -> None:
    cases = [
        ({"read_only_preview": True}, UnsupportedReason.READ_ONLY_PREVIEW),
        ({"frozen": False}, UnsupportedReason.SOURCE_RUN),
        ({"program_dir": setup.tmp_path}, UnsupportedReason.SOURCE_RUN),
        ({"profile_path": None}, UnsupportedReason.NO_RUNTIME_PROFILE),
        ({"profile_path": setup.tmp_path / "missing.json"}, UnsupportedReason.NO_RUNTIME_PROFILE),
    ]
    for overrides, reason in cases:
        view = setup.service(**overrides).view()
        assert (view.supported, view.unsupported_reason) == (False, reason)
    service = setup.service()
    service._target = None  # pyright: ignore[reportPrivateUsage]
    assert service.unsupported_reason() is UnsupportedReason.UNSUPPORTED_PLATFORM
    with pytest.raises(service_module.UpdateRejected) as caught:
        service.check()
    assert caught.value.code == "unsupported_platform"


def test_view_and_check_show_current_and_latest(setup: Setup) -> None:
    service = setup.service()
    view = service.view()
    assert view.supported
    assert view.current.package_id == "pkg-old"
    assert view.current.source_revision == OLD_REVISION
    assert view.latest is None and view.availability is None
    checked = service.check()
    assert checked.latest is not None and checked.latest.tag == "build-2"
    assert checked.availability is Availability.UPDATE_AVAILABLE
    assert checked.check_error is None and checked.checked_at is not None
    assert setup.feed.compared == [(OLD_REVISION, NEW_REVISION)]

    setup.feed.error = ReleaseFeedError("github_rate_limited")
    failed = service.check()
    assert failed.latest is None and failed.check_error == "github_rate_limited"


def test_full_update_prepares_package_and_hands_over_to_helper(setup: Setup) -> None:
    service = setup.service()
    view = service.start_update("build-2")
    assert view.job.phase is UpdatePhase.RESTARTING
    assert view.job.downloaded_bytes == view.job.total_bytes == len(setup.body)
    [(command, log_path)] = setup.launched
    assert command[1] == "update-apply"
    assert command[command.index("--target") + 1] == "pkg-new"
    assert command[command.index("--fallback") + 1] == "pkg-old"
    assert command[command.index("--release-tag") + 1] == "build-2"
    assert log_path.name == "update.log"
    installer = RuntimePackageInstaller(setup.install_root, setup.data_dir)
    assert {item.package_id for item in installer.load().packages} == {"pkg-old", "pkg-new"}
    assert installer.find("pkg-new") is not None
    assert not any((setup.install_root / "downloads").glob("*.tar.gz*"))
    # 换包进程还没跑，当前仍是旧版；旧版已登记但没有 Release 名
    assert service.view().current.release_tag is None


def test_update_runs_in_background_thread(setup: Setup) -> None:
    done = threading.Event()
    setup_launched = setup.launched

    def launcher(command: tuple[str, ...], log: Path) -> None:
        setup_launched.append((command, log))
        done.set()

    service = setup.service(background=True, launcher=launcher)
    service.start_update("build-2")
    assert done.wait(30)
    deadline = time.monotonic() + 5
    while service.view().job.phase is not UpdatePhase.RESTARTING:
        assert time.monotonic() < deadline
        time.sleep(0.01)


@pytest.mark.parametrize(
    ("tag", "availability", "code"),
    [
        ("build-1", Availability.UPDATE_AVAILABLE, "release_changed"),
        ("build-2", Availability.UP_TO_DATE, "already_current"),
        ("build-2", Availability.UNRELEASED_BUILD, "current_is_newer"),
    ],
)
def test_start_update_rejections(
    setup: Setup, tag: str, availability: Availability, code: str
) -> None:
    setup.feed.availability = availability
    with pytest.raises(service_module.UpdateRejected) as caught:
        setup.service().start_update(tag)
    assert caught.value.code == code
    assert setup.launched == []


def test_start_update_feed_error_and_unknown_availability(setup: Setup) -> None:
    setup.feed.error = ReleaseFeedError("network_unreachable")
    with pytest.raises(service_module.UpdateRejected) as caught:
        setup.service().start_update("build-2")
    assert caught.value.code == "network_unreachable"

    setup.feed.error = None
    setup.feed.availability = Availability.UNKNOWN
    assert setup.service().start_update("build-2").job.phase is UpdatePhase.RESTARTING


def test_only_one_update_at_a_time(setup: Setup, monkeypatch: pytest.MonkeyPatch) -> None:
    service = setup.service()
    service._job = service._job.model_copy(  # pyright: ignore[reportPrivateUsage]
        update={"phase": UpdatePhase.DOWNLOADING}
    )
    with pytest.raises(service_module.UpdateRejected) as caught:
        service.start_update("build-2")
    assert caught.value.code == "update_in_progress"

    # 查版本期间另一个请求抢先开始了更新
    racing = setup.service()
    original = racing._fetch  # pyright: ignore[reportPrivateUsage]

    def fetch_then_race() -> tuple[ReleaseInfo, Availability]:
        result = original()
        racing._job = racing._job.model_copy(  # pyright: ignore[reportPrivateUsage]
            update={"phase": UpdatePhase.INSTALLING}
        )
        return result

    monkeypatch.setattr(racing, "_fetch", fetch_then_race)
    with pytest.raises(service_module.UpdateRejected):
        racing.start_update("build-2")


def test_checksum_failure_marks_job_failed_and_keeps_old_version(setup: Setup) -> None:
    setup.release = setup.release.model_copy(
        update={"asset": setup.release.asset.model_copy(update={"sha256": "0" * 64})}
    )
    setup.feed.release = setup.release
    view = setup.service().start_update("build-2")
    assert view.job.phase is UpdatePhase.FAILED
    assert view.job.error_code == "checksum_mismatch"
    assert setup.launched == []


def test_same_package_after_download_is_already_current(setup: Setup) -> None:
    same = build_archive(setup.program, setup.tmp_path / "same" / "tm.tar.gz")
    setup.body = same.read_bytes()
    setup.feed.release = setup.release.model_copy(
        update={
            "asset": setup.release.asset.model_copy(
                update={
                    "size": len(setup.body),
                    "sha256": hashlib.sha256(setup.body).hexdigest(),
                }
            )
        }
    )
    view = setup.service().start_update("build-2")
    assert (view.job.phase, view.job.error_code) == (UpdatePhase.FAILED, "already_current")


def test_busy_and_unexpected_errors_are_reported(
    setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    def busy(self: object) -> None:
        raise UpdateBusy("busy")

    monkeypatch.setattr(service_module.UpdateLock, "__enter__", busy)
    view = setup.service().start_update("build-2")
    assert view.job.error_code == "update_in_progress"

    monkeypatch.undo()

    def broken(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(service_module, "adopt_running_package", broken)
    real_client = httpx.Client

    def client(**kwargs: object) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(200, content=setup.body)
        )
        return real_client(**kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr("tunnelminion.update.package.httpx.Client", client)
    view = setup.service().start_update("build-2")
    assert view.job.error_code == "install_failed"


def test_current_version_survives_broken_install_state(setup: Setup) -> None:
    setup.install_root.mkdir()
    (setup.install_root / "runtime-install.json").write_text("{", encoding="utf-8")
    current = setup.service().view().current
    assert current.package_id == "pkg-old" and current.release_tag is None
    assert setup.service(program_dir=setup.tmp_path).view().current.package_id is None


def test_default_feed_and_dependencies(setup: Setup, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TUNNELMINION_UPDATE_FEED", "http://127.0.0.1:1")
    service = UpdateService(setup.data_dir, profile_path=None)
    assert service._source().allows_loopback_http  # pyright: ignore[reportPrivateUsage]
    assert service._install_root().name.startswith("node-")  # pyright: ignore[reportPrivateUsage]
    launched: list[tuple[tuple[str, ...], Path]] = []
    monkeypatch.setattr(
        service_module.DetachedProcessAdapter,
        "spawn",
        lambda self, command, log: launched.append((command, log)),
    )
    service_module._detached_launcher(("x",), setup.tmp_path / "log")  # pyright: ignore[reportPrivateUsage]
    assert launched == [(("x",), setup.tmp_path / "log")]


def test_revision_unknown_means_availability_unknown(setup: Setup) -> None:
    service = setup.service()
    monkeypatch_current = service_module.CurrentVersion()
    service._current = lambda: monkeypatch_current  # type: ignore[method-assign]  # pyright: ignore[reportPrivateUsage]
    assert service.check().availability is Availability.UNKNOWN
    assert setup.feed.compared == []


def _client(service: UpdateService) -> TestClient:
    app = FastAPI()
    install_local_request_guard(app)
    app.include_router(create_update_router(service))
    return TestClient(app, base_url="http://127.0.0.1:8765")


WRITE = {"X-TunnelMinion-Request": "same-origin", "Origin": "http://127.0.0.1:8765"}


def test_routes_view_check_and_apply(setup: Setup) -> None:
    client = _client(setup.service())
    assert client.get("/api/update").json()["supported"] is True
    checked = client.post("/api/update/check", headers=WRITE).json()
    assert checked["availability"] == "update_available"
    response = client.post("/api/update/apply", headers=WRITE, json={"release_tag": "build-2"})
    assert response.status_code == 202
    assert response.json()["job"]["phase"] == "restarting"


def test_routes_reject_with_readable_codes(setup: Setup) -> None:
    client = _client(setup.service(read_only_preview=True))
    response = client.post("/api/update/check", headers=WRITE)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "read_only_preview"

    client = _client(setup.service())
    response = client.post("/api/update/apply", headers=WRITE, json={"release_tag": "build-1"})
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "release_changed",
        "message": "最新版本刚刚变了，请重新检查后再确认",
    }
    setup.feed.error = ReleaseFeedError("no_release")
    response = client.post("/api/update/apply", headers=WRITE, json={"release_tag": "build-2"})
    assert response.json()["detail"]["message"] == "现在不能更新，请稍后重试"


def test_routes_refuse_cross_site_and_missing_header(setup: Setup) -> None:
    client = _client(setup.service())
    cross = client.post(
        "/api/update/apply",
        headers={"X-TunnelMinion-Request": "same-origin", "Origin": "https://evil.example"},
        json={"release_tag": "build-2"},
    )
    assert cross.status_code == 403
    missing = client.post(
        "/api/update/apply",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"release_tag": "build-2"},
    )
    assert missing.status_code == 403
    assert setup.launched == []
