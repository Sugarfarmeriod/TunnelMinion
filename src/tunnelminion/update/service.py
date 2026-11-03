"""本机网页背后的更新服务：查新版本、下载校验、交给独立进程换包。

只挂在只监听 127.0.0.1 的本机网页上；网关、Agent 和 MCP 都没有入口。
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import BaseModel, ConfigDict

from tunnelminion.runtime.install import (
    PACKAGE_MANIFEST_FILE,
    RuntimePackageInstaller,
    node_install_root,
)
from tunnelminion.runtime.process import DetachedProcessAdapter
from tunnelminion.runtime.profile import RUNTIME_DIRECTORY, current_program_dir
from tunnelminion.update.apply import (
    UPDATE_RECORD_FILE,
    UpdateBusy,
    UpdateLock,
    UpdateRecord,
    adopt_running_package,
    load_update_record,
    running_package_identity,
)
from tunnelminion.update.package import UpdatePackageError, download_asset, stage_archive
from tunnelminion.update.release import (
    Availability,
    GitHubReleaseFeed,
    ReleaseFeed,
    ReleaseFeedError,
    ReleaseInfo,
    runtime_target,
)

HelperLauncher = Callable[[tuple[str, ...], Path], object]


class UnsupportedReason(StrEnum):
    """这个实例不能一键更新的原因。"""

    READ_ONLY_PREVIEW = "read_only_preview"
    SOURCE_RUN = "source_run"
    NO_RUNTIME_PROFILE = "no_runtime_profile"
    UNSUPPORTED_PLATFORM = "unsupported_platform"


class UpdatePhase(StrEnum):
    """更新任务进行到哪一步。"""

    IDLE = "idle"
    DOWNLOADING = "downloading"
    INSTALLING = "installing"
    RESTARTING = "restarting"
    FAILED = "failed"


_ACTIVE_PHASES = frozenset(
    {UpdatePhase.DOWNLOADING, UpdatePhase.INSTALLING, UpdatePhase.RESTARTING}
)


class UpdateRejected(RuntimeError):
    """更新请求被拒绝的稳定错误码。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CurrentVersion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    package_id: str | None = None
    source_revision: str | None = None
    release_tag: str | None = None


class LatestRelease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tag: str
    source_revision: str
    published_at: datetime | None
    size: int


class UpdateJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: UpdatePhase = UpdatePhase.IDLE
    release_tag: str | None = None
    downloaded_bytes: int = 0
    total_bytes: int = 0
    error_code: str | None = None


class UpdateView(BaseModel):
    """设置页"版本"区显示的全部内容，不含路径和秘密。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    supported: bool
    unsupported_reason: UnsupportedReason | None
    current: CurrentVersion
    latest: LatestRelease | None
    availability: Availability | None
    checked_at: datetime | None
    check_error: str | None
    job: UpdateJob
    last_result: UpdateRecord | None


def _detached_launcher(command: tuple[str, ...], log_path: Path) -> object:
    return DetachedProcessAdapter().spawn(command, log_path)


class UpdateService:
    """一次只跑一个更新任务；准备阶段旧版照常可用，切换交给独立进程。"""

    def __init__(
        self,
        data_dir: Path,
        *,
        profile_path: Path | None,
        read_only_preview: bool = False,
        feed: ReleaseFeed | None = None,
        program_dir: Path | None = None,
        executable: Path | None = None,
        frozen: bool | None = None,
        target: str | None = None,
        install_root: Path | None = None,
        launcher: HelperLauncher | None = None,
        background: bool = True,
    ) -> None:
        self._data_dir = data_dir.expanduser().resolve()
        self._profile_path = profile_path
        self._read_only_preview = read_only_preview
        self._feed = feed
        self._program_dir = program_dir or current_program_dir()
        self._executable = executable or Path(sys.executable).resolve()
        self._frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
        self._target = runtime_target() if target is None else target
        self._install_root_override = install_root
        self._launcher = launcher or _detached_launcher
        self._background = background
        # 和 resolve_runtime_paths 的布局一致；这里不碰 profile 默认路径，组装网页时不读系统目录
        runtime = self._data_dir / RUNTIME_DIRECTORY
        self._record_path = runtime / "state" / UPDATE_RECORD_FILE
        self._log_path = runtime / "logs" / "update.log"
        self._lock = threading.Lock()
        self._job = UpdateJob()
        self._latest: ReleaseInfo | None = None
        self._availability: Availability | None = None
        self._checked_at: datetime | None = None
        self._check_error: str | None = None

    def _install_root(self) -> Path:
        """用到时才确定安装目录，组装网页时不去读系统目录。"""
        return self._install_root_override or node_install_root(self._data_dir)

    def unsupported_reason(self) -> UnsupportedReason | None:
        if self._read_only_preview:
            return UnsupportedReason.READ_ONLY_PREVIEW
        if not self._frozen or not (self._program_dir / PACKAGE_MANIFEST_FILE).is_file():
            return UnsupportedReason.SOURCE_RUN
        if self._profile_path is None or not self._profile_path.is_file():
            return UnsupportedReason.NO_RUNTIME_PROFILE
        if self._target is None:
            return UnsupportedReason.UNSUPPORTED_PLATFORM
        return None

    def view(self) -> UpdateView:
        reason = self.unsupported_reason()
        with self._lock:
            latest = self._latest
            return UpdateView(
                supported=reason is None,
                unsupported_reason=reason,
                current=self._current(),
                latest=None
                if latest is None
                else LatestRelease(
                    tag=latest.tag,
                    source_revision=latest.source_revision,
                    published_at=latest.published_at,
                    size=latest.asset.size,
                ),
                availability=self._availability,
                checked_at=self._checked_at,
                check_error=self._check_error,
                job=self._job,
                last_result=load_update_record(self._record_path),
            )

    def check(self) -> UpdateView:
        """联网查一次最新发布版本；只在主人点"检查更新"或打开设置页时调用。"""
        self._require_supported()
        try:
            release, availability = self._fetch()
        except ReleaseFeedError as exc:
            with self._lock:
                self._latest = None
                self._availability = None
                self._check_error = exc.code
                self._checked_at = datetime.now(UTC)
            return self.view()
        with self._lock:
            self._latest = release
            self._availability = availability
            self._check_error = None
            self._checked_at = datetime.now(UTC)
        return self.view()

    def start_update(self, release_tag: str) -> UpdateView:
        """主人确认后开始更新；请求里的版本必须和刚查到的最新版本一致。"""
        self._require_supported()
        with self._lock:
            if self._job.phase in _ACTIVE_PHASES:
                raise UpdateRejected("update_in_progress")
        try:
            release, availability = self._fetch()
        except ReleaseFeedError as exc:
            raise UpdateRejected(exc.code) from exc
        if release.tag != release_tag:
            raise UpdateRejected("release_changed")
        if availability is Availability.UP_TO_DATE:
            raise UpdateRejected("already_current")
        if availability is Availability.UNRELEASED_BUILD:
            raise UpdateRejected("current_is_newer")
        with self._lock:
            if self._job.phase in _ACTIVE_PHASES:
                raise UpdateRejected("update_in_progress")
            self._latest = release
            self._availability = availability
            self._job = UpdateJob(
                phase=UpdatePhase.DOWNLOADING,
                release_tag=release.tag,
                total_bytes=release.asset.size,
            )
        if self._background:
            threading.Thread(
                target=self._run, args=(release,), name="tunnelminion-update", daemon=True
            ).start()
        else:
            self._run(release)
        return self.view()

    def _run(self, release: ReleaseInfo) -> None:
        profile_path = cast(Path, self._profile_path)
        try:
            with UpdateLock(self._install_root()):
                installer = RuntimePackageInstaller(self._install_root(), self._data_dir)
                archive = self._install_root() / "downloads" / release.asset.name
                try:
                    download_asset(
                        release.asset,
                        archive,
                        allow_loopback_http=self._source().allows_loopback_http,
                        progress=self._progress,
                    )
                    self._set_phase(UpdatePhase.INSTALLING)
                    target = stage_archive(
                        installer,
                        archive,
                        self._install_root() / "downloads",
                        release_tag=release.tag,
                    )
                finally:
                    archive.unlink(missing_ok=True)
                fallback = adopt_running_package(installer, self._program_dir)
                if target.package_id == fallback.package_id:
                    raise UpdateRejected("already_current")
            command = (
                str(self._executable),
                "update-apply",
                "--profile",
                str(profile_path),
                "--install-root",
                str(self._install_root()),
                "--target",
                target.package_id,
                "--fallback",
                fallback.package_id,
                "--release-tag",
                release.tag,
            )
            self._set_phase(UpdatePhase.RESTARTING)
            self._launcher(command, self._log_path)
        except UpdatePackageError as exc:
            self._fail(exc.code)
        except UpdateRejected as exc:
            self._fail(exc.code)
        except UpdateBusy:
            self._fail("update_in_progress")
        except (OSError, RuntimeError, ValueError, KeyError):
            self._fail("install_failed")

    def _source(self) -> ReleaseFeed:
        if self._feed is None:
            self._feed = GitHubReleaseFeed.from_environment()
        return self._feed

    def _fetch(self) -> tuple[ReleaseInfo, Availability]:
        feed = self._source()
        release = feed.latest(cast(str, self._target))
        revision = self._current().source_revision
        availability = (
            feed.compare(revision, release.source_revision)
            if revision is not None
            else Availability.UNKNOWN
        )
        return release, availability

    def _current(self) -> CurrentVersion:
        identity = running_package_identity(self._program_dir)
        if identity is None:
            return CurrentVersion()
        package_id, revision = identity
        try:
            installed = RuntimePackageInstaller(self._install_root(), self._data_dir).find(
                package_id
            )
        except (OSError, ValueError):
            installed = None
        return CurrentVersion(
            package_id=package_id,
            source_revision=revision,
            release_tag=None if installed is None else installed.release_tag,
        )

    def _require_supported(self) -> None:
        reason = self.unsupported_reason()
        if reason is not None:
            raise UpdateRejected(reason.value)

    def _progress(self, received: int, total: int) -> None:
        with self._lock:
            self._job = self._job.model_copy(
                update={"downloaded_bytes": received, "total_bytes": total}
            )

    def _set_phase(self, phase: UpdatePhase) -> None:
        with self._lock:
            self._job = self._job.model_copy(update={"phase": phase})

    def _fail(self, code: str) -> None:
        with self._lock:
            self._job = self._job.model_copy(
                update={"phase": UpdatePhase.FAILED, "error_code": code}
            )
