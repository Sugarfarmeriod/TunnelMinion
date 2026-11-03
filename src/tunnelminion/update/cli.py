"""`tunnelminion update`：在命令行查看、更新或退回版本，和网页上的"更新"走同一套代码。"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from tunnelminion.runtime.install import RuntimePackageInstaller, node_install_root
from tunnelminion.runtime.profile import (
    FileRuntimeProfileRepository,
    RuntimeProfile,
    current_program_dir,
    default_runtime_profile_path,
)
from tunnelminion.update.apply import (
    ProfileRuntimeControl,
    RuntimeControl,
    UpdateBusy,
    UpdateLock,
    UpdateOutcome,
    UpdateRecord,
    adopt_running_package,
    apply_switch,
    running_package_identity,
    update_record_path,
)
from tunnelminion.update.package import UpdatePackageError, download_asset, stage_archive
from tunnelminion.update.redirect import forward_to_current_version
from tunnelminion.update.release import (
    Availability,
    GitHubReleaseFeed,
    ReleaseFeed,
    ReleaseFeedError,
    runtime_target,
)

_RESULT_TEXT = {
    UpdateOutcome.UPDATED: "已更新",
    UpdateOutcome.ROLLED_BACK: "新版本没能启动，已自动退回原来的版本",
    UpdateOutcome.FAILED: "更新没有完成",
}


def _short(revision: str | None) -> str:
    return "未知" if revision is None else revision[:7]


def _load_profile(path: Path) -> RuntimeProfile | None:
    try:
        return FileRuntimeProfileRepository(path, current_program_dir()).load()
    except (OSError, ValueError):
        return None


def _over_ssh_on_windows() -> bool:
    return sys.platform == "win32" and bool(
        os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT")
    )


def _confirmed(confirm: Callable[[str], str], prompt: str) -> bool:
    try:
        return confirm(prompt).strip().lower() == "y"
    except EOFError:
        return False


def _print_record(record: UpdateRecord, *, rollback: bool = False) -> int:
    suffix = f"（{record.error_code}）" if record.error_code else ""
    text = _RESULT_TEXT[record.outcome]
    if rollback and record.outcome is UpdateOutcome.UPDATED:
        text = "已退回上一个版本"
    print(f"{text}{suffix}")
    return 0 if record.outcome is UpdateOutcome.UPDATED else 1


def update_command(
    argv: Sequence[str],
    *,
    feed: ReleaseFeed | None = None,
    control: RuntimeControl | None = None,
    confirm: Callable[[str], str] = input,
    frozen: bool | None = None,
    program_dir: Path | None = None,
    forward: Callable[..., int | None] = forward_to_current_version,
) -> int:
    """查看、更新到最新发布版，或退回上一版。"""
    parser = argparse.ArgumentParser(
        prog="tunnelminion update",
        description="把这台电脑上的 TunnelMinion 更新到 GitHub 上的最新发布版",
    )
    parser.add_argument("--profile", type=Path, help="runtime start 用的同一个 profile")
    parser.add_argument("--check", action="store_true", help="只查有没有新版本，不更新")
    parser.add_argument("--yes", action="store_true", help="不再询问，直接更新")
    parser.add_argument("--rollback", action="store_true", help="退回上一个版本")
    parser.add_argument("--install-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(list(argv))

    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    program = (program_dir or current_program_dir()).resolve()
    identity = running_package_identity(program)
    if not is_frozen or identity is None:
        print("从源码运行，不支持一键更新，请用 git pull。")
        return 2
    profile_path = (args.profile or default_runtime_profile_path()).expanduser().resolve()
    profile = _load_profile(profile_path)
    if profile is None:
        print("找不到 runtime profile，请加上 runtime start 时用的 --profile。")
        return 2
    target = runtime_target()
    if target is None:
        print("这个平台没有发布运行包。")
        return 2
    if not args.check and _over_ssh_on_windows():
        print("Windows 上请回到这台电脑的桌面上运行：通过 ssh 起来的新版本读不到凭据管理器。")
        return 2
    install_root = (args.install_root or node_install_root(profile.data_dir)).resolve()
    # 从旧的解包目录运行时，交给当前版本来查和换，显示的"当前版本"才是真正在用的那个
    forwarded = forward(profile.data_dir, ["update", *argv], install_root=install_root)
    if forwarded is not None:
        return forwarded
    installer = RuntimePackageInstaller(install_root, profile.data_dir)
    runtime = control or ProfileRuntimeControl(profile_path)

    if args.rollback:
        state = installer.load()
        if state.current_package_id is None or state.previous_package_id is None:
            print("还没有可以退回的上一个版本。")
            return 2
        if not args.yes and not _confirmed(confirm, "退回上一个版本？会中断一到两分钟 [y/N] "):
            print("已取消。")
            return 1
        try:
            with UpdateLock(install_root):
                record = apply_switch(
                    installer,
                    runtime,
                    state.previous_package_id,
                    state.current_package_id,
                    update_record_path(profile),
                )
        except UpdateBusy:
            print("已经有一次更新在进行。")
            return 2
        return _print_record(record, rollback=True)

    source = feed or GitHubReleaseFeed.from_environment()
    try:
        release = source.latest(target)
    except ReleaseFeedError as exc:
        print(f"查不到最新版本（{exc.code}）。")
        return 2
    revision = identity[1]
    availability = source.compare(revision, release.source_revision)
    print(f"当前版本：提交 {_short(revision)}")
    print(f"最新版本：{release.tag}（提交 {_short(release.source_revision)}）")
    if availability is Availability.UP_TO_DATE:
        print("已是最新版本。")
        return 0
    if availability is Availability.UNRELEASED_BUILD:
        print("当前版本比最新发布版还新，不更新。")
        return 0
    print(
        {
            Availability.UNKNOWN: "无法确认最新版本是否比当前新。",
            Availability.DIVERGED: "当前构建不在发布线上（例如测试构建），"
            "换到最新发布版后它独有的改动不会保留。",
        }.get(availability, "有新版本。")
    )
    if args.check:
        return 0
    if not args.yes and not _confirmed(
        confirm, "现在更新？会中断一到两分钟，失败会自动退回 [y/N] "
    ):
        print("已取消。")
        return 1

    def progress(received: int, total: int) -> None:
        print(f"\r下载中 {received * 100 // max(total, 1)}%", end="", file=sys.stderr)

    try:
        with UpdateLock(install_root):
            current = adopt_running_package(installer, program)
            archive = install_root / "downloads" / release.asset.name
            try:
                download_asset(
                    release.asset,
                    archive,
                    allow_loopback_http=source.allows_loopback_http,
                    progress=progress,
                )
                print(file=sys.stderr)
                staged = stage_archive(
                    installer, archive, install_root / "downloads", release_tag=release.tag
                )
            finally:
                archive.unlink(missing_ok=True)
            if staged.package_id == current.package_id:
                print("已是最新版本。")
                return 0
            print("下载和校验完成，正在停止旧版、启动新版……")
            record = apply_switch(
                installer,
                runtime,
                staged.package_id,
                current.package_id,
                update_record_path(profile),
                release_tag=release.tag,
            )
    except UpdateBusy:
        print("已经有一次更新在进行。")
        return 2
    except UpdatePackageError as exc:
        print(f"\n下载或校验没通过，已删掉下载的文件，旧版不受影响（{exc.code}）。")
        return 2
    except (OSError, ValueError, KeyError) as exc:
        print(f"\n更新没有完成，旧版不受影响（{type(exc).__name__}）。")
        return 2
    return _print_record(record)


def update_apply_command(
    argv: Sequence[str],
    *,
    control: RuntimeControl | None = None,
    settle_seconds: float = 1.0,
) -> int:
    """网页确认更新后拉起的独立换包进程。"""
    parser = argparse.ArgumentParser(prog="tunnelminion update-apply")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--fallback", required=True)
    parser.add_argument("--release-tag")
    args = parser.parse_args(list(argv))
    # 让网页先把"正在重启"的回复送出去
    time.sleep(settle_seconds)
    profile_path = args.profile.expanduser().resolve()
    profile = _load_profile(profile_path)
    if profile is None:
        print("runtime_profile_invalid", file=sys.stderr)
        return 2
    installer = RuntimePackageInstaller(args.install_root, profile.data_dir)
    try:
        with UpdateLock(args.install_root):
            record = apply_switch(
                installer,
                control or ProfileRuntimeControl(profile_path),
                args.target,
                args.fallback,
                update_record_path(profile),
                release_tag=args.release_tag,
            )
    except UpdateBusy:
        print("update_in_progress", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"update_apply_failed {type(exc).__name__}", file=sys.stderr)
        return 2
    print(record.model_dump_json())
    return 0 if record.outcome is UpdateOutcome.UPDATED else 1
