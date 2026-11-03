"""查询最新发布版本与比较提交先后的测试。"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from tunnelminion.update import release as release_module
from tunnelminion.update.release import (
    FEED_OVERRIDE_ENV,
    Availability,
    GitHubReleaseFeed,
    ReleaseFeedError,
    is_loopback_url,
    require_download_url,
    runtime_target,
)

API = "https://api.example.test"
REPO = "owner/repo"
REVISION = "c" * 40
SHA = "d" * 64


def _metadata(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": "tunnelminion-release/v1",
        "tag": "build-7",
        "source_revision": REVISION,
        "assets": {
            "windows-amd64": {"name": "tm-windows.tar.gz", "size": 10, "sha256": SHA},
        },
    }
    value.update(overrides)
    return json.dumps(value).encode()


def _release(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "tag_name": "build-7",
        "published_at": "2026-11-02T08:00:00Z",
        "assets": [
            "not-an-object",
            {"name": "incomplete"},
            {
                "name": "tm-windows.tar.gz",
                "browser_download_url": "https://downloads.example.test/tm-windows.tar.gz",
                "size": 10,
            },
            {
                "name": "release.json",
                "browser_download_url": "https://downloads.example.test/release.json",
                "size": 100,
            },
        ],
    }
    value.update(overrides)
    return value


Handler = Callable[[httpx.Request], httpx.Response]


def _feed(handler: Handler, api: str = API) -> GitHubReleaseFeed:
    return GitHubReleaseFeed(api, REPO, transport=httpx.MockTransport(handler))


def _serve(
    release: object | None = None,
    metadata: bytes | None = None,
    *,
    release_status: int = 200,
    metadata_status: int = 200,
) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(release_status, json=_release() if release is None else release)
        if request.url.path.endswith("/release.json"):
            return httpx.Response(
                metadata_status, content=_metadata() if metadata is None else metadata
            )
        raise AssertionError(request.url)

    return handler


def test_latest_returns_platform_asset_with_checksum_from_metadata() -> None:
    info = _feed(_serve()).latest("windows-amd64")
    assert info.tag == "build-7"
    assert info.source_revision == REVISION
    assert info.published_at is not None
    assert info.asset.url.endswith("tm-windows.tar.gz")
    assert (info.asset.size, info.asset.sha256) == (10, SHA)


def test_latest_without_published_time_is_still_valid() -> None:
    info = _feed(_serve(_release(published_at=None))).latest("windows-amd64")
    assert info.published_at is None


@pytest.mark.parametrize(
    ("release", "metadata", "code"),
    [
        ({"assets": []}, None, "release_invalid"),
        (_release(assets=[]), None, "release_metadata_missing"),
        (None, _metadata(tag="build-8"), "release_invalid"),
        (None, _metadata(assets={}), "platform_not_released"),
        (
            None,
            _metadata(
                assets={"windows-amd64": {"name": "missing.tar.gz", "size": 10, "sha256": SHA}}
            ),
            "platform_not_released",
        ),
        (
            None,
            _metadata(
                assets={"windows-amd64": {"name": "tm-windows.tar.gz", "size": 11, "sha256": SHA}}
            ),
            "release_invalid",
        ),
        (None, b"{not json", "release_invalid"),
        (None, b"x" * (64 * 1024 + 1), "release_invalid"),
        (_release(published_at="yesterday"), None, "release_invalid"),
    ],
    ids=[
        "no-tag",
        "no-metadata",
        "tag-mismatch",
        "no-platform",
        "asset-missing",
        "size-mismatch",
        "bad-json",
        "too-large",
        "bad-time",
    ],
)
def test_latest_rejects_inconsistent_release(
    release: object | None, metadata: bytes | None, code: str
) -> None:
    with pytest.raises(ReleaseFeedError) as caught:
        _feed(_serve(release, metadata)).latest("windows-amd64")
    assert caught.value.code == code


def test_latest_rejects_plain_http_download() -> None:
    release = _release()
    assets = release["assets"]
    assert isinstance(assets, list)
    assets[2] = {
        "name": "tm-windows.tar.gz",
        "browser_download_url": "http://downloads.example.test/tm-windows.tar.gz",
        "size": 10,
    }
    with pytest.raises(ReleaseFeedError) as caught:
        _feed(_serve(release)).latest("windows-amd64")
    assert caught.value.code == "download_url_rejected"


def test_metadata_redirect_to_plain_http_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json=_release())
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"Location": "http://evil.test/release.json"})
        return httpx.Response(200, content=_metadata())

    with pytest.raises(ReleaseFeedError) as caught:
        _feed(handler).latest("windows-amd64")
    assert caught.value.code == "download_url_rejected"


def test_metadata_download_failure_codes() -> None:
    with pytest.raises(ReleaseFeedError) as caught:
        _feed(_serve(metadata_status=404)).latest("windows-amd64")
    assert caught.value.code == "release_metadata_missing"

    def broken(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json=_release())
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(ReleaseFeedError) as caught:
        _feed(broken).latest("windows-amd64")
    assert caught.value.code == "network_unreachable"


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (404, b"{}", "no_release"),
        (403, b"{}", "github_rate_limited"),
        (429, b"{}", "github_rate_limited"),
        (500, b"{}", "release_feed_failed"),
        (200, b"not json", "release_invalid"),
        (200, b"[]", "release_invalid"),
    ],
)
def test_latest_maps_api_errors(status: int, body: bytes, code: str) -> None:
    feed = _feed(lambda request: httpx.Response(status, content=body))
    with pytest.raises(ReleaseFeedError) as caught:
        feed.latest("windows-amd64")
    assert caught.value.code == code


def test_latest_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    with pytest.raises(ReleaseFeedError) as caught:
        _feed(handler).latest("windows-amd64")
    assert caught.value.code == "network_unreachable"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("ahead", Availability.UPDATE_AVAILABLE),
        ("identical", Availability.UP_TO_DATE),
        ("behind", Availability.UNRELEASED_BUILD),
        ("diverged", Availability.DIVERGED),
        ("something-new", Availability.UNKNOWN),
    ],
)
def test_compare_maps_github_status(status: str, expected: Availability) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"status": status})

    assert _feed(handler).compare("a" * 40, "b" * 40) is expected
    assert seen == [f"/repos/{REPO}/compare/{'a' * 40}...{'b' * 40}"]


def test_compare_same_revision_needs_no_network_and_errors_are_unknown() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    feed = _feed(fail)
    assert feed.compare("a" * 40, "a" * 40) is Availability.UP_TO_DATE
    assert feed.compare("a" * 40, "b" * 40) is Availability.UNKNOWN


def test_feed_only_accepts_https_or_loopback_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="https"):
        GitHubReleaseFeed("http://api.example.test")
    loopback = GitHubReleaseFeed("http://127.0.0.1:9/")
    assert loopback.allows_loopback_http
    assert not GitHubReleaseFeed().allows_loopback_http

    monkeypatch.setenv(FEED_OVERRIDE_ENV, "http://127.0.0.1:8123")
    assert GitHubReleaseFeed.from_environment().allows_loopback_http
    monkeypatch.setenv(FEED_OVERRIDE_ENV, "https://evil.example.test")
    assert not GitHubReleaseFeed.from_environment().allows_loopback_http
    monkeypatch.delenv(FEED_OVERRIDE_ENV)
    assert not GitHubReleaseFeed.from_environment().allows_loopback_http


def test_loopback_feed_allows_local_http_downloads() -> None:
    release = _release()
    assets = release["assets"]
    assert isinstance(assets, list)
    assets[2] = {
        "name": "tm-windows.tar.gz",
        "browser_download_url": "http://127.0.0.1:9/tm-windows.tar.gz",
        "size": 10,
    }
    assets[3] = {
        "name": "release.json",
        "browser_download_url": "http://127.0.0.1:9/release.json",
        "size": 100,
    }
    info = _feed(_serve(release), "http://127.0.0.1:9").latest("windows-amd64")
    assert info.asset.url == "http://127.0.0.1:9/tm-windows.tar.gz"


def test_download_url_rules() -> None:
    require_download_url("https://example.test/a", allow_loopback_http=False)
    require_download_url("http://localhost:1/a", allow_loopback_http=True)
    for url in ("http://localhost:1/a", "ftp://example.test/a", "https:///a"):
        with pytest.raises(ReleaseFeedError):
            require_download_url(url, allow_loopback_http=False)
    assert is_loopback_url("http://[::1]:5/")
    assert not is_loopback_url("file://127.0.0.1/x")


@pytest.mark.parametrize(
    ("platform_name", "machine", "expected"),
    [
        ("win32", "AMD64", "windows-amd64"),
        ("win32", "x86_64", "windows-amd64"),
        ("darwin", "arm64", "macos-arm64"),
        ("darwin", "x86_64", None),
        ("linux", "x86_64", None),
        ("win32", "arm64", None),
    ],
)
def test_runtime_target(platform_name: str, machine: str, expected: str | None) -> None:
    assert runtime_target(platform_name, machine) == expected


def test_runtime_target_defaults_to_this_machine() -> None:
    assert runtime_target() == runtime_target(
        release_module.sys.platform, release_module.platform.machine()
    )
