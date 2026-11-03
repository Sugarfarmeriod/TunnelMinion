"""从固定 GitHub 仓库读取最新发布版本，并判断它比当前版本新还是旧。

地址写死在代码里；只有测试时可以用环境变量把来源换成 127.0.0.1 上的本机测试源。
"""

from __future__ import annotations

import os
import platform
import sys
from datetime import datetime
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

RELEASE_REPOSITORY = "Sugarfarmeriod/TunnelMinion"
GITHUB_API = "https://api.github.com"
RELEASE_METADATA_ASSET = "release.json"
RELEASE_METADATA_VERSION = "tunnelminion-release/v1"
FEED_OVERRIDE_ENV = "TUNNELMINION_UPDATE_FEED"
MAX_ARCHIVE_BYTES = 1 << 30
_MAX_METADATA_BYTES = 64 * 1024
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_TAG_PATTERN = r"^[A-Za-z0-9._-]{1,80}$"
_REVISION_PATTERN = "^[0-9a-f]{40}$"


class Availability(StrEnum):
    """最新发布版本和当前版本的先后关系。"""

    UPDATE_AVAILABLE = "update_available"
    UP_TO_DATE = "up_to_date"
    UNRELEASED_BUILD = "unreleased_build"
    UNKNOWN = "unknown"


class ReleaseFeedError(RuntimeError):
    """查询发布版本失败的稳定错误码。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MetadataAsset(BaseModel):
    """`release.json` 里一个平台运行包的大小和摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,120}$")
    size: int = Field(gt=0, le=MAX_ARCHIVE_BYTES)
    sha256: str = Field(pattern="^[0-9a-f]{64}$")


class ReleaseMetadata(BaseModel):
    """CI 随每个 Release 发布的校验清单。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=f"^{RELEASE_METADATA_VERSION}$")
    tag: str = Field(pattern=_TAG_PATTERN)
    source_revision: str = Field(pattern=_REVISION_PATTERN)
    assets: dict[str, MetadataAsset]


class ReleaseAsset(BaseModel):
    """本机平台要下载的那一个运行包。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    url: str
    size: int = Field(gt=0, le=MAX_ARCHIVE_BYTES)
    sha256: str = Field(pattern="^[0-9a-f]{64}$")


class ReleaseInfo(BaseModel):
    """最新发布版本的脱敏摘要。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tag: str = Field(pattern=_TAG_PATTERN)
    source_revision: str = Field(pattern=_REVISION_PATTERN)
    published_at: datetime | None = None
    asset: ReleaseAsset


class ReleaseFeed(Protocol):
    """查询最新发布版本和比较提交先后的来源。"""

    @property
    def allows_loopback_http(self) -> bool: ...  # pragma: no cover - Protocol 无运行时实现

    def latest(self, target: str) -> ReleaseInfo: ...  # pragma: no cover - Protocol 无运行时实现

    def compare(
        self, current_revision: str, release_revision: str
    ) -> Availability: ...  # pragma: no cover - Protocol 无运行时实现


def runtime_target(platform_name: str | None = None, machine: str | None = None) -> str | None:
    """返回本机对应的运行包平台名；不支持的平台返回 None。"""
    name = platform_name or sys.platform
    arch = (machine or platform.machine()).lower()
    if name == "win32" and arch in {"amd64", "x86_64"}:
        return "windows-amd64"
    if name == "darwin" and arch in {"arm64", "aarch64"}:
        return "macos-arm64"
    return None


def is_loopback_url(url: str) -> bool:
    """只认 http(s) 的环回地址。"""
    parts = urlsplit(url)
    return parts.scheme in {"http", "https"} and (parts.hostname or "") in _LOOPBACK_HOSTS


def require_download_url(url: str, *, allow_loopback_http: bool) -> None:
    """下载地址必须是 https；测试源模式下额外允许环回 http。"""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if allow_loopback_http and is_loopback_url(url):
        return
    raise ReleaseFeedError("download_url_rejected")


class GitHubReleaseFeed:
    """读取 GitHub Releases 的 `latest` 和提交比较接口；不带任何令牌。"""

    def __init__(
        self,
        api_base: str = GITHUB_API,
        repository: str = RELEASE_REPOSITORY,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self._loopback = is_loopback_url(api_base)
        if not self._loopback and urlsplit(api_base).scheme != "https":
            raise ValueError("发布来源必须是 https 或本机测试源")
        self._api_base = api_base.rstrip("/")
        self._repository = repository
        self._transport = transport
        self._timeout = timeout_seconds

    @classmethod
    def from_environment(cls) -> GitHubReleaseFeed:
        """默认用 GitHub；环境变量只能指向本机测试源，别的地址一律忽略。"""
        override = os.environ.get(FEED_OVERRIDE_ENV, "").strip()
        if override and is_loopback_url(override):
            return cls(override)
        return cls()

    @property
    def allows_loopback_http(self) -> bool:
        return self._loopback

    def latest(self, target: str) -> ReleaseInfo:
        payload = self._get_json(f"/repos/{self._repository}/releases/latest")
        tag = payload.get("tag_name")
        raw_assets = payload.get("assets")
        if not isinstance(tag, str) or not isinstance(raw_assets, list):
            raise ReleaseFeedError("release_invalid")
        assets: dict[str, tuple[str, int]] = {}
        for item in cast(list[object], raw_assets):
            if not isinstance(item, dict):
                continue
            asset = cast(dict[str, object], item)
            name = asset.get("name")
            url = asset.get("browser_download_url")
            size = asset.get("size")
            if isinstance(name, str) and isinstance(url, str) and isinstance(size, int):
                assets[name] = (url, size)
        if RELEASE_METADATA_ASSET not in assets:
            raise ReleaseFeedError("release_metadata_missing")
        metadata = self._metadata(assets[RELEASE_METADATA_ASSET][0])
        if metadata.tag != tag:
            raise ReleaseFeedError("release_invalid")
        expected = metadata.assets.get(target)
        if expected is None or expected.name not in assets:
            raise ReleaseFeedError("platform_not_released")
        url, size = assets[expected.name]
        if size != expected.size:
            raise ReleaseFeedError("release_invalid")
        require_download_url(url, allow_loopback_http=self._loopback)
        published = payload.get("published_at")
        try:
            return ReleaseInfo(
                tag=tag,
                source_revision=metadata.source_revision,
                published_at=datetime.fromisoformat(published)
                if isinstance(published, str)
                else None,
                asset=ReleaseAsset(
                    name=expected.name, url=url, size=expected.size, sha256=expected.sha256
                ),
            )
        except (ValidationError, ValueError) as exc:
            raise ReleaseFeedError("release_invalid") from exc

    def compare(self, current_revision: str, release_revision: str) -> Availability:
        if current_revision == release_revision:
            return Availability.UP_TO_DATE
        try:
            payload = self._get_json(
                f"/repos/{self._repository}/compare/{current_revision}...{release_revision}"
            )
        except ReleaseFeedError:
            return Availability.UNKNOWN
        status = payload.get("status")
        if status == "ahead":
            return Availability.UPDATE_AVAILABLE
        if status == "identical":
            return Availability.UP_TO_DATE
        if status in {"behind", "diverged"}:
            return Availability.UNRELEASED_BUILD
        return Availability.UNKNOWN

    def _client(self) -> httpx.Client:
        return httpx.Client(
            transport=self._transport,
            # 测试源只在本机，不走代理；GitHub 沿用系统代理设置。
            trust_env=not self._loopback,
            follow_redirects=True,
            timeout=self._timeout,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "TunnelMinion-updater",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    def _get_json(self, path: str) -> dict[str, object]:
        try:
            with self._client() as client:
                response = client.get(f"{self._api_base}{path}")
        except httpx.HTTPError as exc:
            raise ReleaseFeedError("network_unreachable") from exc
        if response.status_code == 404:
            raise ReleaseFeedError("no_release")
        if response.status_code in {403, 429}:
            raise ReleaseFeedError("github_rate_limited")
        if response.status_code != 200:
            raise ReleaseFeedError("release_feed_failed")
        try:
            value = response.json()
        except ValueError as exc:
            raise ReleaseFeedError("release_invalid") from exc
        if not isinstance(value, dict):
            raise ReleaseFeedError("release_invalid")
        return cast(dict[str, object], value)

    def _metadata(self, url: str) -> ReleaseMetadata:
        require_download_url(url, allow_loopback_http=self._loopback)
        try:
            with self._client() as client, client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise ReleaseFeedError("release_metadata_missing")
                require_download_url(str(response.url), allow_loopback_http=self._loopback)
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_METADATA_BYTES:
                        raise ReleaseFeedError("release_invalid")
        except httpx.HTTPError as exc:
            raise ReleaseFeedError("network_unreachable") from exc
        try:
            return ReleaseMetadata.model_validate_json(bytes(body))
        except ValidationError as exc:
            raise ReleaseFeedError("release_invalid") from exc
