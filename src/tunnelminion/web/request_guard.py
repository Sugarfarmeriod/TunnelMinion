"""本机 Web 的 Host 与同源写请求守卫。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import AddressValueError, IPv6Address
from typing import cast

from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_FETCH_METADATA_PREFIX = b"sec-fetch-"
_LOOPBACK_IPV4 = "127.0.0.1"
_LOOPBACK_IPV6 = "::1"
_REQUEST_HEADER = "x-tunnelminion-request"
_REQUEST_HEADER_VALUE = "same-origin"


class LocalRequestErrorCode(StrEnum):
    """在客户端与契约测试中保持稳定的本机请求拒绝原因。"""

    INVALID_HOST = "invalid_host"
    CROSS_SITE_REQUEST = "cross_site_request"
    INVALID_ORIGIN = "invalid_origin"
    REQUEST_HEADER_REQUIRED = "request_header_required"
    INVALID_REQUEST_HEADER = "invalid_request_header"


_ERROR_MESSAGES = {
    LocalRequestErrorCode.INVALID_HOST: "请求 Host 不是当前端口上的受信环回地址",
    LocalRequestErrorCode.CROSS_SITE_REQUEST: "拒绝跨站浏览器写请求",
    LocalRequestErrorCode.INVALID_ORIGIN: "浏览器写请求 Origin 与当前本机来源不一致",
    LocalRequestErrorCode.REQUEST_HEADER_REQUIRED: "浏览器写请求缺少 TunnelMinion 同源请求头",
    LocalRequestErrorCode.INVALID_REQUEST_HEADER: "TunnelMinion 同源请求头无效",
}


@dataclass(frozen=True, slots=True)
class _Authority:
    host: str
    port: int


class LocalWebRequestGuardMiddleware:
    """在任何 FastAPI 路由或领域服务执行前校验本机请求。"""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        error = _request_error(scope)
        if error is None:
            await self._app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=403,
            content={
                "detail": {
                    "code": error.value,
                    "message": _ERROR_MESSAGES[error],
                }
            },
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )
        await response(scope, receive, send)


def install_local_request_guard(app: FastAPI) -> None:
    """把本机请求守卫安装到 FastAPI 应用的路由层之外。"""
    app.add_middleware(LocalWebRequestGuardMiddleware)


def _request_error(scope: Scope) -> LocalRequestErrorCode | None:
    headers = Headers(scope=scope)
    trusted_origin = _trusted_origin(scope, headers)
    if trusted_origin is None:
        return LocalRequestErrorCode.INVALID_HOST

    method = str(scope.get("method", "")).upper()
    if method in _SAFE_METHODS:
        return None

    origin_values = headers.getlist("origin")
    has_fetch_metadata = any(
        name.lower().startswith(_FETCH_METADATA_PREFIX) for name, _value in headers.raw
    )
    if not origin_values and not has_fetch_metadata:
        return None

    if any(value.strip().lower() == "cross-site" for value in headers.getlist("sec-fetch-site")):
        return LocalRequestErrorCode.CROSS_SITE_REQUEST

    scheme, authority = trusted_origin
    if len(origin_values) != 1 or not _origin_matches(
        origin_values[0],
        scheme=scheme,
        authority=authority,
    ):
        return LocalRequestErrorCode.INVALID_ORIGIN

    request_headers = headers.getlist(_REQUEST_HEADER)
    if not request_headers:
        return LocalRequestErrorCode.REQUEST_HEADER_REQUIRED
    if len(request_headers) != 1 or request_headers[0] != _REQUEST_HEADER_VALUE:
        return LocalRequestErrorCode.INVALID_REQUEST_HEADER
    return None


def _trusted_origin(scope: Scope, headers: Headers) -> tuple[str, _Authority] | None:
    scheme = str(scope.get("scheme", "")).lower()
    default_port = _default_port(scheme)
    server_value: object = scope.get("server")
    if default_port is None or not isinstance(server_value, (tuple, list)):
        return None
    server = cast(tuple[object, ...] | list[object], server_value)
    if len(server) != 2:
        return None
    server_port = server[1]
    if type(server_port) is not int or not 1 <= server_port <= 65535:
        return None

    host_values = headers.getlist("host")
    if len(host_values) != 1:
        return None
    authority = _parse_authority(host_values[0], default_port=default_port)
    if authority is None or authority.port != server_port:
        return None
    return scheme, authority


def _origin_matches(value: str, *, scheme: str, authority: _Authority) -> bool:
    if value != value.strip():
        return False
    origin_scheme, separator, origin_authority = value.partition("://")
    if separator != "://" or origin_scheme.lower() != scheme:
        return False
    parsed = _parse_authority(
        origin_authority,
        default_port=_default_port(scheme),
    )
    return parsed == authority


def _parse_authority(value: str, *, default_port: int | None) -> _Authority | None:
    if (
        not value
        or value != value.strip()
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
        or any(character in value for character in "/?#@\\")
    ):
        return None

    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1:
            return None
        host = value[1:closing]
        suffix = value[closing + 1 :]
        port = _parse_port_suffix(suffix, default_port=default_port)
        if port is None or not _is_ipv6_loopback(host):
            return None
        return _Authority(host=_LOOPBACK_IPV6, port=port)

    if "[" in value or "]" in value:
        return None
    host, separator, port_text = value.rpartition(":")
    if not separator:
        host = value
        port = default_port
    else:
        port = _parse_explicit_port(port_text)
    if port is None or ":" in host:
        return None

    normalized_host = host.lower()
    if normalized_host == "localhost":
        return _Authority(host=normalized_host, port=port)
    if normalized_host == _LOOPBACK_IPV4:
        return _Authority(host=normalized_host, port=port)
    return None


def _parse_port_suffix(suffix: str, *, default_port: int | None) -> int | None:
    if not suffix:
        return default_port
    if not suffix.startswith(":"):
        return None
    return _parse_explicit_port(suffix[1:])


def _parse_explicit_port(value: str) -> int | None:
    if not value.isascii() or not value.isdecimal():
        return None
    port = int(value)
    return port if 1 <= port <= 65535 else None


def _is_ipv6_loopback(value: str) -> bool:
    """只接受 IPv6 loopback 的压缩或完整等价文本，不接受 zone ID。"""
    if "%" in value:
        return False
    try:
        address = IPv6Address(value)
    except AddressValueError:
        return False
    return address == IPv6Address(_LOOPBACK_IPV6)


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None
