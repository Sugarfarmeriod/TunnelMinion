"""在本机访问一个监听端口的首页，判断它是不是网页，并读出网页标题。

只发一次 `GET /`（最多跟随两次同一主机内的跳转），最多读 16KB，单次超时 1 秒。
只访问本机或私有地址；HTTPS 证书不做校验，因为本机服务大多用自签名证书。
只依赖标准库，评测脚本可以把本文件单独复制到其他电脑上使用。
"""

from __future__ import annotations

import html
import http.client
import ipaddress
import re
import ssl
import zlib
from dataclasses import dataclass
from urllib.parse import urlsplit

_MAX_BYTES = 16 * 1024
_MAX_TITLE = 60
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CHARSET = re.compile(r"charset=([\w-]+)", re.IGNORECASE)
_REDIRECTS = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class WebPage:
    """一个能在浏览器里打开的页面；`title` 只在正常页面（状态码小于 400）时给出。"""

    title: str | None


def probe_host(address: str) -> str | None:
    """监听地址对应的本机访问地址；公网地址不访问。"""
    if address == "0.0.0.0":
        return "127.0.0.1"
    if address == "::":
        return "::1"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    return address if parsed.is_loopback or parsed.is_private else None


def clean_title(raw: bytes, charset: str = "utf-8") -> str | None:
    """取出 <title> 文字：解码实体、合并空白、去掉控制字符，最长 60 字。"""
    match = _TITLE.search(raw)
    if match is None:
        return None
    try:
        text = match.group(1).decode(charset, errors="replace")
    except LookupError:
        text = match.group(1).decode("utf-8", errors="replace")
    text = " ".join(html.unescape(text).split())
    text = "".join(char for char in text if char.isprintable())
    return text[:_MAX_TITLE].strip() or None


def _looks_like_html(content_type: str, body: bytes) -> bool:
    head = body.lstrip()[:64].lower()
    return "html" in content_type.lower() or head.startswith((b"<!doctype html", b"<html"))


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _decompress(body: bytes, encoding: str) -> bytes:
    # 有的服务只提供压缩后的页面；截断的数据也能解出开头部分，标题通常就在开头。
    if encoding.strip().lower() != "gzip":
        return body
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, _MAX_BYTES)
    except zlib.error:
        return b""


@dataclass(frozen=True)
class _Response:
    status: int
    content_type: str
    location: str | None
    # 回复里要求浏览器弹出登录框（HTTP 认证），在浏览器里打开就是一个登录页。
    asks_browser_login: bool
    body: bytes


def _fetch(host: str, port: int, secure: bool, path: str, timeout: float) -> _Response:
    connection: http.client.HTTPConnection = (
        http.client.HTTPSConnection(host, port, timeout=timeout, context=_unverified_context())
        if secure
        else http.client.HTTPConnection(host, port, timeout=timeout)
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": "TunnelMinion",
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
            },
        )
        response = connection.getresponse()
        body = _decompress(response.read(_MAX_BYTES), response.getheader("Content-Encoding") or "")
        return _Response(
            status=response.status,
            content_type=response.getheader("Content-Type") or "",
            location=response.getheader("Location"),
            asks_browser_login=response.status == 401
            and response.getheader("WWW-Authenticate") is not None,
            body=body,
        )
    finally:
        connection.close()


def _fetch_home(host: str, port: int, secure: bool, timeout: float) -> _Response:
    """取首页；只跟随同一主机内的相对跳转（例如 / → /login），最多两次。"""
    path = "/"
    for _ in range(2):
        response = _fetch(host, port, secure, path, timeout)
        target = urlsplit(response.location or "")
        if response.status not in _REDIRECTS or not response.location or target.netloc:
            return response
        path = target.path or "/"
    return _fetch(host, port, secure, path, timeout)


def probe_web_page(address: str, port: int, *, timeout: float = 1.0) -> WebPage | None:
    """访问首页；是网页时返回 WebPage，不是网页或连不上时返回 None。"""
    host = probe_host(address)
    if host is None:
        return None
    for secure in (False, True):
        try:
            response = _fetch_home(host, port, secure, timeout)
        except (OSError, http.client.HTTPException):
            # 普通 HTTP 连 HTTPS 端口通常会在这里失败，换 HTTPS 再试一次。
            continue
        if response.status == 400 and not secure and b"https" in response.body.lower():
            continue
        if response.asks_browser_login:
            return WebPage(title=None)
        if response.status >= 500 or not _looks_like_html(response.content_type, response.body):
            return None
        match = _CHARSET.search(response.content_type)
        charset = match.group(1) if match else "utf-8"
        title = clean_title(response.body, charset) if response.status < 400 else None
        return WebPage(title=title)
    return None
