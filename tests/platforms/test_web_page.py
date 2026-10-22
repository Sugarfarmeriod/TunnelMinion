"""在本机访问首页，判断是不是网页并读出标题。"""

from __future__ import annotations

import gzip
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tunnelminion.platforms import web_page
from tunnelminion.platforms.web_page import WebPage, clean_title, probe_host, probe_web_page


@dataclass
class Reply:
    """本地测试服务器对某个路径的固定回复。"""

    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict[str, str])


class Site:
    """按路径返回固定内容的本地网页服务器。"""

    def __init__(self) -> None:
        self.replies: dict[str, Reply] = {}
        self.paths: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site.paths.append(self.path)
                reply = site.replies.get(self.path, Reply(404, b"missing"))
                self.send_response(reply.status)
                for key, value in reply.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(reply.body)))
                self.end_headers()
                self.wfile.write(reply.body)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site() -> Iterator[Site]:
    value = Site()
    yield value
    value.close()


HTML = {"Content-Type": "text/html; charset=utf-8"}


def test_html_page_gives_its_title(site: Site) -> None:
    site.replies["/"] = Reply(
        body="<html><title> WireGuard &amp; 面板 </title></html>".encode(), headers=HTML
    )
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title="WireGuard & 面板")
    assert probe_web_page("0.0.0.0", site.port) == WebPage(title="WireGuard & 面板")


def test_page_without_content_type_is_recognised_by_its_start(site: Site) -> None:
    site.replies["/"] = Reply(body=b"  <!DOCTYPE html><title>x</title>")
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title="x")


def test_follows_same_host_redirect_to_login_page(site: Site) -> None:
    site.replies["/"] = Reply(302, headers={"Location": "/login?next=/"})
    site.replies["/login"] = Reply(body=b"<title>Sign in</title>", headers=HTML)
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title="Sign in")
    assert site.paths == ["/", "/login"]


def test_redirect_chain_is_bounded(site: Site) -> None:
    site.replies["/"] = Reply(302, headers={"Location": "/a"})
    site.replies["/a"] = Reply(302, headers={"Location": "/b"})
    site.replies["/b"] = Reply(302, headers={"Location": ""}, body=b"<html>moved</html>")
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title=None)
    assert site.paths == ["/", "/a", "/b"]


def test_redirect_to_another_host_is_not_followed(site: Site) -> None:
    site.replies["/"] = Reply(302, headers={"Location": "http://example.com/", **HTML})
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title=None)
    assert site.paths == ["/"]


def test_browser_login_prompt_counts_as_a_page(site: Site) -> None:
    site.replies["/"] = Reply(
        401,
        body=b'{"error":"Unauthorized"}',
        headers={"Content-Type": "application/json", "WWW-Authenticate": 'Basic realm="x"'},
    )
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title=None)


def test_error_pages_count_as_pages_but_lend_no_title(site: Site) -> None:
    site.replies["/"] = Reply(401, body=b"<title>401 Authorization Required</title>", headers=HTML)
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title=None)


@pytest.mark.parametrize(
    "reply",
    [
        Reply(200, b'{"ok":true}', {"Content-Type": "application/json"}),
        Reply(500, b"<html>boom</html>", HTML),
        Reply(401, b'{"error":"unauthorized"}', {"Content-Type": "application/json"}),
    ],
)
def test_apis_and_broken_servers_are_not_pages(site: Site, reply: Reply) -> None:
    site.replies["/"] = reply
    assert probe_web_page("127.0.0.1", site.port) is None


def test_gzip_only_pages_are_decompressed(site: Site) -> None:
    site.replies["/"] = Reply(
        body=gzip.compress(b"<html><title>Model UI</title></html>"),
        headers={**HTML, "Content-Encoding": "gzip"},
    )
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title="Model UI")


def test_broken_gzip_reads_as_empty(site: Site) -> None:
    site.replies["/"] = Reply(body=b"\x1f\x8b broken", headers={**HTML, "Content-Encoding": "gzip"})
    assert probe_web_page("127.0.0.1", site.port) == WebPage(title=None)


def test_plain_http_rejected_by_https_port_tries_https(site: Site) -> None:
    # 本地服务器不会 TLS，所以 HTTPS 那次失败；重点是 HTTP 的 400 提示不被当成网页。
    site.replies["/"] = Reply(
        400, b"<title>400 The plain HTTP request was sent to HTTPS port</title>", HTML
    )
    assert probe_web_page("127.0.0.1", site.port) is None


def test_closed_ports_and_public_addresses_are_not_probed() -> None:
    assert probe_web_page("127.0.0.1", 1, timeout=0.2) is None
    assert probe_web_page("8.8.8.8", 80) is None


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("0.0.0.0", "127.0.0.1"),
        ("::", "::1"),
        ("127.0.0.1", "127.0.0.1"),
        ("10.77.0.1", "10.77.0.1"),
        ("8.8.8.8", None),
        ("not-an-ip", None),
    ],
)
def test_probe_host(address: str, expected: str | None) -> None:
    assert probe_host(address) == expected


def test_title_cleaning() -> None:
    assert clean_title(b"<TITLE lang=en>\n  a \t b\x07 </TITLE>") == "a b"
    assert clean_title(b"<title>" + "长".encode() * 100 + b"</title>") == "长" * 60
    assert clean_title(b"<title>   </title>") is None
    assert clean_title(b"<html>no title</html>") is None
    assert clean_title("<title>页面</title>".encode("gbk"), "gbk") == "页面"
    assert clean_title(b"<title>ok</title>", "no-such-charset") == "ok"


def test_unverified_context_accepts_self_signed_certificates() -> None:
    context = web_page._unverified_context()  # pyright: ignore[reportPrivateUsage]
    assert context.check_hostname is False
