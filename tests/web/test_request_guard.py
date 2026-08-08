"""本机 Web 请求守卫的安全契约测试。"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from typing import Protocol, Self, cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient
from starlette.types import Message, Receive, Scope, Send

from tunnelminion.web.request_guard import (
    LocalWebRequestGuardMiddleware,
    install_local_request_guard,
)

HeadersInput = dict[str, str] | Sequence[tuple[str, str]]


class ApiClient(Protocol):
    """屏蔽 TestClient 当前缺失的严格类型标注。"""

    def __enter__(self) -> Self: ...

    def __exit__(self, *args: object) -> None: ...

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeadersInput | None = None,
    ) -> httpx.Response: ...


def _build_client(calls: list[str], *, base_url: str = "http://localhost:8765") -> ApiClient:
    app = FastAPI()

    async def target() -> dict[str, str]:
        calls.append("target")
        return {"status": "ok"}

    async def events() -> StreamingResponse:
        async def body() -> AsyncIterator[str]:
            yield "data: ok\n\n"

        calls.append("events")
        return StreamingResponse(body(), media_type="text/event-stream")

    app.add_api_route(
        "/target",
        target,
        methods=["GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"],
    )
    app.add_api_route("/events", events, methods=["GET"])
    install_local_request_guard(app)
    return cast(ApiClient, TestClient(app, base_url=base_url))


def _error_code(response: httpx.Response) -> str:
    body = cast(dict[str, object], response.json())
    detail = cast(dict[str, object], body["detail"])
    return cast(str, detail["code"])


def _invoke_scope(scope: Scope) -> tuple[list[Message], list[str]]:
    messages: list[Message] = []
    calls: list[str] = []

    async def downstream(_scope: Scope, _receive: Receive, _send: Send) -> None:
        calls.append("downstream")

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    middleware = LocalWebRequestGuardMiddleware(downstream)
    asyncio.run(middleware(scope, receive, send))
    return messages, calls


@pytest.mark.parametrize(
    "host",
    [
        "localhost:8765",
        "LOCALHOST:8765",
        "127.0.0.1:8765",
        "[::1]:8765",
        "[0:0:0:0:0:0:0:1]:8765",
    ],
)
def test_get_accepts_normalized_loopback_hosts(host: str) -> None:
    calls: list[str] = []
    with _build_client(calls) as client:
        response = client.request("GET", "/target", headers={"host": host})
    assert response.status_code == 200
    assert calls == ["target"]


@pytest.mark.parametrize(
    "host",
    [
        "example.test:8765",
        "localhost:9999",
        "127.0.0.2:8765",
        "::1:8765",
        "[::2]:8765",
        "localhost.:8765",
        "localhost:",
        "localhost:not-a-port",
        "localhost:0",
        "localhost:65536",
        "[::1]garbage",
        "[]:8765",
        "[::1:8765",
        "local[host]:8765",
        "localhost/path:8765",
        "[::1%lo0]:8765",
        "[bad]:8765",
    ],
)
def test_invalid_or_wrong_port_host_is_rejected_before_route(host: str) -> None:
    calls: list[str] = []
    with _build_client(calls) as client:
        response = client.request("GET", "/target", headers={"host": host})
    assert response.status_code == 403
    assert _error_code(response) == "invalid_host"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in response.headers
    assert calls == []


def test_duplicate_host_has_highest_error_priority() -> None:
    calls: list[str] = []
    headers = [
        ("host", "localhost:8765"),
        ("host", "127.0.0.1:8765"),
        ("origin", "https://attacker.test"),
        ("sec-fetch-site", "cross-site"),
    ]
    with _build_client(calls) as client:
        response = client.request("POST", "/target", headers=headers)
    assert _error_code(response) == "invalid_host"
    assert calls == []


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (
            {
                "origin": "https://attacker.test",
                "sec-fetch-site": " Cross-Site ",
            },
            "cross_site_request",
        ),
        ({"sec-fetch-site": "same-site"}, "invalid_origin"),
        ({"sec-fetch-mode": "cors"}, "invalid_origin"),
        (
            {
                "origin": "http://127.0.0.1:8765",
                "sec-fetch-site": "same-origin",
            },
            "invalid_origin",
        ),
        (
            {
                "origin": "http://localhost:8765",
                "sec-fetch-site": "same-origin",
            },
            "request_header_required",
        ),
        (
            {
                "origin": "http://localhost:8765",
                "sec-fetch-site": "same-origin",
                "x-tunnelminion-request": "forged",
            },
            "invalid_request_header",
        ),
    ],
)
def test_browser_write_error_priority(headers: dict[str, str], expected: str) -> None:
    calls: list[str] = []
    with _build_client(calls) as client:
        response = client.request("POST", "/target", headers=headers)
    assert response.status_code == 403
    assert _error_code(response) == expected
    assert "access-control-allow-origin" not in response.headers
    assert calls == []


@pytest.mark.parametrize(
    "origin",
    [
        " http://localhost:8765",
        "https://localhost:8765",
        "http://localhost:8765/",
        "http://localhost:8765?query",
        "http://user@localhost:8765",
        "null",
        "http://",
        "http://localhost:not-a-port",
    ],
)
def test_malformed_or_non_matching_origin_is_rejected(origin: str) -> None:
    calls: list[str] = []
    headers = {
        "origin": origin,
        "sec-fetch-site": "same-origin",
        "x-tunnelminion-request": "same-origin",
    }
    with _build_client(calls) as client:
        response = client.request("DELETE", "/target", headers=headers)
    assert _error_code(response) == "invalid_origin"
    assert calls == []


def test_duplicate_origin_and_request_header_are_rejected() -> None:
    calls: list[str] = []
    common = [("sec-fetch-site", "same-origin")]
    with _build_client(calls) as client:
        duplicate_origin = client.request(
            "POST",
            "/target",
            headers=[
                *common,
                ("origin", "http://localhost:8765"),
                ("origin", "http://localhost:8765"),
                ("x-tunnelminion-request", "same-origin"),
            ],
        )
        duplicate_request_header = client.request(
            "POST",
            "/target",
            headers=[
                *common,
                ("origin", "http://localhost:8765"),
                ("x-tunnelminion-request", "same-origin"),
                ("x-tunnelminion-request", "same-origin"),
            ],
        )
    assert _error_code(duplicate_origin) == "invalid_origin"
    assert _error_code(duplicate_request_header) == "invalid_request_header"
    assert calls == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_same_origin_browser_unsafe_requests_reach_route_once(method: str) -> None:
    calls: list[str] = []
    headers = {
        "origin": "http://LOCALHOST:8765",
        "sec-fetch-site": "same-origin",
        "x-tunnelminion-request": "same-origin",
    }
    with _build_client(calls) as client:
        response = client.request(method, "/target", headers=headers)
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert calls == ["target"]


def test_cli_without_origin_or_fetch_metadata_remains_compatible() -> None:
    calls: list[str] = []
    with _build_client(calls) as client:
        response = client.request(
            "POST",
            "/target",
            headers={"x-tunnelminion-request": "ignored-for-cli"},
        )
    assert response.status_code == 200
    assert calls == ["target"]


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE"])
def test_safe_methods_only_require_valid_host(method: str) -> None:
    calls: list[str] = []
    headers = {
        "origin": "https://attacker.test",
        "sec-fetch-site": "cross-site",
        "x-tunnelminion-request": "forged",
    }
    with _build_client(calls) as client:
        response = client.request(method, "/target", headers=headers)
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert calls == ["target"]


def test_sse_get_only_requires_valid_host() -> None:
    calls: list[str] = []
    with _build_client(calls) as client:
        response = client.request(
            "GET",
            "/events",
            headers={"origin": "https://attacker.test", "sec-fetch-site": "cross-site"},
        )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text == "data: ok\n\n"
    assert calls == ["events"]


def test_default_http_and_https_ports_are_normalized() -> None:
    http_calls: list[str] = []
    https_calls: list[str] = []
    browser_headers = {
        "origin": "https://localhost",
        "sec-fetch-site": "same-origin",
        "x-tunnelminion-request": "same-origin",
    }
    with _build_client(http_calls, base_url="http://localhost") as client:
        http_response = client.request("GET", "/target", headers={"host": "[::1]"})
    with _build_client(https_calls, base_url="https://localhost") as client:
        https_response = client.request("POST", "/target", headers=browser_headers)
    assert http_response.status_code == https_response.status_code == 200
    assert http_calls == https_calls == ["target"]


@pytest.mark.parametrize(
    ("scheme", "server"),
    [
        ("ftp", ("localhost", 8765)),
        ("http", None),
        ("http", ("localhost",)),
        ("http", ("localhost", "8765")),
        ("http", ("localhost", 0)),
    ],
)
def test_invalid_asgi_listener_metadata_fails_closed(scheme: str, server: object) -> None:
    scope = cast(
        Scope,
        {
            "type": "http",
            "scheme": scheme,
            "method": "GET",
            "server": server,
            "headers": [(b"host", b"localhost:8765")],
        },
    )
    messages, calls = _invoke_scope(scope)
    assert messages[0]["type"] == "http.response.start"
    assert messages[0]["status"] == 403
    assert b"invalid_host" in cast(bytes, messages[1]["body"])
    assert calls == []


def test_non_http_asgi_scope_passes_through() -> None:
    scope = cast(Scope, {"type": "websocket"})
    messages, calls = _invoke_scope(scope)
    assert messages == []
    assert calls == ["downstream"]
