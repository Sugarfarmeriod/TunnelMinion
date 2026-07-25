"""隔离 HTTP fixture、内嵌代理与崩溃恢复标记的技术验证。"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import shutil
import socket
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

PROBE_TOKEN = "probe-only-token"  # nosec: 只用于隔离技术验证
PROBE_OWNER_PREFIX = "tmn_probe_"
DEFAULT_UPSTREAM_PORT = 18880
DEFAULT_PROXY_PORT = 18881
MAX_PROBE_RESPONSE_BYTES = 64 * 1024


class ProbeConfig(BaseModel):
    """HTTP 代理验证的受控配置。"""

    model_config = ConfigDict(extra="forbid")

    bind_host: str
    bind_port: int = Field(ge=1024, le=65535)
    allowed_bind_hosts: frozenset[str]
    upstream_url: str
    token: str
    timeout_seconds: float = Field(gt=0, le=5)
    max_response_bytes: int = Field(gt=0, le=MAX_PROBE_RESPONSE_BYTES)


class ProbeLease(BaseModel):
    """独立恢复器可以读取的非秘密验证租约。"""

    model_config = ConfigDict(extra="forbid")

    owner_id: str
    bind_host: str
    bind_port: int
    process_id: int = Field(gt=0)


class RecoveryResult(BaseModel):
    """租约恢复验证结果。"""

    recovered: bool
    reason: str


class ProxyOption(BaseModel):
    """代理候选的可验证比较项。"""

    name: str
    available: bool
    packaged_with_project: bool
    explicit_lifecycle: bool
    extra_system_config: bool
    note: str


def validate_bind_host(host: str, allowed_hosts: frozenset[str]) -> None:
    """只允许显式列出的非通配私网地址。"""
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_loopback or not address.is_private:
        raise ValueError("代理入口必须绑定显式非环回私网地址")
    if host not in allowed_hosts:
        raise ValueError("代理入口地址不在允许的 WireGuard 地址集合中")


def build_upstream_fixture() -> FastAPI:
    """创建只监听环回地址的隔离 HTTP fixture。"""
    app = FastAPI(title="TunnelMinion 临时共享上游验证")

    @app.api_route("/fixture/{path:path}", methods=["GET", "POST"])
    async def fixture(path: str, request: Request) -> dict[str, object]:
        return {
            "path": path,
            "method": request.method,
            "body": (await request.body()).decode(errors="replace"),
        }

    _ = fixture
    return app


def build_proxy_app(
    config: ProbeConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """创建带短期凭据和响应预算的内嵌 HTTP 代理原型。"""
    validate_bind_host(config.bind_host, config.allowed_bind_hosts)
    app = FastAPI(title="TunnelMinion 临时共享代理验证")

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def proxy(path: str, request: Request) -> Response:
        if request.headers.get("X-TunnelMinion-Share-Token") != config.token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": {"code": "invalid_share_token"}},
            )
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "content-length", "x-tunnelminion-share-token"}
        }
        async with httpx.AsyncClient(
            transport=transport,
            timeout=config.timeout_seconds,
            trust_env=False,
        ) as client:
            upstream = await client.request(
                request.method,
                f"{config.upstream_url.rstrip('/')}/{path}",
                content=await request.body(),
                headers=headers,
            )
        if len(upstream.content) > config.max_response_bytes:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"error": {"code": "upstream_response_too_large"}},
            )
        response_headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower() not in {"content-length", "connection", "transfer-encoding"}
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
            media_type=upstream.headers.get("content-type"),
        )

    _ = proxy
    return app


def compare_proxy_options() -> tuple[ProxyOption, ...]:
    """记录本机可验证的内嵌与外部代理候选。"""
    external = tuple(name for name in ("caddy", "nginx", "traefik") if shutil.which(name))
    return (
        ProxyOption(
            name="embedded-fastapi-httpx",
            available=True,
            packaged_with_project=True,
            explicit_lifecycle=True,
            extra_system_config=False,
            note="复用现有依赖，适合首个有界 HTTP 纵向切片",
        ),
        ProxyOption(
            name="managed-external-proxy",
            available=bool(external),
            packaged_with_project=False,
            explicit_lifecycle=False,
            extra_system_config=True,
            note=(
                f"本机发现：{', '.join(external)}"
                if external
                else "本机未发现 Caddy、Nginx 或 Traefik"
            ),
        ),
    )


def write_probe_lease(path: Path, lease: ProbeLease) -> None:
    """原子写入不含凭据的验证租约。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(lease.model_dump_json(), encoding="utf-8")
    temporary.replace(path)


def recover_stale_probe_lease(path: Path, *, active_process_ids: frozenset[int]) -> RecoveryResult:
    """只清理属于验证原型且进程已经消失的租约标记。"""
    if not path.exists():
        return RecoveryResult(recovered=False, reason="lease_missing")
    lease = ProbeLease.model_validate_json(path.read_text(encoding="utf-8"))
    if not lease.owner_id.startswith(PROBE_OWNER_PREFIX):
        return RecoveryResult(recovered=False, reason="foreign_owner")
    if lease.process_id in active_process_ids:
        return RecoveryResult(recovered=False, reason="process_active")
    path.unlink()
    return RecoveryResult(recovered=True, reason="stale_probe_lease_removed")


def _port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        try:
            candidate.bind((host, port))
        except OSError:
            return False
    return True


def _run_server(server: uvicorn.Server) -> None:
    server.run()


def _wait_until_ready(url: str, headers: dict[str, str] | None = None) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, headers=headers, timeout=0.2, trust_env=False)
            if response.status_code < 500:
                return
        except httpx.HTTPError:
            time.sleep(0.05)
    raise RuntimeError(f"验证服务未在截止时间内启动：{url}")


def run_network_probe(bind_host: str, lease_path: Path) -> dict[str, Any]:
    """在专用端口运行真实网络代理验证并清理全部临时进程。"""
    validate_bind_host(bind_host, frozenset({bind_host}))
    if not _port_available("127.0.0.1", DEFAULT_UPSTREAM_PORT):
        raise RuntimeError(f"fixture 端口被占用：{DEFAULT_UPSTREAM_PORT}")
    if not _port_available(bind_host, DEFAULT_PROXY_PORT):
        raise RuntimeError(f"代理端口被占用：{DEFAULT_PROXY_PORT}")

    upstream = uvicorn.Server(
        uvicorn.Config(
            build_upstream_fixture(),
            host="127.0.0.1",
            port=DEFAULT_UPSTREAM_PORT,
            log_level="error",
        )
    )
    config = ProbeConfig(
        bind_host=bind_host,
        bind_port=DEFAULT_PROXY_PORT,
        allowed_bind_hosts=frozenset({bind_host}),
        upstream_url=f"http://127.0.0.1:{DEFAULT_UPSTREAM_PORT}",
        token=PROBE_TOKEN,
        timeout_seconds=2,
        max_response_bytes=MAX_PROBE_RESPONSE_BYTES,
    )
    proxy = uvicorn.Server(
        uvicorn.Config(
            build_proxy_app(config),
            host=bind_host,
            port=DEFAULT_PROXY_PORT,
            log_level="error",
        )
    )
    threads = (
        threading.Thread(target=_run_server, args=(upstream,), daemon=True),
        threading.Thread(target=_run_server, args=(proxy,), daemon=True),
    )
    for thread in threads:
        thread.start()
    try:
        _wait_until_ready(f"http://127.0.0.1:{DEFAULT_UPSTREAM_PORT}/fixture/ready")
        _wait_until_ready(
            f"http://{bind_host}:{DEFAULT_PROXY_PORT}/fixture/ready",
            {"X-TunnelMinion-Share-Token": PROBE_TOKEN},
        )
        denied = httpx.get(
            f"http://{bind_host}:{DEFAULT_PROXY_PORT}/fixture/denied",
            timeout=2,
            trust_env=False,
        )
        allowed = httpx.post(
            f"http://{bind_host}:{DEFAULT_PROXY_PORT}/fixture/allowed",
            headers={"X-TunnelMinion-Share-Token": PROBE_TOKEN},
            content=b"probe",
            timeout=2,
            trust_env=False,
        )
        write_probe_lease(
            lease_path,
            ProbeLease(
                owner_id=f"{PROBE_OWNER_PREFIX}network",
                bind_host=bind_host,
                bind_port=DEFAULT_PROXY_PORT,
                process_id=999_999_999,
            ),
        )
        recovery = recover_stale_probe_lease(lease_path, active_process_ids=frozenset())
        return {
            "schema_version": 1,
            "bind_host": bind_host,
            "upstream": f"127.0.0.1:{DEFAULT_UPSTREAM_PORT}",
            "proxy": f"{bind_host}:{DEFAULT_PROXY_PORT}",
            "unauthenticated_status": denied.status_code,
            "authenticated_status": allowed.status_code,
            "authenticated_body": allowed.json(),
            "stale_lease_recovered": recovery.recovered,
            "proxy_options": [item.model_dump(mode="json") for item in compare_proxy_options()],
            "excluded": ["share_token", "authorization_headers"],
        }
    finally:
        proxy.should_exit = True
        upstream.should_exit = True
        for thread in threads:
            thread.join(timeout=5)
        if lease_path.exists():
            lease_path.unlink()


async def _exercise_asgi_proxy() -> dict[str, object]:
    upstream = build_upstream_fixture()
    transport = httpx.ASGITransport(app=upstream)
    config = ProbeConfig(
        bind_host="10.77.0.2",
        bind_port=DEFAULT_PROXY_PORT,
        allowed_bind_hosts=frozenset({"10.77.0.2"}),
        upstream_url="http://fixture",
        token=PROBE_TOKEN,
        timeout_seconds=1,
        max_response_bytes=MAX_PROBE_RESPONSE_BYTES,
    )
    proxy_transport = httpx.ASGITransport(app=build_proxy_app(config, transport=transport))
    async with httpx.AsyncClient(transport=proxy_transport, base_url="http://proxy") as client:
        denied = await client.get("/fixture/denied")
        allowed = await client.post(
            "/fixture/allowed",
            headers={"X-TunnelMinion-Share-Token": PROBE_TOKEN},
            content=b"probe",
        )
    return {
        "unauthenticated_status": denied.status_code,
        "authenticated_status": allowed.status_code,
        "authenticated_body": allowed.json(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """运行无网络或真实 WireGuard 地址的代理验证。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-host")
    parser.add_argument("--lease-path", type=Path, default=Path(".data/http-sharing-probe.json"))
    args = parser.parse_args(argv)
    result = (
        run_network_probe(args.bind_host, args.lease_path)
        if args.bind_host
        else {
            "schema_version": 1,
            "asgi": asyncio.run(_exercise_asgi_proxy()),
            "proxy_options": [item.model_dump(mode="json") for item in compare_proxy_options()],
        }
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
