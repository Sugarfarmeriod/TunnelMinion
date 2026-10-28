"""每次 HTTP 请求重新取凭据，名单不同步时只重试一次。"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field

import httpx

from tunnelminion.domain.trust import PassScope
from tunnelminion.gateway.contracts import (
    GatewayErrorCode,
    GatewayErrorResponse,
    parse_peer_response,
)


@dataclass(frozen=True)
class GatewayCredentials:
    """凭据和同步函数只留在服务端，repr 不展开闭包。"""

    provide: Callable[[PassScope], str] = field(repr=False)
    synchronize: Callable[[], Awaitable[None]] = field(repr=False)
    source_host: str | None = None


GatewayCredential = str | GatewayCredentials


class GatewayCredentialError(httpx.RequestError):
    """本机签不出通行证（例如本机刚被移出我的电脑）；调用方按"请求没能发出"处理。"""


class GatewayRequestAuth(httpx.Auth):
    """重试前交换已签名名单，再签一张新通行证。"""

    def __init__(self, credentials: GatewayCredentials) -> None:
        self._credentials = credentials

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        scope = (
            PassScope.OPERATION_GATEWAY
            if request.url.path.startswith("/v1/operations")
            else PassScope.TOOL_GATEWAY
        )
        request.headers["Authorization"] = f"Bearer {self._pass(request, scope)}"
        response = yield request
        if response.status_code != 401:
            return
        await response.aread()
        if len(response.content) > 512_000:
            return
        try:
            error = parse_peer_response(GatewayErrorResponse, response.content)
        except ValueError:
            return
        if error.error.code is not GatewayErrorCode.TRUST_SYNC_REQUIRED:
            return
        try:
            await self._credentials.synchronize()
        except Exception:
            # 同步失败时保留第一次的 401，调用方照常得到"认证失败"。
            return
        request.headers["Authorization"] = f"Bearer {self._pass(request, scope)}"
        yield request

    def _pass(self, request: httpx.Request, scope: PassScope) -> str:
        try:
            return self._credentials.provide(scope)
        except Exception:
            raise GatewayCredentialError("本机无法签发通行证", request=request) from None
