"""每次 HTTP 请求重新取凭据，名单不同步时只重试一次。"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field

import httpx

from tunnelminion.domain.trust import PassScope
from tunnelminion.gateway.contracts import GatewayErrorCode, GatewayErrorResponse


@dataclass(frozen=True)
class GatewayCredentials:
    """凭据和同步函数只留在服务端，repr 不展开闭包。"""

    provide: Callable[[PassScope], str] = field(repr=False)
    synchronize: Callable[[], Awaitable[None]] = field(repr=False)
    source_host: str | None = None


GatewayCredential = str | GatewayCredentials


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
        request.headers["Authorization"] = f"Bearer {self._credentials.provide(scope)}"
        response = yield request
        if response.status_code != 401:
            return
        await response.aread()
        if len(response.content) > 512_000:
            return
        try:
            error = GatewayErrorResponse.model_validate_json(response.content)
        except ValueError:
            return
        if error.error.code is not GatewayErrorCode.TRUST_SYNC_REQUIRED:
            return
        await self._credentials.synchronize()
        request.headers["Authorization"] = f"Bearer {self._credentials.provide(scope)}"
        yield request
