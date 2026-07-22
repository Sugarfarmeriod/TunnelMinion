"""仅供本机面板使用的模型配置 API。"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, HTTPException, Response, status

from tunnelminion.model.configuration import (
    ModelConfigurationInput,
    ModelConfigurationService,
    ModelConfigurationView,
)
from tunnelminion.model.contracts import ProviderError


def _http_error(error: ProviderError, status_code: int) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code, "message": str(error), "retryable": error.retryable},
    )


def create_model_router(service: ModelConfigurationService) -> APIRouter:
    """创建模型配置与降级状态路由。"""
    router = APIRouter(prefix="/api")

    def get_model_config() -> ModelConfigurationView:
        return service.view()

    async def put_model_config(value: ModelConfigurationInput) -> ModelConfigurationView:
        try:
            return await service.configure(value)
        except ProviderError as exc:
            raise _http_error(exc, status.HTTP_422_UNPROCESSABLE_CONTENT) from exc

    async def validate_model_config() -> ModelConfigurationView:
        try:
            return await service.validate()
        except ProviderError as exc:
            raise _http_error(exc, status.HTTP_409_CONFLICT) from exc

    def delete_model_config() -> Response:
        service.delete()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    def check_ai_run_availability() -> dict[str, bool]:
        try:
            service.require_available()
        except ProviderError as exc:
            raise _http_error(exc, status.HTTP_503_SERVICE_UNAVAILABLE) from exc
        return {"available": True}

    def resource_health() -> dict[str, str]:
        return {"status": "available"}

    router.add_api_route(
        "/model-config",
        get_model_config,
        methods=["GET"],
        response_model=ModelConfigurationView,
    )
    router.add_api_route(
        "/model-config",
        put_model_config,
        methods=["PUT"],
        response_model=ModelConfigurationView,
    )
    router.add_api_route(
        "/model-config/validate",
        validate_model_config,
        methods=["POST"],
        response_model=ModelConfigurationView,
    )
    router.add_api_route(
        "/model-config",
        delete_model_config,
        methods=["DELETE"],
        status_code=status.HTTP_204_NO_CONTENT,
    )
    router.add_api_route(
        "/ai/runs/availability",
        check_ai_run_availability,
        methods=["POST"],
    )
    router.add_api_route("/resources/health", resource_health, methods=["GET"])

    return router


def create_local_app(service: ModelConfigurationService) -> FastAPI:
    """组装只应绑定环回地址的本地应用。"""
    app = FastAPI(title="TunnelMinion")
    app.include_router(create_model_router(service))
    return app
