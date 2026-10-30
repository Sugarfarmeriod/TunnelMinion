"""本机巡检状态与"挂了可以自动修"开关接口。

只挂在本机应用上，由本机请求守卫限制为环回地址和同源请求；Gateway 上没有对应接口，
别的电脑和朋友都改不了这个开关。
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from tunnelminion.domain.service_marks import is_mark_key
from tunnelminion.patrol.contracts import AutoRepairInput, PatrolView, WindowsServiceGrantInput
from tunnelminion.patrol.service import PatrolService


def create_patrol_router(patrol: PatrolService) -> APIRouter:
    router = APIRouter()

    def checked(key: str) -> str:
        if not is_mark_key(key):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "服务身份无效")
        return key

    def view() -> PatrolView:
        return patrol.view()

    def set_auto_repair(key: str, payload: AutoRepairInput) -> PatrolView:
        try:
            return patrol.set_auto_repair(
                checked(key), enabled=payload.enabled, stuck=payload.stuck
            )
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "地图上没有这个服务") from exc
        except LookupError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "这个服务没有现成的修法，不能自动修"
            ) from exc

    async def set_windows_service_grant(key: str, payload: WindowsServiceGrantInput) -> PatrolView:
        try:
            return await patrol.set_windows_service_grant(checked(key), granted=payload.granted)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "这不是 Windows 服务") from exc
        except LookupError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "只有标成“是我的服务”、不是系统或受保护软件的服务才能授权",
            ) from exc
        except PermissionError as exc:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "没有完成管理员确认，权限没有改动"
            ) from exc

    def acknowledge(key: str) -> PatrolView:
        try:
            return patrol.acknowledge(checked(key))
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "巡检没有记录这个服务") from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "这个服务现在没有挂") from exc

    router.add_api_route("/api/patrol", view, methods=["GET"], response_model=PatrolView)
    router.add_api_route(
        "/api/patrol/services/{key}/auto-repair",
        set_auto_repair,
        methods=["PUT"],
        response_model=PatrolView,
    )
    router.add_api_route(
        "/api/patrol/services/{key}/windows-service",
        set_windows_service_grant,
        methods=["PUT"],
        response_model=PatrolView,
    )
    router.add_api_route(
        "/api/patrol/services/{key}/acknowledge",
        acknowledge,
        methods=["POST"],
        response_model=PatrolView,
    )
    return router
