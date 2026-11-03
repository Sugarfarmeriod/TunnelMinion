"""本机网页的版本与更新接口。

只挂在本机应用上，由本机请求守卫限制为环回地址和同源请求；网关上没有对应接口，
别的电脑和朋友都触发不了更新。
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from tunnelminion.update.service import UpdateRejected, UpdateService, UpdateView

_MESSAGES = {
    "read_only_preview": "预览模式不能更新",
    "source_run": "从源码运行，不支持一键更新，请用 git pull",
    "no_runtime_profile": "不是用 runtime start 启动的，不支持一键更新",
    "unsupported_platform": "这个平台没有发布运行包",
    "update_in_progress": "已经有一次更新在进行",
    "release_changed": "最新版本刚刚变了，请重新检查后再确认",
    "already_current": "已经是最新版本",
    "current_is_newer": "当前版本比最新发布版还新，不需要更新",
}


class UpdateApplyInput(BaseModel):
    """确认更新时带上刚才检查到的版本号，防止点的和换的不是同一个。"""

    model_config = ConfigDict(extra="forbid")

    release_tag: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")


def create_update_router(service: UpdateService) -> APIRouter:
    router = APIRouter()

    def rejected(exc: UpdateRejected) -> HTTPException:
        return HTTPException(
            status.HTTP_409_CONFLICT,
            {"code": exc.code, "message": _MESSAGES.get(exc.code, "现在不能更新，请稍后重试")},
        )

    def view() -> UpdateView:
        return service.view()

    def check() -> UpdateView:
        try:
            return service.check()
        except UpdateRejected as exc:
            raise rejected(exc) from exc

    def apply(payload: UpdateApplyInput) -> UpdateView:
        try:
            return service.start_update(payload.release_tag)
        except UpdateRejected as exc:
            raise rejected(exc) from exc

    router.add_api_route("/api/update", view, methods=["GET"], response_model=UpdateView)
    router.add_api_route("/api/update/check", check, methods=["POST"], response_model=UpdateView)
    router.add_api_route(
        "/api/update/apply",
        apply,
        methods=["POST"],
        response_model=UpdateView,
        status_code=status.HTTP_202_ACCEPTED,
    )
    return router
