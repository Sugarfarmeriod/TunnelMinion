"""本机 Web 使用的强类型、脱敏诊断下载契约。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from tunnelminion import __version__
from tunnelminion.domain.tools import Platform
from tunnelminion.network.contracts import ProviderKind
from tunnelminion.web.overview import (
    CoordinatorOverviewState,
    EvidenceStatus,
    ModelStatus,
    NetworkPathOverviewState,
    OverviewError,
    OverviewFreshness,
    ResourceOverview,
    RuntimePackageKind,
    RuntimeReadiness,
    RuntimeState,
)

StableDiagnosticCode = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_-]*$"),
]


class OverviewProvider(Protocol):
    """诊断导出只依赖已经脱敏的总览读模型。"""

    def view(self) -> ResourceOverview: ...


class DiagnosticError(BaseModel):
    """只公开稳定码和是否值得重试。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: StableDiagnosticCode
    retryable: bool = False


class DiagnosticRuntimeSummary(BaseModel):
    """本机运行状态，不包含安装路径、进程参数或环境变量。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime: RuntimeState
    platform: Platform | None = None
    readiness: RuntimeReadiness
    freshness: OverviewFreshness
    package_kind: RuntimePackageKind
    manifest_schema: str | None = Field(
        default=None,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9-]*/v[1-9][0-9]*$",
    )
    error: OverviewError | None = None


class DiagnosticModelSummary(BaseModel):
    """模型只导出是否配置和健康状态，不导出 endpoint、模型名或密钥。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool | None
    status: ModelStatus
    freshness: OverviewFreshness
    error: OverviewError | None = None


class DiagnosticCoordinatorSummary(BaseModel):
    """控制面摘要不包含 endpoint、验证 key 或认证材料。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool | None
    state: CoordinatorOverviewState
    freshness: OverviewFreshness
    revision: int | None = Field(default=None, ge=0)
    last_success_at: AwareDatetime | None = None
    error: OverviewError | None = None


class DiagnosticNetworkEvidence(BaseModel):
    """只保留网络证据结论和时间，不导出 route、地址或 peer key。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: EvidenceStatus
    observed_at: AwareDatetime | None = None


class DiagnosticNetworkPathSummary(BaseModel):
    """网络路径摘要把 handshake、route 与真实探测分开表达。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool | None
    state: NetworkPathOverviewState
    provider: ProviderKind | None = None
    revision: int | None = Field(default=None, ge=0)
    freshness: OverviewFreshness
    handshake: DiagnosticNetworkEvidence
    route: DiagnosticNetworkEvidence
    probe: DiagnosticNetworkEvidence
    error: OverviewError | None = None


class DiagnosticOverviewSummary(BaseModel):
    """总览 allowlist；节点/服务正文与标识符不会进入诊断包。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime: DiagnosticRuntimeSummary
    model: DiagnosticModelSummary
    coordinator: DiagnosticCoordinatorSummary
    network_path: DiagnosticNetworkPathSummary
    known_node_count: int = Field(ge=0, le=200)
    known_service_count: int = Field(ge=0, le=1024)


class OptionalDiagnosticSourceName(StrEnum):
    """首版只声明两个非产品依赖的可选来源。"""

    FIREWALL_LOGGING = "firewall_logging"
    VENDOR_VPN_CLI = "vendor_vpn_cli"


class OptionalDiagnosticSourceStatus(StrEnum):
    """可选来源缺失不是产品故障。"""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class OptionalDiagnosticSource(BaseModel):
    """可选来源只公开能力状态，不公开规则、日志或工具输出。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: OptionalDiagnosticSourceName
    required: Literal[False] = False
    status: OptionalDiagnosticSourceStatus
    evidence_at: AwareDatetime | None = None
    error: DiagnosticError | None = None


class DiagnosticRecoveryStep(BaseModel):
    """不包含设备路径、秘密或可直接改系统的命令。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: StableDiagnosticCode
    title: str = Field(min_length=1, max_length=80)
    instruction: str = Field(min_length=1, max_length=500)


class ExcludedDiagnosticCategory(StrEnum):
    """明确记录不会进入下载的敏感类别。"""

    MODEL_API_KEYS = "model_api_keys"
    GATEWAY_TOKENS = "gateway_tokens"
    WIREGUARD_SECRETS = "wireguard_secrets"
    AUTHORIZATION_HEADERS = "authorization_headers"
    ENROLLMENT_TOKENS = "coordinator_enrollment_tokens"
    REFRESH_CREDENTIALS = "coordinator_refresh_credentials"
    ACCESS_ASSERTIONS = "coordinator_access_assertions"
    FIREWALL_RULES = "raw_firewall_rules"
    FIREWALL_LOGS = "raw_firewall_logs"
    VPN_OUTPUT = "raw_vendor_vpn_output"
    PROCESS_ARGUMENTS = "process_arguments"
    FILESYSTEM_PATHS = "filesystem_paths"
    REMOTE_BODIES = "remote_response_bodies"


class DiagnosticProduct(BaseModel):
    """产品身份不包含构建主机或签名材料。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["tunnelminion"] = "tunnelminion"
    version: str = Field(min_length=1, max_length=64)


class DiagnosticsExport(BaseModel):
    """浏览器下载的完整强类型诊断包。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["diagnostics-export/v1"] = "diagnostics-export/v1"
    generated_at: AwareDatetime
    product: DiagnosticProduct
    overview: DiagnosticOverviewSummary
    optional_sources: tuple[OptionalDiagnosticSource, ...] = Field(max_length=2)
    recovery_steps: tuple[DiagnosticRecoveryStep, ...] = Field(max_length=8)
    warnings: tuple[DiagnosticError, ...] = Field(default=(), max_length=8)
    excluded_categories: tuple[ExcludedDiagnosticCategory, ...]


_MISSING_SOURCE_CODES = {
    OptionalDiagnosticSourceName.FIREWALL_LOGGING: "firewall_logging_unavailable",
    OptionalDiagnosticSourceName.VENDOR_VPN_CLI: "vendor_vpn_cli_unavailable",
}
_FAILED_SOURCE_CODES = {
    OptionalDiagnosticSourceName.FIREWALL_LOGGING: "firewall_logging_status_unknown",
    OptionalDiagnosticSourceName.VENDOR_VPN_CLI: "vendor_vpn_cli_status_unknown",
}
_RECOVERY_STEPS = (
    DiagnosticRecoveryStep(
        code="check_local_runtime",
        title="先确认本机程序",
        instruction="先确认 TunnelMinion 本机程序仍在运行，再刷新页面查看最新状态。",
    ),
    DiagnosticRecoveryStep(
        code="verify_peer_with_real_request",
        title="用真实请求判断 peer",
        instruction=(
            "从另一台机器实际访问目标服务；若仍失败，再请设备管理员检查客户自己的防火墙或 VPN。"
        ),
    ),
    DiagnosticRecoveryStep(
        code="optional_logs_do_not_block",
        title="可选日志不阻塞使用",
        instruction=(
            "看不到防火墙日志或厂商 VPN 工具没关系；核心功能继续可用，"
            "需要排障时再由管理员授权查看。"
        ),
    ),
)
_EXCLUDED_CATEGORIES = tuple(ExcludedDiagnosticCategory)


class _Utf8JsonResponse(JSONResponse):
    """下载文件显式声明 UTF-8，避免平台按本地编码猜测。"""

    media_type = "application/json; charset=utf-8"


class DiagnosticsExportService:
    """从公开总览与可选状态 callback 生成 allowlist 下载。"""

    def __init__(
        self,
        overview: OverviewProvider,
        *,
        firewall_logging: Callable[[], object] | None = None,
        vendor_vpn_cli: Callable[[], object] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._overview = overview
        self._providers = {
            OptionalDiagnosticSourceName.FIREWALL_LOGGING: firewall_logging,
            OptionalDiagnosticSourceName.VENDOR_VPN_CLI: vendor_vpn_cli,
        }
        self._clock = clock or (lambda: datetime.now(UTC))

    def build(self) -> DiagnosticsExport:
        """生成下载；任一可选来源失败只产生 unknown 记录。"""
        generated_at = self._now()
        warnings: tuple[DiagnosticError, ...] = ()
        try:
            overview = self._overview.view()
        except Exception:
            from tunnelminion.web.overview import OverviewService

            overview = OverviewService(clock=lambda: generated_at).view()
            warnings = (DiagnosticError(code="overview_unavailable", retryable=True),)
        return DiagnosticsExport(
            generated_at=generated_at,
            product=DiagnosticProduct(version=__version__),
            overview=self._summarize(overview),
            optional_sources=tuple(
                self._resolve_source(source, self._providers[source])
                for source in OptionalDiagnosticSourceName
            ),
            recovery_steps=_RECOVERY_STEPS,
            warnings=warnings,
            excluded_categories=_EXCLUDED_CATEGORIES,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("诊断导出时钟必须包含时区")
        return value.astimezone(UTC)

    @staticmethod
    def _resolve_source(
        source: OptionalDiagnosticSourceName,
        provider: Callable[[], object] | None,
    ) -> OptionalDiagnosticSource:
        if provider is None:
            return OptionalDiagnosticSource(
                source=source,
                status=OptionalDiagnosticSourceStatus.UNAVAILABLE,
                error=DiagnosticError(code=_MISSING_SOURCE_CODES[source]),
            )
        try:
            value = OptionalDiagnosticSource.model_validate(provider())
            if value.source is not source:
                raise ValueError("可选诊断来源与 callback 不匹配")
            return value
        except Exception:
            return OptionalDiagnosticSource(
                source=source,
                status=OptionalDiagnosticSourceStatus.UNKNOWN,
                error=DiagnosticError(code=_FAILED_SOURCE_CODES[source], retryable=True),
            )

    @staticmethod
    def _summarize(value: ResourceOverview) -> DiagnosticOverviewSummary:
        network = value.network_path
        return DiagnosticOverviewSummary(
            runtime=DiagnosticRuntimeSummary(
                runtime=value.local.runtime,
                platform=value.local.platform,
                readiness=value.local.readiness,
                freshness=value.local.freshness,
                package_kind=value.local.package.kind,
                manifest_schema=value.local.package.manifest_schema,
                error=value.local.error,
            ),
            model=DiagnosticModelSummary(
                configured=value.model.configured,
                status=value.model.status,
                freshness=value.model.freshness,
                error=value.model.error,
            ),
            coordinator=DiagnosticCoordinatorSummary(
                configured=value.coordinator.configured,
                state=value.coordinator.state,
                freshness=value.coordinator.freshness,
                revision=value.coordinator.revision,
                last_success_at=value.coordinator.last_success_at,
                error=value.coordinator.error,
            ),
            network_path=DiagnosticNetworkPathSummary(
                configured=network.configured,
                state=network.state,
                provider=network.provider,
                revision=network.revision,
                freshness=network.freshness,
                handshake=DiagnosticNetworkEvidence(
                    status=network.handshake.status,
                    observed_at=network.handshake.observed_at,
                ),
                route=DiagnosticNetworkEvidence(
                    status=network.route.status,
                    observed_at=network.route.observed_at,
                ),
                probe=DiagnosticNetworkEvidence(
                    status=network.probe.status,
                    observed_at=network.probe.observed_at,
                ),
                error=network.error,
            ),
            known_node_count=len(value.nodes.items),
            known_service_count=len(value.services.items),
        )


def create_diagnostics_router(service: DiagnosticsExportService) -> APIRouter:
    """创建带下载头、禁缓存和稳定失败码的本机只读路由。"""
    router = APIRouter()

    def export_diagnostics() -> Response:
        try:
            payload = service.build()
        except Exception as exc:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"code": "diagnostics_export_failed", "retryable": True},
            ) from exc
        stamp = payload.generated_at.strftime("%Y%m%dT%H%M%SZ")
        return _Utf8JsonResponse(
            content=payload.model_dump(mode="json"),
            headers={
                "Content-Disposition": (
                    f'attachment; filename="tunnelminion-diagnostics-{stamp}.json"'
                ),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    router.add_api_route(
        "/api/diagnostics/export",
        export_diagnostics,
        methods=["GET"],
        response_model=DiagnosticsExport,
        responses={
            status.HTTP_500_INTERNAL_SERVER_ERROR: {
                "description": "诊断包无法构造",
            }
        },
    )
    return router
