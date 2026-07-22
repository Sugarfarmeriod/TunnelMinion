"""与传输协议无关的受控 Agent 工具定义。"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from tunnelminion.domain.versioning import ProtocolVersion


class RiskLevel(StrEnum):
    """工具向模型暴露之前必须应用的策略等级。"""

    READ_ONLY = "read-only"
    REQUIRES_APPROVAL = "requires-approval"
    FORBIDDEN = "forbidden"


class Platform(StrEnum):
    """确定性适配器所支持的平台。"""

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"


class DataSensitivity(StrEnum):
    """工具有意返回的数据所允许的最高敏感级别。"""

    PUBLIC = "public"
    SYSTEM_METADATA = "system-metadata"
    SENSITIVE = "sensitive"


class ToolDefinition(BaseModel):
    """独立于 Python 可调用对象和传输协议的版本化工具契约。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    version: ProtocolVersion
    description: str = Field(min_length=1, max_length=500)
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    risk_level: RiskLevel
    platforms: frozenset[Platform] = Field(min_length=1)
    permissions: tuple[str, ...] = ()
    timeout_seconds: float = Field(gt=0, le=300)
    max_result_bytes: int = Field(gt=0, le=10_000_000)
    data_sensitivity: DataSensitivity
