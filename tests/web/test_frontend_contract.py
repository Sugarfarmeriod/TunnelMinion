"""网页严格校验的响应格式必须和后端实际返回的数据一致，否则网页会把整份数据当成格式错误。

网页一侧的格式由 `frontend/src/api/contract/webApiContract.test.ts` 生成快照
`web-api-contract.json`；这里把它和后端 OpenAPI（没有声明响应模型的接口用登记的
pydantic 类型）逐个字段比对，并要求每个本机 `/api` 接口都已在网页一侧登记。
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Literal, TypeAlias, cast

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel, TypeAdapter

from tunnelminion.agent.conversation import (
    CheckedRunView,
    RunEvent,
    RunView,
    ThreadDetail,
    ThreadView,
)
from tunnelminion.app import build_windows_application
from tunnelminion.domain.identifiers import ServiceId
from tunnelminion.macos_app import build_macos_local_application
from tunnelminion.memory.contracts import LongTermMemory
from tunnelminion.web.overview import ProgramResourceOverview

_CONTRACT = Path(__file__).resolve().parents[2] / "frontend/src/api/contract/web-api-contract.json"

Json: TypeAlias = Any
Schema: TypeAlias = Mapping[str, Json]


class _ProgramThreadDetail(ThreadDetail):
    """`/api/ui/threads/{value}` 在线程详情上附带所选程序。"""

    service_id: ServiceId | None


# 路由返回 `model_dump()` 的字典或事件流，OpenAPI 里没有字段；这里登记路由实际序列化的类型。
_UNDECLARED_RESPONSES: dict[str, object] = {
    "GET /api/ui/overview": ProgramResourceOverview,
    "GET /api/threads": list[ThreadView],
    "POST /api/threads": ThreadView,
    "GET /api/threads/{value}": ThreadDetail,
    "GET /api/ui/threads/{value}": _ProgramThreadDetail,
    "POST /api/threads/{value}/runs": RunView,
    "POST /api/ui/threads/{value}/runs": RunView,
    "GET /api/runs/{value}": CheckedRunView,
    "POST /api/runs/{value}/cancel": RunView,
    "GET /api/runs/{value}/events": RunEvent,
    "GET /api/memories": list[LongTermMemory],
    "PUT /api/memories/{value}": LongTermMemory,
}


def _contract() -> dict[str, dict[str, Json]]:
    return cast(dict[str, dict[str, Json]], json.loads(_CONTRACT.read_text(encoding="utf-8")))


def _no_password(*_arguments: object) -> None:
    return None


@pytest.fixture(scope="module")
def applications(tmp_path_factory: pytest.TempPathFactory) -> dict[str, FastAPI]:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("keyring.get_password", _no_password)
        root = tmp_path_factory.mktemp("contract")
        return {
            "windows": build_windows_application(root / "windows").app,
            "macos": build_macos_local_application(root / "macos").app,
        }


def _operations(app: FastAPI) -> Iterator[str]:
    """应用实际挂载的全部 `/api` 接口（含不进 OpenAPI 的），形如 "GET /api/patrol"。"""
    for context in iter_route_contexts(app.routes):
        path = re.sub(r"\{(\w+):\w+\}", r"{\1}", context.path or "")
        if isinstance(context.original_route, APIRoute) and path.startswith("/api/"):
            for method in sorted(set(context.methods or ()) - {"HEAD"}):
                yield f"{method} {path}"


def _response_schema(app: FastAPI, operation: str) -> Schema | None:
    """OpenAPI 里声明了字段的成功响应 schema；没有声明时返回 None。"""
    method, path = operation.split(" ", 1)
    paths = cast(dict[str, dict[str, Json]], app.openapi()["paths"])
    responses = cast(
        dict[str, Json], paths.get(path, {}).get(method.lower(), {}).get("responses", {})
    )
    for code, response in responses.items():
        if code.startswith("2"):
            schema = cast(
                Schema | None,
                response.get("content", {}).get("application/json", {}).get("schema"),
            )
            if schema is not None and _declares_fields(schema):
                return schema
    return None


def _declares_fields(schema: Schema) -> bool:
    if "$ref" in schema or "properties" in schema:
        return True
    items = schema.get("items")
    return isinstance(items, Mapping) and _declares_fields(cast(Schema, items))


# 后端只声明成 `dict[str, str]`、OpenAPI 里没有字段名的对象；键由注明的代码固定组装。
_UNTYPED_OBJECTS = {
    "operationDetailSchema.transitions[]": "OperationDetailView.from_record 固定组装四个键",
}


class _Comparison:
    """把网页格式快照和后端 JSON Schema 递归比对，收集会导致整份拒收的差异。

    后端字段只声明为字符串、没有限定取值时，无法判断网页的枚举是否收全，不报差异。
    """

    def __init__(self, definitions: Mapping[str, Schema]) -> None:
        self.definitions = definitions
        self.problems: list[str] = []
        self.untyped: set[str] = set()

    def resolve(self, schema: Schema) -> Schema:
        while "$ref" in schema:
            schema = self.definitions[str(schema["$ref"]).rsplit("/", 1)[-1]]
        return schema

    def branches(self, schema: Schema) -> tuple[list[Schema], bool]:
        """拆出后端可能返回的各种形状，以及是否可能是 null。"""
        schema = self.resolve(schema)
        options = schema.get("anyOf") or schema.get("oneOf")
        if options is None:
            if schema.get("type") == "null":
                return [], True
            return [schema], False
        found: list[Schema] = []
        nullable = False
        for option in cast(list[Schema], options):
            inner, inner_nullable = self.branches(option)
            found.extend(inner)
            nullable = nullable or inner_nullable
        return found, nullable

    def compare(self, shape: Json, schema: Schema, where: str) -> None:
        if shape == "unknown" or (isinstance(shape, dict) and "catch" in shape):
            return
        options, nullable = self.branches(schema)
        if isinstance(shape, dict) and "nullable" in shape:
            shape = cast(Json, shape["nullable"])
        elif nullable and shape != "null":
            self.problems.append(f"{where}：后端可能返回 null，网页不接受")
        if shape == "null":
            if options:
                self.problems.append(f"{where}：网页只接受 null，后端会返回具体值")
            return
        if not options and not nullable:
            options = [schema]
        for option in options:
            self.compare_one(shape, option, where)

    def compare_one(self, shape: Json, schema: Schema, where: str) -> None:
        if not schema or shape == "unknown":
            return
        if isinstance(shape, dict) and "union" in shape:
            for option in cast(list[Json], shape["union"]):
                attempt = _Comparison(self.definitions)
                attempt.compare(option, schema, where)
                if not attempt.problems:
                    return
            self.problems.append(f"{where}：后端这种形状不匹配网页联合类型的任何分支")
            return
        kind = schema.get("type")
        if isinstance(shape, str):
            self.compare_scalar(shape, schema, where)
        elif "object" in shape:
            self.compare_object(cast(dict[str, Json], shape), schema, where)
        elif "array" in shape:
            if kind != "array":
                self.problems.append(f"{where}：网页要列表，后端给的是 {kind}")
            else:
                items = cast(Schema, schema.get("items", {}))
                self.compare(shape["array"], items, f"{where}[]")
        elif "record" in shape:
            values = schema.get("additionalProperties", {})
            if isinstance(values, Mapping):
                self.compare(shape["record"], cast(Schema, values), f"{where}{{}}")
            for name, field in cast(dict[str, Schema], schema.get("properties", {})).items():
                self.compare(shape["record"], field, f"{where}.{name}")
        else:
            accepted = cast(list[Json], shape["enum"])
            offered = schema.get("enum", [schema["const"]] if "const" in schema else None)
            if offered is None:
                return
            extra = [value for value in cast(list[Json], offered) if value not in accepted]
            if extra:
                self.problems.append(f"{where}：后端可能返回 {extra}，网页只认 {accepted}")

    def compare_scalar(self, shape: str, schema: Schema, where: str) -> None:
        kind = schema.get("type")
        allowed = {
            "string": {"string"},
            "number": {"number", "integer"},
            "boolean": {"boolean"},
        }[shape]
        if kind not in allowed:
            self.problems.append(f"{where}：网页要 {shape}，后端给的是 {kind or schema}")

    def compare_object(self, shape: dict[str, Json], schema: Schema, where: str) -> None:
        if "properties" not in schema:
            if where in _UNTYPED_OBJECTS:
                self.untyped.add(where)
                return
            self.problems.append(f"{where}：网页要固定字段的对象，后端没有声明字段")
            return
        fields = cast(dict[str, Json], shape["object"])
        properties = cast(dict[str, Schema], schema["properties"])
        if shape["strict"]:
            for name in sorted(set(properties) - set(fields)):
                self.problems.append(f"{where}.{name}：后端会返回，网页严格校验没收录，会整份拒收")
        optional = set(cast(list[str], shape["optional"]))
        for name in sorted(set(fields) - set(properties) - optional):
            self.problems.append(f"{where}.{name}：网页要求这个字段，后端不会返回")
        for name in sorted(set(fields) & set(properties)):
            self.compare(fields[name], properties[name], f"{where}.{name}")


def _backend_schema(app: FastAPI, operation: str) -> tuple[Schema, dict[str, Schema]]:
    declared = _response_schema(app, operation)
    if declared is not None:
        components = cast(dict[str, Json], app.openapi().get("components", {}))
        return declared, cast(dict[str, Schema], components.get("schemas", {}))
    produced = TypeAdapter[Json](_UNDECLARED_RESPONSES[operation]).json_schema(mode="serialization")
    return produced, cast(dict[str, Schema], produced.get("$defs", {}))


def test_every_local_api_operation_is_registered_on_the_web(
    applications: dict[str, FastAPI],
) -> None:
    contract = _contract()
    registered = set(contract["responses"]) | set(contract["unparsed"])
    served: set[str] = set()
    for name, app in applications.items():
        operations = set(_operations(app))
        served |= operations
        assert sorted(operations - registered) == [], (
            f"{name} 有网页没登记的接口：请在 webApiContract.ts 的 webResponses 或 "
            "unparsedOperations 登记"
        )
    assert sorted(registered - served) == []
    assert all(reason.strip() for reason in contract["unparsed"].values())


def test_undeclared_responses_list_exactly_the_routes_without_openapi_fields(
    applications: dict[str, FastAPI],
) -> None:
    app = applications["windows"]
    undeclared = {
        operation
        for operation in _contract()["responses"]
        if _response_schema(app, operation) is None
    }
    assert undeclared == set(_UNDECLARED_RESPONSES)


@pytest.mark.parametrize("platform", ["windows", "macos"])
def test_web_response_schemas_match_backend_fields(
    applications: dict[str, FastAPI], platform: str
) -> None:
    app = applications[platform]
    contract = _contract()
    served = set(_operations(app))
    problems: list[str] = []
    untyped: set[str] = set()
    for operation, name in sorted(contract["responses"].items()):
        if operation not in served:
            continue
        schema, definitions = _backend_schema(app, operation)
        comparison = _Comparison(definitions)
        comparison.compare(contract["schemas"][name], schema, name)
        problems.extend(f"{operation} {problem}" for problem in comparison.problems)
        untyped |= comparison.untyped
    assert problems == []
    assert untyped == set(_UNTYPED_OBJECTS)


class _Endpoint(BaseModel):
    port: int
    note: str | None = None
    state: Literal["running", "stopped"] = "running"


class _Service(BaseModel):
    key: str
    windows_service: bool = False
    endpoints: tuple[_Endpoint, ...] = ()


def _problems(shape: Json, model: type[BaseModel]) -> list[str]:
    schema = TypeAdapter[Json](model).json_schema(mode="serialization")
    comparison = _Comparison(cast(dict[str, Schema], schema.get("$defs", {})))
    comparison.compare(shape, schema, "service")
    return comparison.problems


def _object(
    fields: dict[str, Json], *, strict: bool = True, optional: tuple[str, ...] = ()
) -> Json:
    return {"object": fields, "strict": strict, "optional": list(optional)}


_ENDPOINT: Json = _object(
    {"port": "number", "note": {"nullable": "string"}, "state": {"enum": ["running", "stopped"]}}
)


def test_comparison_accepts_a_matching_shape() -> None:
    shape = _object(
        {"key": "string", "windows_service": "boolean", "endpoints": {"array": _ENDPOINT}}
    )
    assert _problems(shape, _Service) == []


def test_comparison_reports_every_kind_of_whole_payload_rejection() -> None:
    endpoint = _object(
        {"port": "string", "note": "string", "state": {"enum": ["running"]}, "extra": "string"},
        optional=("extra",),
    )
    shape = _object({"key": "string", "endpoints": {"array": endpoint}, "owner": "string"})
    assert _problems(shape, _Service) == [
        "service.windows_service：后端会返回，网页严格校验没收录，会整份拒收",
        "service.owner：网页要求这个字段，后端不会返回",
        "service.endpoints[].note：后端可能返回 null，网页不接受",
        "service.endpoints[].port：网页要 string，后端给的是 integer",
        "service.endpoints[].state：后端可能返回 ['stopped']，网页只认 ['running']",
    ]


def test_comparison_tolerates_lenient_web_shapes() -> None:
    endpoint = _object(
        {"port": {"union": ["string", "number"]}, "state": {"catch": {"enum": []}}}, strict=False
    )
    shape = _object(
        {"key": "unknown", "windows_service": "boolean", "endpoints": {"array": endpoint}}
    )
    assert _problems(shape, _Service) == []
    mismatched = _object({"key": {"union": ["number", "boolean"]}}, strict=False)
    assert _problems(mismatched, _Service) == [
        "service.key：后端这种形状不匹配网页联合类型的任何分支"
    ]
