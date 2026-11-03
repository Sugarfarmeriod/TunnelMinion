"""首页服务项的字段必须都写进网页的严格校验，否则网页会把整份服务清单当成格式错误。"""

import re
from pathlib import Path

from tunnelminion.web.service_map import LocalServiceMap, ServiceEndpoint, ServiceEntry

_FRONTEND_API = Path(__file__).resolve().parents[2] / "frontend/src/features/service-map/api.ts"


def _schema_keys(name: str) -> set[str]:
    source = _FRONTEND_API.read_text(encoding="utf-8")
    match = re.search(rf"export const {name} = z\s*\.object\(\{{(.*?)\n  \}}\)", source, re.S)
    assert match is not None, name
    return set(re.findall(r"^\s{4}(\w+):", match.group(1), re.M))


def test_frontend_service_schemas_list_every_backend_field() -> None:
    assert _schema_keys("serviceEntrySchema") == set(ServiceEntry.model_fields)
    assert _schema_keys("serviceEndpointSchema") == set(ServiceEndpoint.model_fields)
    assert _schema_keys("localServicesSchema") == set(LocalServiceMap.model_fields)
