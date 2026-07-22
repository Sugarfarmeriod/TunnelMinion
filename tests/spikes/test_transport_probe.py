# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

import asyncio

from fastapi.testclient import TestClient
from spikes.transport.http_rpc_probe import SPIKE_TOKEN, build_app
from spikes.transport.mcp_probe import build_server, discover_tool_names

from tunnelminion.domain import RunId, ToolRunId


def test_mcp_provides_standard_capability_discovery() -> None:
    names = asyncio.run(discover_tool_names(build_server()))

    assert names == ["get_node_summary"]


def test_http_rpc_rejects_missing_node_authentication() -> None:
    response = TestClient(build_app()).get("/v1/capabilities")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "unauthenticated"


def test_http_rpc_exposes_versioned_capabilities() -> None:
    response = TestClient(build_app()).get(
        "/v1/capabilities", headers={"Authorization": f"Bearer {SPIKE_TOKEN}"}
    )

    assert response.status_code == 200
    assert response.json()["protocol"] == {"major": 1, "minor": 0}
    assert response.json()["tools"][0]["name"] == "get_node_summary"


def test_http_rpc_propagates_trace_identifiers() -> None:
    run_id = str(RunId.new())
    tool_run_id = str(ToolRunId.new())
    response = TestClient(build_app()).post(
        "/v1/tools/get_node_summary:call",
        headers={
            "Authorization": f"Bearer {SPIKE_TOKEN}",
            "X-Run-ID": run_id,
            "X-Tool-Run-ID": tool_run_id,
        },
        json={"arguments": {"node_id": "node_b"}, "timeout_seconds": 1},
    )

    assert response.status_code == 200
    assert response.json() == {
        "run_id": run_id,
        "tool_run_id": tool_run_id,
        "result": {"node_id": "node_b", "status": "online"},
    }
