"""委派使用被委派电脑的修复存储，发起电脑只能收到无路径的摘要。"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from tests.agent.test_langchain_agent import ScriptedProvider
from tests.gateway.test_api import call_payload
from tests.gateway.test_delegation import real_agent
from tests.repair.factories import NODE, NOW, plan
from tests.repair.fakes import (
    FakeContainers,
    FakeHost,
    FakeLauncher,
    FakeVerifier,
    MemoryRepairStore,
)
from tests.repair.test_agent_tools import TOOL_NAMES

from tunnelminion.agent.delegation import DelegationService, current_delegation
from tunnelminion.app import build_windows_application, build_windows_gateway_application
from tunnelminion.domain.delegation import (
    DelegationProposedRepair,
    DelegationRequest,
    DelegationResult,
    DelegationStatus,
)
from tunnelminion.domain.identifiers import DelegationId, NodeId, OperationId
from tunnelminion.domain.tools import Platform
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewayPeerConfig,
    GatewayPeerInput,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
)
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.macos_app import build_macos_gateway_application, build_macos_local_application
from tunnelminion.memory.sqlite import SQLiteStores
from tunnelminion.model.contracts import CancellationToken, ModelRequest, ModelResponse, ToolCall
from tunnelminion.repair.agent_tools import proposed_repairs_for_delegation
from tunnelminion.repair.contracts import (
    REPAIR_TOOL_NAMES,
    RepairOrigin,
    RepairOriginKind,
    RepairRecord,
)
from tunnelminion.repair.local import build_local_repair_service

CALLER = NodeId("node_" + "2" * 32)
TOKEN = "tmn_" + "a" * 40


class ProposalProvider(ScriptedProvider):
    async def complete(
        self, request: ModelRequest, cancellation: CancellationToken | None = None
    ) -> ModelResponse:
        self.requests.append(request)
        if len(self.requests) == 1:
            assert "propose_repair" in {item.name for item in request.tools}
            assert not set(REPAIR_TOOL_NAMES.values()) & {item.name for item in request.tools}
            return ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="proposal",
                        name="propose_repair",
                        arguments={
                            "service_key": "docker:compose:photos",
                            "kind": "restart_containers",
                            "reason": "容器已经退出；docker rm photos; rm -rf /",
                        },
                    ),
                )
            )
        return ModelResponse(content="这台电脑提出了重启相册的修法，正在等本机批准。")


def configure(root: Path) -> None:
    service = GatewayConfigurationService(
        FileGatewayConfigurationRepository(root / "gateway.json"),
        configure_gateway_secret_store(root, GatewaySecretStoreKind.RESTRICTED_FILE),
    )
    service.configure_local(GatewayBindConfig(host="10.77.0.5"))
    service.provision_peer(
        GatewayPeerInput(
            peer=GatewayPeerConfig(
                node_id=CALLER,
                platform=Platform.WINDOWS,
                host="10.77.0.1",
                allowed_tools=frozenset({*TOOL_NAMES, *REPAIR_TOOL_NAMES.values()}),
                allow_delegation=True,
            ),
            token=TOKEN,
        )
    )


@pytest.mark.parametrize("platform", (Platform.WINDOWS, Platform.MACOS))
def test_gateway_delegation_builds_local_repairs_without_exposing_tools_or_remote_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: Platform
) -> None:
    containers, host, launcher, verifier = (
        FakeContainers(),
        FakeHost(),
        FakeLauncher(),
        FakeVerifier(),
    )

    def fake_containers(*_args: object) -> FakeContainers:
        return containers

    def fake_host(*_args: object) -> FakeHost:
        return host

    def no_secret(*_args: object) -> None:
        return None

    monkeypatch.setattr("tunnelminion.repair.local.DockerContainerRuntime", fake_containers)
    monkeypatch.setattr("tunnelminion.repair.local.PsutilHostInspector", fake_host)
    monkeypatch.setattr("tunnelminion.repair.local.BackgroundProcessLauncher", lambda: launcher)
    monkeypatch.setattr("tunnelminion.repair.local.SocketLocalVerifier", lambda: verifier)
    monkeypatch.setattr("keyring.get_password", no_secret)
    providers: list[ProposalProvider] = []

    def provider(_self: object) -> ProposalProvider:
        value = ProposalProvider()
        providers.append(value)
        return value

    monkeypatch.setattr(
        "tunnelminion.model.configuration.ModelConfigurationService.create_provider", provider
    )
    configure(tmp_path)
    gateway = (
        build_windows_gateway_application(tmp_path)
        if platform is Platform.WINDOWS
        else build_macos_gateway_application(tmp_path)
    )
    delegation_service = gateway.delegation_service
    assert delegation_service is not None

    async def scenario() -> tuple[DelegationId, OperationId]:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway.app),
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {TOKEN}"},
        ) as client:
            capabilities = await client.get("/v1/capabilities")
            assert capabilities.status_code == 200 and capabilities.json()["tools"] == []
            for name in (*TOOL_NAMES, *REPAIR_TOOL_NAMES.values()):
                payload, _, _ = call_payload(CALLER)
                denied = await client.post(f"/v1/tools/{name}:call", json=payload)
                assert denied.status_code == (403 if name in TOOL_NAMES else 404)
            submitted = await client.post(
                "/v1/delegations",
                json={"caller_node_id": str(CALLER), "question": "相册为什么打不开？"},
            )
            assert submitted.status_code == 202
            delegation_id = DelegationId(submitted.json()["delegation_id"])
            await delegation_service.wait(delegation_id)
            assert current_delegation.get() is None
            response = await client.get(f"/v1/delegations/{delegation_id}")
            body = response.json()
            assert body["status"] == "completed", body
            repairs = body["result"]["proposed_repairs"]
            assert len(repairs) == 1
            summary = repairs[0]
            assert set(summary) == {
                "repair_id",
                "service_name",
                "action",
                "status",
                "how_to_approve",
                "expires_at",
            }
            assert summary["status"] == "awaiting_authorization"
            assert summary["how_to_approve"].startswith("请到这台电脑本机上运行：")
            assert "--data-dir" not in response.text and str(tmp_path) not in response.text
            repair_id = OperationId(summary["repair_id"])
            for prefix in ("/v1/repairs", "/api/repairs"):
                for action in ("approve", "execute"):
                    denied = await client.post(f"{prefix}/{repair_id}/{action}", json={})
                    assert denied.status_code == 404
            payload, _, _ = call_payload(CALLER)
            payload.update(
                operation_id=str(repair_id),
                plan_version=1,
                idempotency_key="opkey_" + "0" * 64,
                request_node_id=str(CALLER),
                target_node_id=str(gateway.node_id),
                tool_run_ids=[],
            )
            payload.pop("arguments")
            payload.pop("timeout_seconds")
            payload.pop("tool_version")
            payload.pop("tool_run_id")
            payload.pop("caller_node_id")
            denied = await client.post("/v1/operations:execute", json=payload)
            assert denied.status_code == 404
            return delegation_id, repair_id

    delegation_id, repair_id = asyncio.run(scenario())
    assert not containers.calls and not launcher.calls
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    record = stores.repairs.get(repair_id)
    assert record is not None
    assert record.plan.node_id == gateway.node_id
    assert record.plan.origin.kind is RepairOriginKind.DELEGATION
    assert record.plan.origin.delegation_id == delegation_id
    assert record.plan.origin.thread_id is not None and record.plan.origin.run_id is not None
    assert record.audit[0].actor == f"delegation:{CALLER}"
    assert record.plan.reason == "容器已经退出；docker rm photos; rm -rf /"
    assert record.authorization is None and record.execution is None
    # 命令行和网页重新打开同一节点目录，能看见网关进程生成的记录。
    assert build_local_repair_service(tmp_path, platform=platform).get(repair_id) == record
    local = (
        build_windows_application(tmp_path)
        if platform is Platform.WINDOWS
        else build_macos_local_application(tmp_path)
    )
    client: Any = TestClient(local.app, base_url="http://127.0.0.1")
    assert client.get(f"/api/repairs/{repair_id}").status_code == 200
    approved = client.post(f"/api/repairs/{repair_id}/approve")
    assert approved.status_code == 202 and approved.json()["status"] == "authorized"
    assert client.get(f"/api/repairs/{repair_id}").json()["status"] == "succeeded"
    assert containers.calls == [("start", ("a" * 64,))]
    assert not launcher.calls
    assert len(providers[0].requests) == 2


def test_delegation_query_filters_origin_limits_count_and_never_exports_local_details() -> None:
    store = MemoryRepairStore()
    delegation_id = DelegationId.new()
    for index in range(6):
        origin = RepairOrigin(
            kind=RepairOriginKind.CONVERSATION if index == 4 else RepairOriginKind.DELEGATION,
            delegation_id=DelegationId.new() if index == 5 else delegation_id,
        )
        item = plan().model_copy(
            update={"origin": origin, "created_at": NOW + timedelta(minutes=index)}
        )
        store.put(RepairRecord.planned(item, actor="agent"))
    repairs = proposed_repairs_for_delegation(store, delegation_id)
    assert len(repairs) == 3
    assert [item.expires_at for item in repairs] == [
        NOW + timedelta(minutes=index + 10) for index in (3, 2, 1)
    ]
    assert proposed_repairs_for_delegation(store, DelegationId.new()) == ()
    for repair in repairs:
        assert "--data-dir" not in repair.how_to_approve
        assert "argv" not in repair.model_dump_json()


def test_delegation_result_defaults_and_service_limit_query_output(tmp_path: Path) -> None:
    item = DelegationProposedRepair(
        repair_id=OperationId.new(),
        service_name="相册",
        action="重启容器",
        status="awaiting_authorization",
        how_to_approve="请到这台电脑本机上批准",
        expires_at=NOW,
    )
    fields: dict[str, Any] = {
        "summary": "查完了",
        "stop_reason": "completed",
        "model_rounds": 1,
        "tool_calls": 0,
        "elapsed_ms": 1,
    }
    assert DelegationResult.model_validate(fields).proposed_repairs == ()
    with pytest.raises(ValidationError):
        DelegationResult.model_validate({**fields, "proposed_repairs": [item] * 4})
    stores = SQLiteStores.open(tmp_path / "runtime.sqlite3")
    queries: list[DelegationId] = []

    def query(delegation_id: DelegationId) -> tuple[DelegationProposedRepair, ...]:
        queries.append(delegation_id)
        return (item,) * 4

    async def scenario() -> None:
        service = DelegationService(
            NODE, stores.delegations, real_agent, lambda: ("probe_service",), repair_query=query
        )
        record = service.submit(DelegationRequest(caller_node_id=CALLER, question="服务是否存在？"))
        await service.wait(record.delegation_id)
        final = service.get(record.delegation_id, CALLER)
        assert final is not None and final.status is DelegationStatus.COMPLETED
        assert final.result is not None and final.result.proposed_repairs == (item,) * 3
        assert queries == [record.delegation_id]

    asyncio.run(scenario())
