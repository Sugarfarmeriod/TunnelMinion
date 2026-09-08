import {
  expect,
  test,
  type APIRequestContext,
  type Route,
} from "@playwright/test";

import { resourceOverviewSchema } from "../src/api/schemas/overview";
import {
  makeOperationDetail,
  makeOperationListItem,
  makeOperationSummary,
} from "../src/features/operations/testFixtures";

const localNodeId = `node_${"1".repeat(32)}`;
const remoteNodeId = `node_${"2".repeat(32)}`;
const serviceId = `service_${"3".repeat(32)}`;
const incidentId = `incident_${"4".repeat(32)}`;
const snapshotA = `snapshot_${"5".repeat(32)}`;
const snapshotB = `snapshot_${"6".repeat(32)}`;
const createdOperationId = `operation_${"7".repeat(32)}`;
const observedAt = "2026-09-08T09:00:00+08:00";

async function fulfillJson(route: Route, payload: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(payload),
  });
}

async function remoteIncidentOverview(request: APIRequestContext) {
  const response = await request.get("/api/resources/overview");
  const overview = resourceOverviewSchema.parse(await response.json());
  overview.nodes.items = [
    {
      node_id: localNodeId,
      display_name: "本机",
      platform: "windows",
      state: "local",
      source: "local_observation",
      evidence_at: observedAt,
      freshness: "live",
      service_count: 0,
    },
    {
      node_id: remoteNodeId,
      display_name: "远端 Mac",
      platform: "macos",
      state: "online",
      source: "coordinator_directory",
      evidence_at: observedAt,
      freshness: "fresh",
      service_count: 1,
    },
  ];
  overview.services.items = [
    {
      service_id: serviceId,
      node_id: remoteNodeId,
      display_name: "远端管理面板",
      protocol: "tcp",
      port: 4312,
      access_address: "tcp://127.0.0.1:4312",
      accessibility: "loopback",
      lifecycle: "active",
      state: "available",
      source: "coordinator_directory",
      evidence_at: observedAt,
      freshness: "fresh",
    },
  ];
  overview.incidents = {
    source: "coordinator_directory",
    evidence_at: observedAt,
    freshness: "fresh",
    error: null,
    items: [
      {
        incident_id: incidentId,
        event_type: "local_only",
        object_kind: "service",
        object_id: serviceId,
        severity: "warning",
        status: "confirmed",
        first_observed_at: observedAt,
        last_observed_at: observedAt,
        conclusion: "远端服务只监听环回地址",
      },
    ],
  };
  return overview;
}

function incidentDetail() {
  return {
    incident: {
      schema_version: "incident/v1",
      incident_id: incidentId,
      dedup_key: `sha256:${"a".repeat(64)}`,
      event: {
        event_type: "local_only",
        object_kind: "service",
        object_id: serviceId,
        target_node_id: remoteNodeId,
        baseline_snapshot_id: snapshotA,
        current_snapshot_id: snapshotB,
        baseline_revision: 1,
        current_revision: 2,
        observed_at: observedAt,
        source: "coordinator_directory",
        before_state: "network",
        after_state: "loopback",
        dedup_key: `sha256:${"a".repeat(64)}`,
      },
      status: "confirmed",
      created_at: observedAt,
      last_observed_at: observedAt,
      run_id: `run_${"8".repeat(32)}`,
      hypotheses: [],
      trace: [],
      report: {
        facts: ["服务只监听环回地址"],
        candidate_explanations: [],
        unknowns: [],
        conclusion: "远端服务只监听环回地址",
        stop_reason: "evidence_sufficient",
        evidence: [
          {
            snapshot_id: snapshotB,
            tool_run_id: null,
            observed_at: observedAt,
            summary: "当前快照确认环回监听",
          },
        ],
      },
    },
    suggested_questions: [],
    thread_id: null,
  };
}

test("从 Overview incident 进入预填计划并只创建一次 Operation", async ({
  context,
  page,
  request,
}) => {
  const overview = await remoteIncidentOverview(request);
  const created = makeOperationDetail({
    role: "requester",
    summary: makeOperationSummary({ operation_id: createdOperationId }),
    allowed_actions: ["refresh"],
  });
  const queue = [
    makeOperationListItem({ operation_id: `operation_${"1".repeat(32)}` }),
    makeOperationListItem({
      operation_id: `operation_${"2".repeat(32)}`,
      role: "requester",
      status: "authorized",
    }),
    makeOperationListItem({
      operation_id: `operation_${"3".repeat(32)}`,
      role: "requester",
      status: "awaiting_authorization",
    }),
    makeOperationListItem({
      operation_id: `operation_${"4".repeat(32)}`,
      status: "succeeded",
    }),
    makeOperationListItem({
      operation_id: `operation_${"5".repeat(32)}`,
      execution_result_unknown: true,
    }),
    makeOperationListItem({
      operation_id: `operation_${"6".repeat(32)}`,
      status: "cleanup_failed",
    }),
  ];
  const writes: unknown[] = [];

  await context.route("**/api/resources/overview", (route) =>
    fulfillJson(route, overview),
  );
  await context.route(`**/api/incidents/${incidentId}`, (route) =>
    fulfillJson(route, incidentDetail()),
  );
  await context.route("**/api/operations**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === "/api/operations/eligible-peers") {
      await fulfillJson(route, [
        {
          node_id: remoteNodeId,
          host: "10.77.0.2",
          port: 8787,
          allowed_tools: ["get_node_summary"],
          allowed_operations: ["share_local_http_service"],
          credential_configured: true,
        },
      ]);
    } else if (path === "/api/operations" && method === "POST") {
      writes.push(request.postDataJSON());
      await fulfillJson(route, created);
    } else if (path === `/api/operations/${createdOperationId}`) {
      await fulfillJson(route, created);
    } else if (path === "/api/operations") {
      await fulfillJson(route, queue);
    } else {
      await route.fallback();
    }
  });

  await page.goto("/app/overview");
  const attention = page.locator(
    '[aria-labelledby="overview-operation-attention"]',
  );
  await expect(attention.getByText("待本机批准")).toBeVisible();
  await expect(attention.getByText("待确认执行")).toBeVisible();
  await expect(attention.getByText("写入结果待确认")).toBeVisible();
  await expect(attention.getByText("清理失败，需人工处理")).toBeVisible();
  await expect(
    attention.getByRole("link", { name: "打开最新操作详情" }),
  ).toHaveCount(4);

  await page.getByRole("button", { name: "查看调查详情" }).click();
  await page.getByRole("link", { name: "生成候选处理计划" }).click();
  await expect(page).toHaveURL(
    `/app/operations?incident_id=${incidentId}&target_node_id=${remoteNodeId}&service_port=4312`,
  );
  await expect(page.getByText(`来自 Incident ${incidentId}`)).toBeVisible();
  await expect(page.locator('select[name="target_node_id"]')).toHaveValue(
    remoteNodeId,
  );
  await expect(page.getByLabel("目标服务端口")).toHaveValue("4312");
  expect(writes).toEqual([]);

  await page.getByRole("checkbox", { name: /目标节点批准后会创建/ }).check();
  await page.getByRole("button", { name: "生成计划并请求批准" }).click();
  await expect(page).toHaveURL(`/app/operations/${createdOperationId}`);
  await expect(page.getByText("等待本机批准")).toBeVisible();
  expect(writes).toEqual([
    {
      target_node_id: remoteNodeId,
      service_port: 4312,
      bind_port: 18881,
      duration_seconds: 300,
      confirmed: true,
    },
  ]);
});

test("Operation 摘要失败只降级待办卡且不产生写请求", async ({
  context,
  page,
  request,
}) => {
  const overview = await remoteIncidentOverview(request);
  let writes = 0;
  await context.route("**/api/resources/overview", (route) =>
    fulfillJson(route, overview),
  );
  await context.route("**/api/operations", async (route) => {
    if (route.request().method() !== "GET") {
      writes += 1;
    }
    await fulfillJson(route, { code: "operations_unavailable" }, 503);
  });

  await page.goto("/app/overview");

  await expect(page.getByText("远端服务只监听环回地址")).toBeVisible();
  await expect(
    page.getByText("操作待办暂时无法读取；资源和 incident 总览不受影响。"),
  ).toBeVisible();
  expect(writes).toBe(0);
});
