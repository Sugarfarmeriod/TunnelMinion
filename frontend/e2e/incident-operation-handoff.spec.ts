import {
  expect,
  test,
  type APIRequestContext,
  type Route,
} from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

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
      investigation: {
        schema_version: "investigation-state/v1",
        skill_id: "service.local-only",
        skill_version: "1",
        phase: "finished",
        model_rounds: 2,
        tool_calls: 2,
        steps: [
          {
            step_id: "target-listener",
            requirement_ids: ["target-listener"],
            tool_name: "get_process_summary",
            execution: "target",
            status: "succeeded",
            attempts: 1,
            evidence: {
              snapshot_id: snapshotB,
              tool_run_id: `toolrun_${"9".repeat(32)}`,
              observed_at: observedAt,
              summary: "目标节点确认服务只监听 127.0.0.1:4312",
            },
            observations: {},
            failure_code: null,
          },
          {
            step_id: "requester-reachability",
            requirement_ids: ["requester-reachability"],
            tool_name: "probe_service",
            execution: "requester",
            status: "succeeded",
            attempts: 1,
            evidence: {
              snapshot_id: null,
              tool_run_id: `toolrun_${"a".repeat(32)}`,
              observed_at: observedAt,
              summary: "请求节点无法连接目标服务",
            },
            observations: {},
            failure_code: null,
          },
        ],
        facts: ["目标服务只监听环回地址", "请求节点无法连接目标服务"],
        unknowns: [],
        stop_reason: "evidence_sufficient",
        updated_at: observedAt,
      },
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

test("从最近事件 进入预填计划并只创建一次 Operation", async ({
  context,
  page,
  request,
}, testInfo) => {
  const overview = await remoteIncidentOverview(request);
  const created = makeOperationDetail({
    role: "requester",
    source_incident_id: incidentId,
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
  const incidentRequests: string[] = [];

  await context.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
    fulfillJson(route, overview),
  );
  await context.route(`**/api/incidents/${incidentId}`, (route) => {
    incidentRequests.push(route.request().method());
    return fulfillJson(route, incidentDetail());
  });
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

  await page.goto("/app/incidents");
  await page.getByRole("button", { name: "查看调查详情" }).click();
  const detail = page.locator(".incident-detail");
  const handoff = detail.getByRole("link", { name: "查看临时访问方案" });
  await expect(handoff).toBeVisible();
  await expect(detail.getByText("service.local-only@1")).toBeHidden();
  await expect(detail.getByText("get_process_summary")).toBeHidden();
  await expect(detail.getByRole("textbox")).toBeHidden();
  const a11y = await new AxeBuilder({ page })
    .include(".incident-detail")
    .analyze();
  expect(
    a11y.violations.filter((item) =>
      ["serious", "critical"].includes(item.impact ?? ""),
    ),
  ).toEqual([]);
  expect(incidentRequests).toEqual(["GET"]);
  expect(writes).toEqual([]);
  await detail.screenshot({
    animations: "disabled",
    path: testInfo.outputPath("service-result-first.png"),
  });
  await page.setViewportSize({ width: 320, height: 760 });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
  await detail.screenshot({
    animations: "disabled",
    path: testInfo.outputPath("service-result-narrow.png"),
  });
  await page.setViewportSize({ width: 1280, height: 720 });
  await detail.getByText("查看技术过程与证据").click();
  await expect(detail).toContainText("service.local-only@1");
  await expect(detail).toContainText("调查已停止");
  await expect(detail).toContainText("get_process_summary");
  await detail.getByText("查看公开证据引用").first().click();
  await expect(detail).toContainText(snapshotB);
  await expect(detail).toContainText("目标节点确认服务只监听 127.0.0.1:4312");
  expect(incidentRequests).toEqual(["GET"]);
  expect(writes).toEqual([]);
  await detail.screenshot({
    animations: "disabled",
    path: testInfo.outputPath("investigation-evidence-view.png"),
  });
  await handoff.click();
  await expect(page).toHaveURL(
    `/app/operations?incident_id=${incidentId}&target_node_id=${remoteNodeId}&service_port=4312`,
  );
  await expect(page.getByText("已带入刚才调查的服务")).toBeVisible();
  await expect(page.locator('select[name="target_node_id"]')).toHaveValue(
    remoteNodeId,
  );
  await expect(page.locator('input[name="service_port"]')).toHaveValue("4312");
  const application = page.locator(".operation-request-card");
  await expect(
    application.getByRole("option", { name: "远端 Mac", exact: true }),
  ).toBeAttached();
  await expect(
    application.getByText("远端管理面板", { exact: true }),
  ).toBeVisible();
  await expect(application.getByLabel("临时共享端口")).toBeHidden();
  await expect(application.getByText(/来源事件/)).toBeHidden();
  await expect(application.getByText(/可能使用模型额度/)).toBeVisible();
  const applicationA11y = await new AxeBuilder({ page })
    .include(".operation-request-card")
    .analyze();
  expect(
    applicationA11y.violations.filter((item) =>
      ["serious", "critical"].includes(item.impact ?? ""),
    ),
  ).toEqual([]);
  await application.screenshot({
    animations: "disabled",
    path: testInfo.outputPath("request-form-first.png"),
  });
  await page.setViewportSize({ width: 320, height: 760 });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
  await application.screenshot({
    animations: "disabled",
    path: testInfo.outputPath("request-form-narrow.png"),
  });
  await page.setViewportSize({ width: 1280, height: 720 });
  expect(writes).toEqual([]);

  await page.getByRole("checkbox", { name: /我了解风险/ }).check();
  await page.getByRole("button", { name: "发送访问请求" }).click();
  await expect(page).toHaveURL(`/app/operations/${createdOperationId}`);
  await expect(page.getByText("等待对方同意").first()).toBeVisible();
  expect(writes).toEqual([
    {
      source_incident_id: incidentId,
      target_node_id: remoteNodeId,
      service_port: 4312,
      bind_port: 18881,
      duration_seconds: 300,
      confirmed: true,
    },
  ]);
  await page.getByRole("link", { name: "返回调查结果", exact: true }).click();
  await expect(
    detail.getByRole("heading", { name: "调查结果", exact: true }),
  ).toBeFocused();
  await detail.getByRole("link", { name: "返回这项服务", exact: true }).click();
  await expect(page).toHaveURL("/app/map");
  await expect(
    page.getByRole("heading", { name: "我的服务网络" }),
  ).toBeVisible();
  expect(writes).toHaveLength(1);
});

test("事件列表与调查详情独立展示，追问转入地图线程", async ({
  page,
  context,
  request,
}) => {
  const overview = await remoteIncidentOverview(request);
  await context.route("**/api/ui/overview", (route) =>
    fulfillJson(route, overview),
  );
  await context.route(`**/api/incidents/${incidentId}`, (route) =>
    fulfillJson(route, incidentDetail()),
  );
  const followups: unknown[] = [];
  const run = {
    run_id: `run_${"b".repeat(32)}`,
    thread_id: `thread_${"c".repeat(32)}`,
    status: "running",
    created_at: observedAt,
    finished_at: null,
    result: null,
    error_code: null,
    error_message: null,
    failure: null,
  };
  await context.route(`**/api/incidents/${incidentId}/follow-up`, (route) => {
    followups.push(route.request().postDataJSON());
    return fulfillJson(route, run);
  });
  await page.goto("/app/incidents");
  await page.getByRole("button", { name: "查看调查详情" }).click();
  const detail = page.locator(".incident-detail");
  await expect(
    detail.getByRole("heading", { name: "调查结果", exact: true }),
  ).toBeFocused();
  await detail.getByText("查看技术过程与证据").click();
  await expect(detail.getByText("service.local-only@1")).toBeVisible();
  await detail.getByText("继续问一下（会使用模型额度）").click();
  const input = page.getByRole("textbox", { name: "针对这个事件追问" });
  await expect(input).toHaveAttribute("maxlength", "2000");
  await input.fill("接下来该看什么？");
  await page.getByRole("button", { name: "开始只读追问" }).click();
  await expect(
    page.getByRole("link", { name: "打开对应聊天线程" }),
  ).toHaveAttribute("href", `/app/map?thread=${run.thread_id}`);
  expect(followups).toEqual([{ question: "接下来该看什么？" }]);
  await page.getByRole("button", { name: "返回最近变化" }).click();
  await expect(
    page.getByRole("button", { name: "查看调查详情" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "← 回到地图" }).click();
  await expect(
    page.getByRole("heading", { name: "我的服务网络" }),
  ).toBeVisible();
});
for (const identity of ["missing", "wrong-node", "stale"] as const) {
  test(`调查的 ${identity} 对象只保留原记录，不生成错误申请`, async ({
    page,
    context,
    request,
  }) => {
    const overview = await remoteIncidentOverview(request);
    if (identity === "missing") overview.services.items = [];
    else if (identity === "wrong-node")
      overview.services.items[0]!.node_id = localNodeId;
    else overview.services.items[0]!.freshness = "stale";
    await context.route("**/api/ui/overview", (route) =>
      fulfillJson(route, overview),
    );
    await context.route(`**/api/incidents/${incidentId}`, (route) =>
      fulfillJson(route, incidentDetail()),
    );
    await page.goto(`/app/incidents?incident_id=${incidentId}`);
    await expect(page.getByRole("heading", { name: "调查结果" })).toBeVisible();
    await expect(
      page.getByRole("link", { name: "查看临时访问方案" }),
    ).toHaveCount(0);
    await expect(page.getByRole("link", { name: "← 回到地图" })).toBeVisible();
  });
}
