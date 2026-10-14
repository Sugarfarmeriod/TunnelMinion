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

test("调查与申请可以返回原服务，并把键盘位置带回来", async ({
  page,
  context,
  request,
}, testInfo) => {
  const overview = await remoteIncidentOverview(request);
  let writes = 0;
  page.on("request", (request) => {
    if (request.method() !== "GET") writes++;
  });
  await context.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
    fulfillJson(route, overview),
  );
  await context.route(`**/api/incidents/${incidentId}`, (route) =>
    fulfillJson(route, incidentDetail()),
  );
  await context.route("**/api/operations", (route) => fulfillJson(route, []));
  await context.route("**/api/operations/eligible-peers", (route) =>
    fulfillJson(route, []),
  );
  await page.goto("/app/overview");
  const services = page.getByRole("list", { name: "有名称的服务" });
  await services.getByRole("link", { name: "查看这项服务的变化" }).click();
  const detail = page.locator(".incident-detail");
  await expect(
    detail.getByRole("heading", { name: "调查结果", exact: true }),
  ).toBeFocused();
  await expect(detail.getByLabel("正在查看的服务")).toHaveText(
    "远端 Mac · 远端管理面板",
  );
  await detail.getByRole("link", { name: "查看临时访问方案" }).click();
  await expect(
    page.getByText("这台电脑当前不可申请，本次不会发送请求。"),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "申请临时访问", exact: true }),
  ).toBeFocused();
  await page.getByRole("link", { name: "返回调查结果", exact: true }).click();
  await expect(
    detail.getByRole("heading", { name: "调查结果", exact: true }),
  ).toBeFocused();
  await page.setViewportSize({ width: 320, height: 760 });
  await detail.screenshot({
    animations: "disabled",
    path: testInfo.outputPath("investigation-context-320.png"),
  });
  await detail.getByRole("link", { name: "返回这项服务", exact: true }).click();
  await expect(services.locator("summary")).toBeFocused();
  await expect(services.locator("summary")).toBeInViewport();
  await expect(
    page.locator(".overview-device").filter({ hasText: "远端 Mac" }),
  ).toHaveAttribute("open", "");
  await page.reload();
  await expect(services.locator("summary")).toBeFocused();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
  await page.screenshot({
    fullPage: true,
    animations: "disabled",
    path: testInfo.outputPath("returned-service-320.png"),
  });
  await page.setViewportSize({ width: 1280, height: 720 });
  await services.getByRole("link", { name: "查看这项服务的变化" }).click();
  await detail.getByRole("button", { name: "返回最近变化" }).click();
  await expect(
    page.getByRole("button", { name: "查看调查详情" }),
  ).toBeFocused();
  await page.goBack();
  await expect(
    detail.getByRole("heading", { name: "调查结果", exact: true }),
  ).toBeFocused();
  expect(writes).toBe(0);
});

test("同一程序名称贯穿调查、申请与批准确认，各入口不混淆", async ({
  page,
  context,
  request,
}, testInfo) => {
  const overview = await remoteIncidentOverview(request);
  overview.schema_version = "resource-overview-programs/v1";
  const service = overview.services.items[0]!;
  service.display_name = "Python · nanobot · 4312";
  service.application = {
    group_id: `application_${"b".repeat(32)}`,
    name: "nanobot",
    kind: "python",
  };
  overview.services.items.push({
    ...service,
    service_id: `service_${"c".repeat(32)}`,
    display_name: "Python · nanobot · 18790",
    port: 18790,
    access_address: "tcp://127.0.0.1:18790",
  });
  overview.nodes.items[1]!.service_count = 2;
  const legacy = {
    ...overview,
    schema_version: "resource-overview/v1",
    services: {
      ...overview.services,
      items: overview.services.items.map(
        ({ application: _app, ...item }) => item,
      ),
    },
  };
  const operation = makeOperationDetail({
    role: "target",
    service_id: serviceId,
    service_endpoint: "http://127.0.0.1:4312",
    service_process_or_container: "python3",
    source_incident_id: incidentId,
    summary: makeOperationSummary({
      operation_id: createdOperationId,
      request_node_id: localNodeId,
      target_node_id: remoteNodeId,
    }),
  });
  let writes = 0;
  page.on("request", (req) => {
    if (req.method() !== "GET") writes++;
  });
  await context.route("**/api/ui/overview", (route) =>
    fulfillJson(route, overview),
  );
  await context.route("**/api/resources/overview", (route) =>
    fulfillJson(route, legacy),
  );
  await context.route(`**/api/incidents/${incidentId}`, (route) =>
    fulfillJson(route, incidentDetail()),
  );
  await context.route("**/api/operations", (route) => fulfillJson(route, []));
  await context.route("**/api/operations/eligible-peers", (route) =>
    fulfillJson(route, [
      {
        node_id: remoteNodeId,
        platform: "macos",
        host: "10.77.0.1",
        port: 8787,
        allowed_tools: ["get_node_summary"],
        allowed_operations: ["share_local_http_service"],
        credential_configured: true,
      },
    ]),
  );
  await context.route(`**/api/operations/${createdOperationId}`, (route) =>
    fulfillJson(route, operation),
  );
  await page.goto("/app/overview");
  const programs = page.getByRole("list", {
    name: "有名称的服务",
    exact: true,
  });
  await expect(programs.locator(":scope > li")).toHaveCount(1);
  await programs.getByRole("link", { name: "查看这项程序的变化" }).click();
  const investigation = page.locator(".incident-detail");
  await investigation.screenshot({
    path: testInfo.outputPath("program-context-investigation.png"),
  });
  await expect(investigation.getByLabel("正在查看的服务")).toHaveText(
    "远端 Mac · nanobot",
  );
  await expect(
    investigation.getByText("连接入口 4312", { exact: true }),
  ).toBeVisible();
  await investigation.getByRole("link", { name: "查看临时访问方案" }).click();
  const application = page.locator(".operation-request-card");
  await expect(application.getByText("nanobot", { exact: true })).toBeVisible();
  await expect(
    application.getByText("连接入口 4312", { exact: true }),
  ).toBeVisible();
  await expect(application.locator('[name="service_port"]')).toHaveValue(
    "4312",
  );
  await expect(
    application.getByText("Python · nanobot · 4312", { exact: true }),
  ).toHaveCount(0);
  await page.goto(`/app/operations/${createdOperationId}`);
  const explanation = page.getByRole("region", { name: "这次请求会做什么" });
  await expect(explanation.getByText("nanobot", { exact: true })).toBeVisible();
  await expect(
    explanation.getByText("远端 Mac · 连接入口 4312", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "批准一次", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "确认批准一次" });
  await expect(dialog.getByText("nanobot", { exact: true })).toBeVisible();
  await expect(
    dialog.getByText("远端 Mac · 连接入口 4312", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "返回检查详情", exact: true }),
  ).toBeFocused();
  await page.setViewportSize({ width: 320, height: 760 });
  await dialog.screenshot({
    path: testInfo.outputPath("program-context-approval-320.png"),
  });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "批准一次", exact: true }),
  ).toBeFocused();
  const otherEntry = overview.services.items[1]!;
  for (const mismatch of ["stale", "duplicate", "other-node"] as const) {
    const current = { ...service };
    if (mismatch === "stale") current.freshness = "stale";
    if (mismatch === "other-node") current.node_id = localNodeId;
    overview.services.items = [current, otherEntry];
    if (mismatch === "duplicate") overview.services.items.push({ ...current });
    await page.reload();
    await expect(
      explanation.getByText("python3", { exact: true }),
    ).toBeVisible();
    await expect(explanation.getByText("nanobot", { exact: true })).toHaveCount(
      0,
    );
    await expect(explanation.getByText(/连接入口/)).toHaveCount(0);
  }
  expect(writes).toBe(0);
});

for (const identity of [
  "unnamed",
  "stale",
  "missing",
  "duplicate",
  "other-node",
] as const) {
  test(`调查返回遵守 ${identity} 服务归属`, async ({
    page,
    context,
    request,
  }) => {
    const overview = await remoteIncidentOverview(request);
    overview.services.items[0]!.application = {
      group_id: `application_${"a".repeat(32)}`,
      name: "不应采用的程序名",
      kind: "python",
    };
    if (identity === "unnamed") overview.services.items[0].display_name = null;
    if (identity === "stale") overview.services.items[0].freshness = "stale";
    if (identity === "missing") overview.services.items = [];
    if (identity === "duplicate")
      overview.services.items.push({ ...overview.services.items[0] });
    if (identity === "other-node")
      overview.services.items[0].node_id = localNodeId;
    await context.route(
      /\/api\/(?:resources\/overview|ui\/overview)$/,
      (route) => fulfillJson(route, overview),
    );
    await context.route(`**/api/incidents/${incidentId}`, (route) =>
      fulfillJson(route, incidentDetail()),
    );
    await context.route("**/api/operations", (route) => fulfillJson(route, []));
    await page.goto(
      `/app/overview?incident_id=${incidentId}#overview-incidents`,
    );
    const detail = page.locator(".incident-detail");
    const returnLink = detail.getByRole("link", {
      name: "返回这项服务",
      exact: true,
    });
    if (identity === "unnamed" || identity === "stale") {
      await expect(detail.getByLabel("正在查看的服务")).toContainText(
        "服务名称待确认",
      );
      await returnLink.click();
      const row = page.locator(
        `#${identity === "unnamed" ? "technical-" : ""}${serviceId}`,
      );
      if (identity === "unnamed") {
        await expect(row).toBeFocused();
        await expect(row).toContainText("用途未识别的后台项目");
      } else {
        await expect(row.locator("summary")).toBeFocused();
        await expect(row).toContainText("记录已过时");
      }
      await expect(row).toBeInViewport();
    } else {
      await expect(
        detail.getByText(
          "当前清单中找不到唯一的同一服务；下面保留此前的调查记录。",
        ),
      ).toBeVisible();
      await expect(returnLink).toHaveCount(0);
      await expect(
        detail.getByRole("link", { name: "查看临时访问方案" }),
      ).toHaveCount(0);
    }
  });
}

test("从 Overview incident 进入预填计划并只创建一次 Operation", async ({
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

  await page.goto("/app/overview");
  const attention = page.getByRole("list", { name: "需要你处理的请求" });
  await expect(attention.getByText("待本机批准")).toBeVisible();
  await expect(attention.getByText("待确认执行")).toBeVisible();
  await expect(attention.getByText("结果待确认")).toBeVisible();
  await expect(attention.getByText("清理失败，需人工处理")).toBeVisible();
  await expect(attention.getByRole("link", { name: "查看并处理" })).toHaveCount(
    4,
  );

  await page
    .getByRole("list", { name: "有名称的服务" })
    .getByRole("link", { name: "查看这项服务的变化" })
    .click();
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
  await expect(
    page.getByRole("list", { name: "有名称的服务" }).locator("summary"),
  ).toBeFocused();
  expect(writes).toHaveLength(1);
});

for (const mismatch of [
  "stale",
  "stopped",
  "duplicate",
  "other-node",
  "other-port",
  "unavailable",
] as const) {
  test(`申请页的 ${mismatch} 归属不会冒充已识别服务`, async ({
    context,
    page,
    request,
  }) => {
    const overview = await remoteIncidentOverview(request);
    const service = overview.services.items[0]!;
    service.application = {
      group_id: `application_${"a".repeat(32)}`,
      name: "不应采用的程序名",
      kind: "python",
    };
    if (mismatch === "stale") service.freshness = "stale";
    if (mismatch === "stopped") service.lifecycle = "stopped";
    if (mismatch === "duplicate") overview.services.items.push({ ...service });
    if (mismatch === "other-node") service.node_id = localNodeId;
    if (mismatch === "other-port") service.port = 4313;
    await context.route(
      /\/api\/(?:resources\/overview|ui\/overview)$/,
      (route) =>
        mismatch === "unavailable"
          ? fulfillJson(route, { error: "unavailable" }, 503)
          : fulfillJson(route, overview),
    );
    const writes: string[] = [];
    await context.route("**/api/operations**", (route) => {
      if (route.request().method() !== "GET")
        writes.push(route.request().method());
      return fulfillJson(
        route,
        new URL(route.request().url()).pathname.endsWith("eligible-peers")
          ? [
              {
                node_id: remoteNodeId,
                host: "10.77.0.2",
                port: 8787,
                allowed_tools: [],
                allowed_operations: ["share_local_http_service"],
                credential_configured: true,
              },
            ]
          : [],
      );
    });
    await page.goto(
      `/app/operations?incident_id=${incidentId}&target_node_id=${remoteNodeId}&service_port=4312`,
    );
    const application = page.locator(".operation-request-card");
    await expect(
      application.getByText("还不能确认服务名称", { exact: true }),
    ).toBeVisible();
    await expect(
      application.getByText("远端管理面板", { exact: true }),
    ).toHaveCount(0);
    await expect(
      application.getByText("不应采用的程序名", { exact: true }),
    ).toHaveCount(0);
    await expect(application.getByLabel("服务的端口号码")).toHaveValue("4312");
    await application.getByText("技术设置（通常不用改）").click();
    await expect(application.getByLabel("临时共享端口")).toBeVisible();
    expect(writes).toEqual([]);
  });
}

test("同页切换调查、返回历史和关闭详情不会遗留旧追问或产生写请求", async ({
  page,
  context,
  request,
}) => {
  const overview = await remoteIncidentOverview(request);
  const nextId = `incident_${"b".repeat(32)}`;
  overview.incidents.items.push({
    ...overview.incidents.items[0],
    incident_id: nextId,
    status: "insufficient_evidence",
    last_observed_at: "2026-09-09T09:00:00+08:00",
    conclusion: "还没有查清原因",
  });
  const next = incidentDetail();
  next.incident.incident_id = nextId;
  next.incident.status = "insufficient_evidence";
  next.incident.report.conclusion = "还没有查清原因";
  let writes = 0;
  page.on("request", (request) => {
    if (request.method() !== "GET") writes++;
  });
  await context.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
    fulfillJson(route, overview),
  );
  await context.route("**/api/operations", (route) => fulfillJson(route, []));
  await context.route(`**/api/incidents/${incidentId}`, (route) =>
    fulfillJson(route, incidentDetail()),
  );
  await context.route(`**/api/incidents/${nextId}`, (route) =>
    fulfillJson(route, next),
  );
  await page.goto(`/app/overview?incident_id=${incidentId}`);
  const detail = page.locator(".incident-detail");
  await expect(
    detail.getByRole("link", { name: "查看临时访问方案" }),
  ).toBeVisible();
  await page
    .getByRole("textbox", { name: "问题", exact: true })
    .fill("上一次的问题");
  await detail.getByRole("button", { name: "返回最近变化" }).click();
  await expect(page.getByRole("button", { name: "查看调查详情" })).toHaveCount(
    2,
  );
  await page
    .getByRole("list", { name: "有名称的服务" })
    .getByRole("link", { name: "查看这项服务的变化" })
    .click();
  await expect(page).toHaveURL(new RegExp(`incident_id=${nextId}`));
  await expect(
    detail.getByText("结论：还没有查清原因", { exact: true }),
  ).toBeVisible();
  await expect(
    detail.getByRole("link", { name: "查看临时访问方案" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("textbox", { name: "问题", exact: true }),
  ).toHaveValue("");
  await page.goBack();
  await expect(
    page.getByRole("button", { name: "查看调查详情" }).first(),
  ).toBeVisible();
  await page.goForward();
  await expect(
    detail.getByText("结论：还没有查清原因", { exact: true }),
  ).toBeVisible();
  await detail.getByRole("link", { name: "返回这项服务" }).click();
  await expect(page.locator(".incident-detail")).toHaveCount(0);
  await expect(page).not.toHaveURL(/incident_id=/);
  expect(writes).toBe(0);
});

test("请求读取失败只显示提示，不阻断设备和调查且不产生写请求", async ({
  context,
  page,
  request,
}) => {
  const overview = await remoteIncidentOverview(request);
  let writes = 0;
  await context.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
    fulfillJson(route, overview),
  );
  await context.route("**/api/operations", async (route) => {
    if (route.request().method() !== "GET") {
      writes += 1;
    }
    await fulfillJson(route, { code: "operations_unavailable" }, 503);
  });

  await page.goto("/app/overview");

  await expect(page.getByText("更多信息", { exact: true })).toBeVisible();
  await expect(
    page.getByText("暂时读不到待处理请求；设备和服务仍可查看。"),
  ).toBeVisible();
  await page.getByRole("link", { name: "查看最近变化与调查" }).first().click();
  await expect(page.getByText("远端服务只监听环回地址")).toBeVisible();
  expect(writes).toBe(0);
});
