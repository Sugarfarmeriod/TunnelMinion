import { expect, test, type Page } from "@playwright/test";

import type { ResourceOverview } from "../src/api/schemas/overview";

const generatedAt = "2026-08-11T09:00:00+08:00";
const evidenceAt = "2026-08-11T08:59:00+08:00";
const nodeId = `node_${"a".repeat(32)}`;
const serviceId = `service_${"b".repeat(32)}`;

function makeOverview(): ResourceOverview {
  return {
    schema_version: "resource-overview/v1",
    generated_at: generatedAt,
    local: {
      source: "local_runtime",
      evidence_at: evidenceAt,
      freshness: "live",
      error: null,
      runtime: "running",
      platform: "windows",
      version: "0.1.0",
      package: {
        name: "tunnelminion",
        kind: "source",
        version: "0.1.0",
        manifest_schema: null,
      },
      readiness: "ready",
    },
    model: {
      source: "model_configuration",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      status: "available",
    },
    coordinator: {
      source: "coordinator_sync",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      state: "ready",
      revision: 12,
      last_success_at: evidenceAt,
    },
    network_path: {
      source: "network_path_evidence",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      state: "direct",
      provider: "windows",
      revision: 4,
      handshake: { status: "passed", observed_at: evidenceAt },
      route: { status: "passed", observed_at: evidenceAt },
      probe: { status: "passed", observed_at: evidenceAt },
    },
    nodes: {
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      items: [],
    },
    services: {
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      items: [],
    },
    incidents: {
      source: "local_observation",
      evidence_at: null,
      freshness: "not_applicable",
      error: null,
      items: [],
    },
  };
}

async function serveOverview(page: Page, payload: ResourceOverview) {
  await page.route(
    /\/api\/(?:resources\/overview|ui\/overview)$/,
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(payload),
      });
    },
  );
  await page.goto("/app/settings");
  await expect(page.getByRole("heading", { name: "模型设置" })).toBeVisible();
}

function modelUnavailableOverview(): ResourceOverview {
  const overview = makeOverview();
  overview.model = {
    ...overview.model,
    configured: false,
    status: "unconfigured",
    freshness: "not_applicable",
    evidence_at: null,
  };
  return overview;
}

function coordinatorUnconfiguredOverview(): ResourceOverview {
  const overview = makeOverview();
  overview.coordinator = {
    ...overview.coordinator,
    configured: false,
    state: "unconfigured",
    freshness: "not_applicable",
    evidence_at: null,
    revision: null,
    last_success_at: null,
  };
  overview.network_path = {
    ...overview.network_path,
    configured: false,
    state: "unconfigured",
    provider: null,
    revision: null,
    handshake: { status: "missing", observed_at: null },
    route: { status: "missing", observed_at: null },
    probe: { status: "missing", observed_at: null },
  };
  return overview;
}

function peerOfflineOverview(): ResourceOverview {
  const overview = makeOverview();
  overview.network_path = {
    ...overview.network_path,
    state: "offline",
    handshake: { status: "passed", observed_at: evidenceAt },
    route: { status: "missing", observed_at: null },
    probe: { status: "failed", observed_at: evidenceAt },
  };
  overview.nodes.items = [
    {
      node_id: nodeId,
      display_name: "实验室 Mac（脱敏）",
      platform: "macos",
      state: "offline",
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      service_count: 0,
    },
  ];
  return overview;
}

function firewallLogUnavailableOverview(): ResourceOverview {
  const overview = makeOverview();
  overview.network_path.error = {
    code: "firewall_log_unavailable",
    retryable: false,
  };
  return overview;
}

function staleCacheOverview(): ResourceOverview {
  const overview = makeOverview();
  overview.coordinator = {
    ...overview.coordinator,
    state: "stale",
    freshness: "stale",
    error: { code: "directory_cache_stale", retryable: true },
  };
  overview.nodes = {
    ...overview.nodes,
    freshness: "stale",
    error: { code: "directory_cache_stale", retryable: true },
    items: [
      {
        node_id: nodeId,
        display_name: "缓存中的实验节点",
        platform: "macos",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "stale",
        service_count: 1,
      },
    ],
  };
  overview.services.items = [
    {
      service_id: serviceId,
      node_id: nodeId,
      display_name: "缓存中的只读服务",
      protocol: "https",
      port: 443,
      access_address: "https://service.example:443",
      accessibility: "network",
      lifecycle: "active",
      state: "available",
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "stale",
    },
  ];
  return overview;
}

for (const [title, fixture, selector, text] of [
  ["无模型", modelUnavailableOverview, "overview-model", "还没有配置模型"],
  [
    "无 Coordinator",
    coordinatorUnconfiguredOverview,
    "overview-coordinator",
    "未配置 Coordinator，当前按仅本机模式工作",
  ],
  ["路径离线", peerOfflineOverview, "overview-network", "peer 路径当前不可达"],
  [
    "可选防火墙日志不可用",
    firewallLogUnavailableOverview,
    "overview-network",
    "防火墙日志不可用不影响当前路径判断",
  ],
  [
    "证据陈旧",
    staleCacheOverview,
    "overview-coordinator",
    "Coordinator 目录已经陈旧",
  ],
] as const) {
  test(`设置保留运行基础：${title}`, async ({ page }) => {
    await serveOverview(page, fixture());
    const card = page.locator(`article[aria-labelledby="${selector}"]`);
    await expect(card).toContainText(text);
    await expect(
      page.locator('article[aria-labelledby="overview-local"]'),
    ).toContainText("本机接口已准备好");
    await page.getByText("数据来源与高级连接信息", { exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "设备与服务的数据来源" }),
    ).toBeVisible();
  });
}
test("设置运行基础刷新失败保留记录，重新读取后恢复", async ({ page }) => {
  let failed = false;
  await page.route("**/api/resources/overview", (route) =>
    route.fulfill(
      failed ? { status: 503, json: {} } : { json: makeOverview() },
    ),
  );
  await page.goto("/app/settings");
  const button = page.getByRole("button", { name: "刷新运行基础" });
  await expect(button).toBeVisible();
  failed = true;
  await button.click();
  await expect(
    page.getByText("运行基础刷新失败，下面保留上一次读取的记录。"),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "本机运行", exact: true }),
  ).toBeVisible();
  failed = false;
  await button.click();
  await expect(
    page.getByText("运行基础刷新失败，下面保留上一次读取的记录。"),
  ).toHaveCount(0);
});
