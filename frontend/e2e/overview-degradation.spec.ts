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
  };
}

async function serveOverview(page: Page, payload: ResourceOverview) {
  await page.route("**/api/resources/overview", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(payload),
    });
  });
  await page.goto("/app/overview");
  await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
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

test.describe("Overview 浏览器层降级与恢复矩阵", () => {
  test("无模型时仍保留本机总览，并给出配置模型的下一步", async ({ page }) => {
    await serveOverview(page, modelUnavailableOverview());

    const modelCard = page.locator('article[aria-labelledby="overview-model"]');
    await expect(modelCard).toContainText("还没有配置模型");
    await expect(modelCard).toContainText("没有保存模型配置");
    await expect(
      modelCard.getByRole("link", { name: /资源总览仍可使用/ }),
    ).toBeVisible();
    await expect(
      page.locator('article[aria-labelledby="overview-local"]'),
    ).toContainText("本机接口已准备好");
  });

  test("无 Coordinator 时按仅本机模式工作，不阻断本机能力", async ({
    page,
  }) => {
    await serveOverview(page, coordinatorUnconfiguredOverview());

    const coordinatorCard = page.locator(
      'article[aria-labelledby="overview-coordinator"]',
    );
    await expect(coordinatorCard).toContainText(
      "未配置 Coordinator，当前按仅本机模式工作",
    );
    await expect(coordinatorCard).toContainText(
      "仅使用本机功能即可；需要多节点目录时再配置 Coordinator。",
    );
    await expect(
      page.locator('article[aria-labelledby="overview-local"]'),
    ).toContainText("本机接口已准备好");
    await expect(
      page.locator('article[aria-labelledby="overview-nodes"]'),
    ).toContainText("当前没有服务端确认的节点记录。本机功能仍可使用。");
  });

  test("peer 离线时单独标记路径和节点，不误报本机故障", async ({ page }) => {
    await serveOverview(page, peerOfflineOverview());

    const networkCard = page.locator(
      'article[aria-labelledby="overview-network"]',
    );
    await expect(networkCard).toContainText("peer 路径当前不可达");
    await expect(networkCard).toContainText("真实探测");
    await expect(networkCard).toContainText("未通过");
    await expect(
      page.locator('article[aria-labelledby="overview-nodes"]'),
    ).toContainText("实验室 Mac（脱敏）");
    await expect(
      page.locator('article[aria-labelledby="overview-nodes"]'),
    ).toContainText("当前离线");
    await expect(
      page.locator('article[aria-labelledby="overview-local"]'),
    ).toContainText("本机程序正在运行");
  });

  test("防火墙日志不可读时仍展示真实路径结果，并说明日志只是可选诊断", async ({
    page,
  }) => {
    await serveOverview(page, firewallLogUnavailableOverview());

    const networkCard = page.locator(
      'article[aria-labelledby="overview-network"]',
    );
    await expect(networkCard).toContainText("当前选择了直连路径");
    await expect(networkCard).toContainText("firewall_log_unavailable");
    await expect(networkCard).toContainText(
      "防火墙日志只是可选诊断，不是运行条件。",
    );
    await expect(networkCard).toContainText("真实探测");
    await expect(networkCard).toContainText("已通过");
  });

  test("缓存过期时明确标记陈旧证据，不把缓存节点当作当前在线", async ({
    page,
  }) => {
    await serveOverview(page, staleCacheOverview());

    const coordinatorCard = page.locator(
      'article[aria-labelledby="overview-coordinator"]',
    );
    await expect(coordinatorCard).toContainText("Coordinator 目录已经陈旧");
    await expect(coordinatorCard).toContainText("directory_cache_stale");
    const nodesCard = page.locator('article[aria-labelledby="overview-nodes"]');
    await expect(nodesCard).toContainText("缓存中的实验节点");
    await expect(nodesCard).toContainText("有在线证据（证据陈旧）");
    await expect(nodesCard).toContainText("不要把缓存记录当作当前在线");
    await expect(
      page.locator('article[aria-labelledby="overview-services"]'),
    ).toContainText("缓存中的只读服务");
  });

  test("刷新失败后保留旧数据，再次刷新恢复新证据", async ({ page }) => {
    const initial = makeOverview();
    initial.nodes.items = [
      {
        node_id: nodeId,
        display_name: "刷新前的节点记录",
        platform: "macos",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
        service_count: 0,
      },
    ];
    const recovered = makeOverview();
    recovered.generated_at = "2026-08-11T09:05:00+08:00";
    recovered.nodes.items = [
      {
        ...initial.nodes.items[0],
        display_name: "再次刷新后的节点记录",
        evidence_at: recovered.generated_at,
      },
    ];

    let allowRecovery = false;
    let requestCount = 0;
    await page.route("**/api/resources/overview", async (route) => {
      requestCount += 1;
      if (requestCount === 1 || allowRecovery) {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(requestCount === 1 ? initial : recovered),
        });
        return;
      }
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          detail: {
            code: "overview_temporarily_unavailable",
            retryable: true,
            message: "总览暂时不可用",
          },
        }),
      });
    });

    await page.goto("/app/overview");
    await expect(page.getByText("刷新前的节点记录")).toBeVisible();

    const refresh = page.getByRole("button", {
      name: "刷新证据",
      exact: true,
    });
    await refresh.click();
    await expect(page.getByRole("alert")).toContainText(
      "刷新失败，下面是上一次成功读取的缓存。",
    );
    await expect(page.getByText("刷新前的节点记录")).toBeVisible();
    expect(requestCount).toBeGreaterThanOrEqual(2);

    allowRecovery = true;
    await refresh.click();
    await expect(page.getByText("再次刷新后的节点记录")).toBeVisible();
    await expect(page.getByText("刷新前的节点记录")).toBeHidden();
    await expect(
      page.getByText("刷新失败，下面是上一次成功读取的缓存。"),
    ).toBeHidden();
  });
});
