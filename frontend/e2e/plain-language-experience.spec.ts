import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";
import {
  makeOperationDetail,
  requestNodeId,
  targetNodeId,
} from "../src/features/operations/testFixtures";

test("远端自动归属进入精选，归属失效不丢原服务", async ({
  page,
  request,
}, testInfo) => {
  const overview = (await (
    await request.get("/api/resources/overview")
  ).json()) as ResourceOverview;
  overview.nodes = {
    ...overview.nodes,
    source: "coordinator_directory",
    error: null,
    freshness: "fresh",
    evidence_at: overview.generated_at,
  };
  overview.services = {
    ...overview.services,
    source: "coordinator_directory",
    error: null,
    freshness: "fresh",
    evidence_at: overview.generated_at,
  };
  overview.nodes.items = [
    {
      node_id: targetNodeId,
      display_name: "客厅电脑",
      platform: "macos",
      state: "online",
      source: "coordinator_directory",
      freshness: "fresh",
      evidence_at: overview.generated_at,
      service_count: 4,
    },
  ];
  overview.services.items = [
    "Python 服务 · 43123",
    "Docker · my-app · 8088",
    "模型服务 · llama.cpp · 8080",
    null,
  ].map((display_name, index) => ({
    service_id: `service_${index.toString(16).padStart(32, "0")}`,
    node_id: targetNodeId,
    display_name,
    protocol: "tcp" as const,
    port: [43123, 8088, 8080, 9000][index],
    access_address: null,
    accessibility: "loopback" as const,
    lifecycle: "active" as const,
    state: "available" as const,
    source: "coordinator_directory" as const,
    freshness: "fresh" as const,
    evidence_at: overview.generated_at,
  }));
  await page.route("**/api/resources/overview", (route) =>
    route.fulfill({ json: overview }),
  );
  await page.route("**/api/operations", (route) => route.fulfill({ json: [] }));
  await page.goto("/app/overview");
  await page.getByText("客厅电脑", { exact: true }).click();
  const device = page
    .locator(".overview-device")
    .filter({ hasText: "客厅电脑" });
  const selected = device.getByRole("list", { name: "有名称的服务" });
  await expect(selected).toContainText("Python 服务 · 43123");
  await expect(selected).toContainText("Docker · my-app · 8088");
  await expect(selected).toContainText("模型服务 · llama.cpp · 8080");
  await expect(selected.getByRole("listitem")).toHaveCount(3);
  await expect(device).toContainText("1 个后台项目用途未识别");
  await page.screenshot({
    fullPage: true,
    path: testInfo.outputPath("remote-service-selection.png"),
  });
  for (const service of overview.services.items) service.display_name = null;
  await page.reload();
  await page.getByText("客厅电脑", { exact: true }).click();
  await expect(selected).toHaveCount(0);
  await device.getByText("查看全部 4 个检测项目（技术清单）").click();
  await expect(
    device.getByRole("list", { name: "完整检测清单" }).getByRole("listitem"),
  ).toHaveCount(4);
});

test("三百个后台项目不淹没有名称的服务，完整清单可搜索到末项", async ({
  page,
  request,
}, testInfo) => {
  const overview = (await (
    await request.get("/api/resources/overview")
  ).json()) as ResourceOverview;
  overview.nodes = {
    ...overview.nodes,
    source: "coordinator_directory",
    error: null,
    freshness: "fresh",
    evidence_at: overview.generated_at,
  };
  overview.services = {
    ...overview.services,
    source: "coordinator_directory",
    error: null,
    freshness: "fresh",
    evidence_at: overview.generated_at,
  };
  overview.nodes.items = [
    {
      node_id: targetNodeId,
      display_name: "客厅电脑",
      platform: "macos",
      state: "online",
      source: "coordinator_directory",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      service_count: 300,
    },
  ];
  overview.services.items = Array.from({ length: 300 }, (_, index) => ({
    service_id: `service_${index.toString(16).padStart(32, "0")}`,
    node_id: targetNodeId,
    display_name: index === 0 ? "照片备份" : null,
    protocol: "tcp",
    port: 9000 + index,
    access_address: `tcp://10.77.0.1:${9000 + index}`,
    accessibility: "network",
    lifecycle: "active",
    state: index === 299 ? "unknown" : "available",
    source: "coordinator_directory",
    evidence_at: overview.generated_at,
    freshness: "fresh",
  }));
  let writes = 0;
  page.on("request", (request) => {
    if (request.method() !== "GET") writes++;
  });
  await page.route("**/api/resources/overview", (route) =>
    route.fulfill({ json: overview }),
  );
  await page.route("**/api/operations", (route) => route.fulfill({ json: [] }));
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/app/overview");
  await page.getByText("客厅电脑", { exact: true }).click();
  const device = page
    .locator(".overview-device")
    .filter({ hasText: "客厅电脑" });
  await expect(
    device.getByRole("list", { name: "有名称的服务" }),
  ).toContainText("照片备份");
  await expect(device).toContainText(
    "299 个后台项目用途未识别 · 1 项状态需要确认",
  );
  await expect(device.getByText("tcp://10.77.0.1:9299")).toBeHidden();
  await expect(device.getByText("tcp://10.77.0.1:9000")).toBeHidden();
  await expect(device.getByText("Coordinator 目录")).toHaveCount(0);
  await expect(page.locator(".overview-card:visible")).toHaveCount(0);
  await expect(
    page.getByRole("list", { name: "需要你处理的请求" }),
  ).toHaveCount(0);
  expect(
    (await device.getByRole("list", { name: "有名称的服务" }).boundingBox())!.y,
  ).toBeLessThan(600);
  await page.screenshot({
    fullPage: true,
    path: testInfo.outputPath("services-300-summary.png"),
  });
  await device.getByText("查看全部 300 个检测项目（技术清单）").click();
  const list = device.getByRole("list", { name: "完整检测清单" });
  await expect(list.getByRole("listitem")).toHaveCount(300);
  expect((await list.boundingBox())!.height).toBeLessThanOrEqual(321);
  await device.getByRole("searchbox").fill("9299");
  await expect(list.getByRole("listitem")).toHaveCount(1);
  await expect(list).toContainText("状态未知");
  await device.getByRole("searchbox").fill("没有这个名称");
  await expect(
    device.getByText("没有匹配的项目，试试其他名称或地址。"),
  ).toBeVisible();
  await device.getByRole("searchbox").fill("");
  await expect(list.getByRole("listitem")).toHaveCount(300);
  for (const width of [1280, 320]) {
    await page.setViewportSize({ width, height: 760 });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth),
    ).toBeLessThanOrEqual(width);
  }
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(
    a11y.violations.filter((item) =>
      ["serious", "critical"].includes(item.impact ?? ""),
    ),
  ).toEqual([]);
  expect(writes).toBe(0);
});

test("批准摘要按精确身份匹配名称，陈旧名称不冒充访问者", async ({
  page,
  request,
}, testInfo) => {
  const overview = (await (
    await request.get("/api/resources/overview")
  ).json()) as ResourceOverview;
  const detail = makeOperationDetail();
  overview.nodes.items = [
    {
      node_id: requestNodeId,
      display_name: "书房电脑",
      platform: "windows",
      state: "online",
      source: "coordinator_directory",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      service_count: 0,
    },
  ];
  await page.route("**/api/resources/overview", (route) =>
    route.fulfill({ json: overview }),
  );
  await page.route(
    `**/api/operations/${detail.summary.operation_id}`,
    (route) => route.fulfill({ json: detail }),
  );
  await page.goto(`/app/operations/${detail.summary.operation_id}`);
  await expect(
    page.getByRole("region", { name: "这次请求会做什么" }),
  ).toContainText("书房电脑");
  await expect(page.getByText("查看技术详情与记录")).toBeVisible();
  await expect(page.getByText(detail.service_fingerprint)).toBeHidden();
  await page.getByRole("button", { name: "批准一次", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("书房电脑");
  await expect(dialog).toContainText("最多 5 分钟");
  await expect(dialog).toContainText(
    "能否修改内容或是否需要登录，取决于服务本身",
  );
  await expect(dialog).toContainText("访问检查通过不代表这些风险已确认安全");
  await page.screenshot({
    fullPage: true,
    path: testInfo.outputPath("named-request-confirmation.png"),
  });
  await dialog.getByText("调整批准有效期").click();
  await dialog.getByLabel("批准有效期截止时间").fill("");
  await dialog.getByText("调整批准有效期").click();
  await dialog.getByRole("button", { name: "确认批准一次" }).click();
  await expect(dialog.getByLabel("批准有效期截止时间")).toBeVisible();
  await page.keyboard.press("Escape");
  overview.nodes.items[0].freshness = "stale";
  await page.reload();
  await expect(page.getByText("访问者名称未知")).toBeVisible();
  await expect(
    page.getByText("请与发起请求的人确认身份，不要只凭设备名称判断。"),
  ).toBeVisible();
});
