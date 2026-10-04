import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";
import {
  makeOperationDetail,
  requestNodeId,
  targetNodeId,
} from "../src/features/operations/testFixtures";

test("三百个后台项目不淹没有名称的服务，完整清单可搜索到末项", async ({
  page,
  request,
}, testInfo) => {
  const overview = (await (
    await request.get("/api/resources/overview")
  ).json()) as ResourceOverview;
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
  await expect(dialog).toContainText("不一定只能看，也可能更改内容");
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
    page.getByText("请先与发起请求的人确认。不认识的请求不要批准。"),
  ).toBeVisible();
});
