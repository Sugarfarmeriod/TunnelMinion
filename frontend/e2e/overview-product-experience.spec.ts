import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import type { ResourceOverview } from "../src/api/schemas/overview";

const nodeA = `node_${"1".repeat(32)}`;
const nodeB = `node_${"2".repeat(32)}`;

test("没有请求时首页只呈现设备，其他信息按需打开", async ({
  page,
  request,
}, testInfo) => {
  const response = await request.get("/api/resources/overview");
  const overview = (await response.json()) as ResourceOverview;
  const evidenceAt = overview.generated_at;
  overview.nodes.items = [
    {
      node_id: nodeA,
      display_name: "工作室 Mac",
      platform: "macos",
      state: "online",
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      service_count: 7,
    },
    {
      node_id: nodeB,
      display_name: "客厅电脑",
      platform: "windows",
      state: "online",
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      service_count: 6,
    },
  ];
  overview.services.items = Array.from({ length: 13 }, (_, index) => ({
    service_id: `service_${index.toString(16).padStart(32, "0")}`,
    node_id: index < 7 ? nodeA : nodeB,
    display_name: index === 0 ? "照片备份" : null,
    protocol: "tcp",
    port: 9000 + index,
    access_address: `tcp://10.77.0.${index < 7 ? 1 : 2}:${9000 + index}`,
    accessibility: "network",
    lifecycle: "active",
    state: "available",
    source: "coordinator_directory",
    evidence_at: evidenceAt,
    freshness: "fresh",
  }));

  await page.route("**/api/resources/overview", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(overview),
    }),
  );
  await page.route("**/api/operations", (route) => route.fulfill({ json: [] }));
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/app/overview");

  await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
  await expect(
    page.getByRole("list", { name: "需要你处理的请求" }),
  ).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "需要你处理" })).toHaveCount(
    0,
  );
  await expect(page.locator(".overview-card:visible")).toHaveCount(0);
  await expect(page.getByText("2 台设备 · 13 个检测项目")).toBeVisible();
  await expect(page.getByText("工作室 Mac", { exact: true })).toBeVisible();
  await expect(page.getByText("客厅电脑", { exact: true })).toBeVisible();
  await expect(page.getByText("更多信息", { exact: true })).toBeVisible();
  await expect(page.getByText("本机程序正在运行")).toBeHidden();
  await expect(page.getByText(/第 \d+ \/ \d+ 页/)).toHaveCount(0);
  await expect(page.getByText(nodeA.slice(0, 8))).toHaveCount(0);
  expect(
    (await page.getByText("客厅电脑", { exact: true }).boundingBox())!.y,
  ).toBeLessThan(600);

  await page.screenshot({
    animations: "disabled",
    fullPage: true,
    path: testInfo.outputPath("overview-single-view-1280.png"),
  });

  await page.getByText("工作室 Mac", { exact: true }).click();
  const device = page
    .locator(".overview-device")
    .filter({ hasText: "工作室 Mac" });
  await expect(
    device.getByRole("list", { name: "有名称的服务" }).getByRole("listitem"),
  ).toHaveCount(1);
  await expect(
    device
      .getByRole("list", { name: "有名称的服务" })
      .getByText("照片备份", { exact: true }),
  ).toBeVisible();
  await expect(device.getByText("用途未识别的后台项目").first()).toBeHidden();
  await device.getByText("查看全部 7 个检测项目（技术清单）").click();
  await expect(
    device.getByRole("list", { name: "完整检测清单" }).getByRole("listitem"),
  ).toHaveCount(7);
  await expect(device.getByText("用途未识别的后台项目")).toHaveCount(6);
  await expect(device).toContainText("tcp://10.77.0.1:9006");
  await page.getByText("更多信息", { exact: true }).click();
  await expect(page.getByText("本机程序正在运行")).toBeVisible();
  await page.getByText("更多信息", { exact: true }).click();

  const accessibility = await new AxeBuilder({ page })
    .include("main")
    .analyze();
  expect(
    accessibility.violations.filter((item) =>
      ["serious", "critical"].includes(item.impact ?? ""),
    ),
  ).toEqual([]);
  await page.screenshot({
    animations: "disabled",
    fullPage: true,
    path: testInfo.outputPath("overview-product-experience-1280.png"),
  });

  await page.setViewportSize({ width: 320, height: 760 });
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth))
    .toBeLessThanOrEqual(320);
  await page.screenshot({
    animations: "disabled",
    fullPage: true,
    path: testInfo.outputPath("overview-product-experience-320.png"),
  });
});
