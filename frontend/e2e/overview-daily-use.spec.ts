import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { makeOperationListItem } from "../src/features/operations/testFixtures";
import {
  dailyOverview,
  incidentDetail,
  incidentId,
} from "./overview-daily-use.fixture";

async function serveDailyOverview(page: Page) {
  const state = {
    overview: dailyOverview(),
    detail: incidentDetail(),
    operations: [makeOperationListItem()],
    failing: false,
    requests: [] as string[],
    writes: [] as string[],
  };
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() !== "GET") state.writes.push(path);
    state.requests.push(path);
    const payload =
      path === "/api/resources/overview"
        ? state.overview
        : path === `/api/incidents/${incidentId}`
          ? state.detail
          : path === "/api/operations"
            ? state.operations
            : undefined;
    await route.fulfill({
      status: payload === undefined ? 404 : state.failing ? 503 : 200,
      contentType: "application/json",
      body: JSON.stringify(
        payload === undefined || state.failing
          ? { detail: "模拟读取失败" }
          : payload,
      ),
    });
  });
  await page.goto("/app/overview");
  await expect(page.getByRole("searchbox", { name: "搜索服务" })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "刷新证据", exact: true }),
  ).toBeEnabled();
  return state;
}

for (const width of [1280, 320]) {
  test(`${width}px 多服务分页、键盘搜索与无溢出`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const state = await serveDailyOverview(page);
    const card = page.getByRole("article", { name: "已知服务" });
    await expect(card.getByRole("listitem")).toHaveCount(6);
    await expect(card.getByRole("status")).toHaveText(
      "共 13 项 · 匹配 13 项 · 显示 1–6 项",
    );
    const search = card.getByRole("searchbox");
    await search.focus();
    await page.keyboard.press("Tab");
    await expect(card.getByRole("button", { name: "下一页" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(card.getByRole("status")).toContainText("显示 7–12 项");
    await card.getByRole("button", { name: "下一页" }).click();
    await expect(card.getByRole("listitem")).toHaveCount(1);
    await expect(card.getByRole("status")).toContainText("显示 13–13 项");
    await search.fill("9012");
    await expect(card.getByText("本机服务 13", { exact: true })).toBeVisible();
    await expect(card).toContainText("tcp://service-13.example:9012");
    await page.getByRole("button", { name: "刷新证据", exact: true }).click();
    await expect(search).toHaveValue("9012");
    await search.fill("不存在的服务");
    await expect(card).toContainText("没有匹配的服务");
    await search.fill("");
    await expect(card.getByRole("listitem")).toHaveCount(6);
    await expect
      .poll(() =>
        page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      )
      .toBe(true);
    const accessibility = await new AxeBuilder({ page })
      .include("#overview-services")
      .analyze();
    expect(
      accessibility.violations.filter((item) =>
        ["serious", "critical"].includes(item.impact ?? ""),
      ),
    ).toEqual([]);
    await card.screenshot({
      path: testInfo.outputPath(`services-${width}.png`),
    });
    await page.screenshot({
      path: testInfo.outputPath(`overview-${width}.png`),
      fullPage: true,
    });
    expect(state.writes).toEqual([]);
  });
}

test("三类定时更新、失败恢复与输入保持，隐藏和离开页面停止轮询", async ({
  page,
}, testInfo) => {
  await page.clock.install();
  const state = await serveDailyOverview(page);
  const search = page.getByRole("searchbox", { name: "搜索服务" });
  await search.fill("本机服务");
  await page.getByRole("button", { name: "查看调查详情" }).click();
  const composer = page.getByRole("textbox", { name: "针对这个事件追问" });
  await composer.fill("正在输入的追问不要丢失");
  state.overview.local.version = "0.2.0";
  state.detail.incident.report.conclusion = "定时更新后的调查结论";
  state.operations = [];
  await page.clock.fastForward(30_000);
  await expect(page.getByText("0.2.0", { exact: true })).toBeVisible();
  await expect(page.getByText("定时更新后的调查结论")).toBeVisible();
  await expect(page.getByText("当前没有待办", { exact: true })).toBeVisible();
  await expect(composer).toHaveValue("正在输入的追问不要丢失");
  await expect(search).toHaveValue("本机服务");
  for (const path of [
    "/api/resources/overview",
    "/api/operations",
    `/api/incidents/${incidentId}`,
  ]) {
    expect(
      state.requests.filter((item) => item === path).length,
    ).toBeGreaterThanOrEqual(2);
  }
  state.failing = true;
  await page.getByRole("button", { name: "刷新证据", exact: true }).click();
  await page.clock.fastForward(2_000);
  await expect(
    page.getByText("刷新失败，下面是上一次成功读取的缓存。"),
  ).toBeVisible();
  await expect(
    page.getByText("调查详情刷新失败，以下是上次读取的旧详情，不能视为最新。"),
  ).toBeVisible();
  await expect(
    page.getByText("操作待办暂时无法读取；资源和 incident 总览不受影响。"),
  ).toBeVisible();
  await expect(composer).toHaveValue("正在输入的追问不要丢失");
  await page.screenshot({
    path: testInfo.outputPath("refresh-failed.png"),
    fullPage: true,
  });
  state.failing = false;
  state.detail.incident.report.conclusion = "恢复后的调查结论";
  await page.getByRole("button", { name: "刷新证据", exact: true }).click();
  await expect(page.getByText("恢复后的调查结论")).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(composer).toHaveValue("正在输入的追问不要丢失");
  await expect(search).toHaveValue("本机服务");
  await expect(
    page.getByRole("button", { name: "刷新证据", exact: true }),
  ).toBeEnabled();
  const beforeHidden = state.requests.length;
  // 模拟浏览器可见性事件，验证 Query 使用的隐藏状态边界。
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    window.dispatchEvent(new Event("visibilitychange"));
  });
  await page.clock.fastForward(60_000);
  expect(state.requests).toHaveLength(beforeHidden);
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
    window.dispatchEvent(new Event("visibilitychange"));
  });
  await page.clock.fastForward(30_000);
  await expect.poll(() => state.requests.length).toBeGreaterThan(beforeHidden);
  await expect(
    page.getByRole("button", { name: "刷新证据", exact: true }),
  ).toBeEnabled();
  await page.getByRole("link", { name: "查看全部操作记录" }).click();
  await expect(page).toHaveURL(/\/app\/operations$/);
  // 允许导航前已经发出的读取完成，再验证卸载后不会启动下一轮。
  await page.clock.fastForward(1_000);
  const overviewRequestsAfterLeaving = state.requests.filter(
    (path) =>
      path === "/api/resources/overview" ||
      path === `/api/incidents/${incidentId}`,
  ).length;
  await page.clock.fastForward(60_000);
  expect(
    state.requests.filter(
      (path) =>
        path === "/api/resources/overview" ||
        path === `/api/incidents/${incidentId}`,
    ),
  ).toHaveLength(overviewRequestsAfterLeaving);
  expect(state.writes).toEqual([]);
});
