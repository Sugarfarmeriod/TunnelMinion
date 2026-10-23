import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../src/features/service-map/testFixtures";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/ui/overview", (route) =>
    route.fulfill({ json: makeMapOverview() }),
  );
  await page.route("**/api/services/local", (route) =>
    route.fulfill({
      json: makeLocalServices([
        makeService(),
        makeService({
          key: "program:候选程序 #1",
          name: "候选程序",
          kind: "program",
          tier: "review",
        }),
        makeService({
          key: "docker:old",
          name: "隐藏的容器",
          kind: "docker",
          tier: "hidden",
          mark: "hidden",
        }),
      ]),
    }),
  );
});

test("/app 默认是服务地图，键盘点开电脑、Esc 和点空白可关闭", async ({
  page,
}, testInfo) => {
  await page.goto("/app");
  await expect(page).toHaveURL(/\/app\/map$/);
  await expect(page.getByRole("heading", { name: "服务地图" })).toBeVisible();
  const navigation = page.getByRole("navigation", { name: "主要导航" });
  await expect(navigation.getByRole("link").first()).toHaveText("服务地图");
  const computer = page.getByRole("button", {
    name: "这台电脑，在线，2 个服务",
  });
  await computer.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "这台电脑上的服务" });
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "关闭服务框" }),
  ).toBeFocused();
  await expect(
    dialog.getByRole("link", { name: "打开 WireGuard Panel" }),
  ).toHaveAttribute("href", "http://localhost:8787");
  await expect(dialog.getByText("隐藏的容器")).toHaveCount(0);
  await page.screenshot({
    path: testInfo.outputPath("service-map-desktop.png"),
    fullPage: true,
  });
  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter(
      ({ impact }) => impact === "serious" || impact === "critical",
    ),
  ).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(computer).toBeFocused();
  await computer.click();
  await computer.click();
  await expect(dialog).toHaveCount(0);
  await computer.click();
  await page.locator(".map-canvas").click({ position: { x: 20, y: 20 } });
  await expect(dialog).toHaveCount(0);
  await expect(computer).toBeFocused();
  await navigation.getByRole("link", { name: "工作台", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/overview$/);
  await expect(
    page.getByRole("heading", { name: "工作台", exact: true }),
  ).toBeVisible();
});

test("标记与恢复按响应更新清单，服务 key 编码且不追加读取", async ({
  page,
}) => {
  let reads = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/api/services/local")) reads++;
  });
  const candidate = makeService({
    key: "program:候选程序 #1",
    name: "候选程序",
    kind: "program",
    tier: "show",
    mark: "mine",
  });
  const hidden = makeService({
    key: "docker:old",
    name: "隐藏的容器",
    kind: "docker",
    tier: "hidden",
    mark: "hidden",
  });
  const writes: {
    method: string;
    path: string;
    body: unknown;
    header: string | undefined;
  }[] = [];
  await page.route("**/api/services/marks/**", async (route) => {
    const request = route.request();
    writes.push({
      method: request.method(),
      path: new URL(request.url()).pathname,
      body: request.method() === "PUT" ? request.postDataJSON() : null,
      header: request.headers()["x-tunnelminion-request"],
    });
    await route.fulfill({
      json: makeLocalServices([
        makeService(),
        candidate,
        request.method() === "DELETE"
          ? { ...hidden, tier: "review", mark: null }
          : hidden,
      ]),
    });
  });
  await page.goto("/app/map");
  await page
    .getByRole("button", { name: /^这台电脑，在线，2 个服务$/ })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "是我的服务 候选程序" }).click();
  await expect(
    dialog.getByRole("button", { name: "不再显示 候选程序" }),
  ).toBeVisible();
  await dialog.getByRole("button", { name: "已隐藏的 1 个" }).click();
  await dialog.getByRole("button", { name: "恢复 隐藏的容器" }).click();
  await expect(
    dialog.getByRole("button", { name: "是我的服务 隐藏的容器" }),
  ).toBeVisible();
  expect(writes).toEqual([
    {
      method: "PUT",
      path: `/api/services/marks/${encodeURIComponent(candidate.key)}`,
      body: { mark: "mine" },
      header: "same-origin",
    },
    {
      method: "DELETE",
      path: `/api/services/marks/${encodeURIComponent(hidden.key)}`,
      body: null,
      header: "same-origin",
    },
  ]);
  expect(reads).toBe(1);
});

for (const width of [320, 700]) {
  test(`${width}px 窄屏在拓扑图下方显示面板且没有横向溢出`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 760 });
    await page.route("**/api/ui/overview", (route) =>
      route.fulfill({ json: makeMapOverview("macos") }),
    );
    await page.goto("/app");
    await page
      .getByRole("button", { name: /^这台电脑，在线，2 个服务$/ })
      .click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toHaveClass(/is-inline/);
    await expect(page.locator("svg[data-platform='mini']")).toBeVisible();
    const canvas = await page.locator(".map-canvas").boundingBox();
    const panel = await dialog.boundingBox();
    expect(panel!.y).toBeGreaterThanOrEqual(canvas!.y + canvas!.height);
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth,
      ),
    ).toBe(true);
    await dialog.getByRole("button", { name: "已隐藏的 1 个" }).click();
    await expect(
      dialog.getByRole("button", { name: "恢复 隐藏的容器" }),
    ).toBeVisible();
    const results = await new AxeBuilder({ page }).analyze();
    expect(
      results.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
    await page.screenshot({
      path: testInfo.outputPath(`service-map-${width}.png`),
      fullPage: true,
    });
  });
}

test("大量服务可搜索翻页，小高度保留明显滚动提示，减少动态效果时停止动画", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1100, height: 800 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.route("**/api/services/local", (route) =>
    route.fulfill({
      json: makeLocalServices(
        Array.from({ length: 18 }, (_, index) =>
          makeService({
            key: `python:${index}`,
            name: `服务 ${index}`,
            endpoints: [
              {
                protocol: "tcp",
                address: "0.0.0.0",
                port: 8000 + index,
                has_web_page: true,
              },
            ],
          }),
        ),
      ),
    }),
  );
  await page.goto("/app/map");
  const computer = page.getByRole("button", {
    name: "这台电脑，在线，18 个服务",
  });
  await computer.click();
  const dialog = page.getByRole("dialog");
  const count = await dialog.getByRole("listitem").count();
  expect(count).toBeGreaterThanOrEqual(3);
  expect(count).toBeLessThanOrEqual(6);
  await dialog.getByRole("button", { name: "下一页" }).click();
  await expect(dialog.getByText(/第 2 \/ \d+ 页/)).toBeVisible();
  await page.keyboard.press("ArrowLeft");
  await expect(dialog.getByRole("button", { name: "上一页" })).toBeDisabled();
  await dialog.getByRole("searchbox").fill("8017");
  await expect(dialog.getByRole("listitem")).toHaveCount(1);
  await expect(dialog.getByText("服务 17", { exact: true })).toBeVisible();
  await dialog.getByRole("searchbox").fill("");
  await page.setViewportSize({ width: 1100, height: 430 });
  await expect(dialog.getByRole("listitem")).toHaveCount(3);
  await expect(dialog.getByText("▼ 下面还有")).toBeVisible();
  await page.locator(".map-scroll").evaluate((element) => {
    element.scrollTop = element.scrollHeight;
  });
  await expect(dialog.getByText("▼ 下面还有")).toHaveCount(0);
  expect(
    await page
      .locator(".map-blink")
      .first()
      .evaluate((element) => getComputedStyle(element).animationName),
  ).toBe("none");
  expect(
    await page
      .locator(".map-computer")
      .evaluate((element) => getComputedStyle(element).transform),
  ).toBe("none");
});

test("靠右边缘的提示框与服务框向左显示", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/app/map");
  const computer = page.getByRole("button", {
    name: "这台电脑，在线，2 个服务",
  });
  await expect(computer).toBeVisible();
  await page.locator(".map-node-position").evaluate((element) => {
    (element as HTMLElement).style.left = "84%";
  });
  await computer.hover();
  const tooltip = page.getByRole("tooltip");
  await expect(tooltip).toContainText("Windows");
  const tip = await tooltip.boundingBox();
  const node = await computer.boundingBox();
  expect(tip!.x + tip!.width).toBeLessThanOrEqual(node!.x);
  await computer.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toHaveClass(/tail-left/);
  const panel = await dialog.boundingBox();
  expect(panel!.x + panel!.width).toBeLessThanOrEqual(node!.x);
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth,
    ),
  ).toBe(true);
});
