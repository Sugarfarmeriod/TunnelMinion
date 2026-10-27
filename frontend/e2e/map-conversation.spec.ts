import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { allowedToolNames } from "../src/features/chat/api";
import { makeService } from "../src/features/service-map/testFixtures";
import { mockMapChat } from "./mapChatFixture";

test("地图提问、后台回答、未读提示和证据在同一抽屉完成", async ({ page }) => {
  const backend = await mockMapChat(page, [makeService({ state: "stopped" })]);
  const writes: string[] = [];
  page.on("request", (request) => {
    if (request.method() !== "GET") writes.push(request.url());
  });
  await page.goto("/app/map");
  await page.getByRole("button", { name: "这台电脑，在线，1 个服务" }).click();
  await page.getByRole("button", { name: "问问 WireGuard Panel" }).click();
  const drawer = page.getByRole("dialog", { name: "对话", exact: true });
  await expect(drawer).toBeVisible();
  await expect.poll(() => backend.questions.length).toBe(1);
  expect(backend.questions[0]).toEqual({
    question: "WireGuard Panel怎么打不开？",
    about: { node_id: backend.local.node_id, service_key: "python:app.py" },
    tool_names: [...allowedToolNames],
  });
  await page.getByRole("button", { name: "关闭对话" }).click();
  backend.finish();
  await expect(page.getByLabel("1 条未读回答")).toBeVisible();
  await page.getByRole("button", { name: /^对话/ }).click();
  await expect(
    drawer.getByText("已检查这台电脑，服务运行正常。", { exact: true }),
  ).toBeVisible();
  await expect(drawer.getByText("推断 · 尚未逐条核对")).toBeVisible();
  await expect(page.getByLabel("1 条未读回答")).toHaveCount(0);
  await drawer.getByText("查看用了哪些工具与证据").focus();
  await page.keyboard.press("Enter");
  await expect(drawer.getByText("最终回答引用的证据")).toBeVisible();
  expect(writes.filter((url) => url.endsWith("/cancel"))).toHaveLength(0);
  expect(writes).toHaveLength(2);
  const result = await new AxeBuilder({ page }).analyze();
  expect(
    result.violations.filter(
      (item) => item.impact === "serious" || item.impact === "critical",
    ),
  ).toEqual([]);
});

for (const width of [1440, 1000, 760, 320]) {
  test(`${width}px 正常服务仅预填，抽屉保持地图选择、页码和草稿`, async ({
    page,
  }, testInfo) => {
    const services = Array.from({ length: 21 }, (_, index) =>
      makeService({
        key: `python:${index}`,
        name: `相册预览与备份服务${index}`,
      }),
    );
    const backend = await mockMapChat(page, services);
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/app/map");
    const stage = page.locator(".map-stage");
    const before = (await stage.boundingBox())!;
    await page
      .getByRole("button", { name: "这台电脑，在线，21 个服务" })
      .click();
    await page.getByRole("button", { name: "下一页", exact: true }).click();
    const pager = await page
      .getByRole("navigation", { name: "服务分页" })
      .textContent();
    await page
      .getByRole("button", { name: /^问问 相册/ })
      .first()
      .click();
    const input = page.getByRole("textbox", { name: "问题", exact: true });
    await expect(input).toBeFocused();
    await expect(
      page.getByText(/关于：这台电脑 · 相册预览与备份服务\d+（Python）/),
    ).toBeVisible();
    await input.fill("先保留这个问题");
    expect(backend.questions).toEqual([]);
    const after = (await stage.boundingBox())!;
    if (width >= 1100) expect(before.width - after.width).toBeGreaterThan(400);
    else expect(after.width).toBe(before.width);
    const drawer = page.getByRole("dialog", { name: "对话", exact: true });
    if (width <= 760) expect((await drawer.boundingBox())!.width).toBe(width);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: testInfo.outputPath(`map-drawer-${width}.png`),
    });
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    expect(
      await page.getByRole("navigation", { name: "服务分页" }).textContent(),
    ).toBe(pager);
    await page.getByRole("button", { name: "对话", exact: true }).click();
    await expect(input).toHaveValue("先保留这个问题");
    await page.getByRole("button", { name: "新对话", exact: true }).click();
    await expect(input).toHaveValue("");
    await expect(page.getByText(/关于：/)).toHaveCount(0);
  });
}

test("全局问题创建新对话；旧链接保留 thread 并打开抽屉", async ({ page }) => {
  const backend = await mockMapChat(page);
  await page.goto("/app/map");
  await page
    .getByRole("textbox", { name: "想问点什么？" })
    .fill("这台电脑现在怎么样？");
  await page.getByRole("button", { name: "问问 Agent", exact: true }).click();
  await expect.poll(() => backend.questions.length).toBe(1);
  expect(backend.questions[0]?.about).toBeUndefined();
  backend.finish();
  await expect(
    page.getByText("已检查这台电脑，服务运行正常。", { exact: true }),
  ).toBeVisible();
  for (const path of ["overview", "chat"]) {
    await page.goto(`/app/${path}?thread=${backend.threadId}`);
    await expect(page).toHaveURL(`/app/map?thread=${backend.threadId}`);
    await expect(
      page.getByRole("dialog", { name: "对话", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("这台电脑现在怎么样？", { exact: true }),
    ).toBeVisible();
  }
});
