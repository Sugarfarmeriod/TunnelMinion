import { expect, test } from "@playwright/test";
import { makeThread } from "../src/features/chat/testFixtures";
import { mockMapChat } from "./mapChatFixture";

test("以往对话按 20 条分页并恢复原对象，标题和电脑名称可辨认", async ({
  page,
}) => {
  const backend = await mockMapChat(page);
  const context = {
    node_id: backend.local.node_id,
    service_key: "python:app.py",
    service_name: "WireGuard Panel",
  };
  const threads = Array.from({ length: 41 }, (_, index) => ({
    ...makeThread(`thread_${String(index + 1).padStart(32, "0")}`),
    title: `以往问题 ${index}`,
    context,
  }));
  await page.route("**/api/threads", (route) =>
    route.fulfill({ json: threads }),
  );
  await page.route(/\/api\/ui\/threads\/thread_[0-9a-f]+$/, (route) => {
    const id = new URL(route.request().url()).pathname.split("/").at(-1);
    return route.fulfill({
      json: {
        thread: threads.find((thread) => thread.thread_id === id),
        context,
        messages: [],
      },
    });
  });
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/app/map");
  await page.getByRole("button", { name: "对话", exact: true }).click();
  await page.getByRole("tab", { name: "以往对话" }).click();
  const history = page.getByRole("tabpanel", { name: "以往对话" });
  await expect(history.getByRole("listitem")).toHaveCount(20);
  await expect(
    history.getByRole("button", { name: /^以往问题 0 / }),
  ).toContainText("这台电脑");
  await page.getByRole("button", { name: "下一页对话" }).click();
  await expect(history.getByRole("listitem")).toHaveCount(20);
  await page.getByRole("button", { name: "下一页对话" }).click();
  await expect(history.getByRole("listitem")).toHaveCount(1);
  await expect(history.getByText("第 3 / 3 页")).toBeVisible();
  await page.getByRole("button", { name: /^以往问题 40 / }).click();
  await expect(page.getByRole("tab", { name: "当前对话" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(
    page.getByText("关于：这台电脑 · WireGuard Panel（Python）"),
  ).toBeVisible();
  await expect(
    page.getByRole("textbox", { name: "问题", exact: true }),
  ).toBeFocused();
  expect(backend.questions).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});
