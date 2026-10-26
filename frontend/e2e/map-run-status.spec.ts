import { expect, test } from "@playwright/test";
import {
  makeMessage,
  makeRun,
  makeThread,
} from "../src/features/chat/testFixtures";
import { mockMapChat } from "./mapChatFixture";

test("停止检查需要确认，确认后只发送一次取消请求并保留原问题", async ({
  page,
}) => {
  const backend = await mockMapChat(page);
  let cancels = 0;
  await page.route("**/api/runs/*/cancel", (route) => {
    cancels += 1;
    return route.fulfill({ json: backend.cancel() });
  });
  await page.goto("/app/map");
  await page.getByRole("button", { name: "哪个程序最占内存？" }).click();
  await page.getByRole("button", { name: "停止这次检查" }).click();
  const confirmation = page.getByRole("alertdialog", {
    name: "要停止这次检查吗？",
  });
  await expect(
    confirmation.getByRole("button", { name: "暂不停止" }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(confirmation).toHaveCount(0);
  expect(cancels).toBe(0);
  await page.getByRole("button", { name: "停止这次检查" }).click();
  await confirmation.getByRole("button", { name: "确认停止" }).click();
  await expect(page.getByText("已停止检查", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("textbox", { name: "问题", exact: true }),
  ).toBeEnabled();
  await expect(
    page.getByText("哪个程序最占内存？", { exact: true }).last(),
  ).toBeVisible();
  expect(cancels).toBe(1);
  expect(backend.questions).toHaveLength(1);
});

for (const [status, label] of [
  ["failed", "这次没查完"],
  ["cancelled", "已停止检查"],
  ["interrupted", "检查被打断"],
] as const) {
  test(`${status} 保留检查进展并允许继续问，不自动重跑`, async ({ page }) => {
    await mockMapChat(page);
    const run = makeRun(status, {
      error_code: status === "failed" ? "model_authentication_failed" : null,
    });
    const detail = {
      thread: makeThread(),
      messages: [makeMessage("user", "检查相册")],
      context: null,
    };
    await page.route(/\/api\/(?:ui\/)?threads\/thread_[0-9a-f]+$/, (route) =>
      route.fulfill({ json: detail }),
    );
    await page.route(/\/api\/runs\/run_[0-9a-f]+$/, (route) =>
      route.fulfill({ json: run }),
    );
    let writes = 0;
    page.on("request", (request) => {
      if (request.method() !== "GET") writes += 1;
    });
    await page.goto(`/app/map?thread=${detail.thread.thread_id}`);
    await expect(page.getByText(label, { exact: true })).toBeVisible();
    await expect(
      page.getByRole("textbox", { name: "问题", exact: true }),
    ).toBeEnabled();
    await expect(page.getByText("检查相册", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "刷新这段对话" }).click();
    expect(writes).toBe(0);
    await page.getByRole("button", { name: "关闭对话" }).click();
    await expect(
      page.getByRole("heading", { name: "我的服务网络" }),
    ).toBeVisible();
  });
}
