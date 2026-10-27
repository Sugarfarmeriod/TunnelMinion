import { expect, test } from "@playwright/test";
import {
  makeOperationDetail,
  makeOperationListItem,
  operationId,
} from "../src/features/operations/testFixtures";
import type { RunEvent, RunView } from "../src/features/chat/contracts";

const origin = "http://127.0.0.1:4176";
test.use({ baseURL: origin });

for (const width of [1280, 320]) {
  test(`${width}px 预览保留记录浏览，所有操作入口禁用`, async ({
    page,
  }, testInfo) => {
    const writes: string[] = [];
    page.on("request", (request) => {
      if (request.method() !== "GET") writes.push(request.url());
    });
    const thread = {
      thread_id: `thread_${"9".repeat(32)}`,
      created_at: "2026-10-18T08:00:00Z",
      updated_at: "2026-10-18T08:00:00Z",
      message_count: 1,
    };
    const run: RunView = {
      run_id: `run_${"8".repeat(32)}`,
      thread_id: thread.thread_id,
      status: "completed",
      created_at: thread.created_at,
      finished_at: thread.updated_at,
      result: null,
      error_code: null,
      error_message: null,
      failure: null,
    };
    await page.route("**/api/threads", (route) =>
      route.fulfill({ json: [thread] }),
    );
    await page.route(`**/api/ui/threads/${thread.thread_id}`, (route) =>
      route.fulfill({
        json: {
          thread,
          service_id: null,
          messages: [
            {
              role: "user",
              content: "这是一条已有的问题",
              created_at: thread.created_at,
              run_id: run.run_id,
            },
          ],
        },
      }),
    );
    await page.route(`**/api/runs/${run.run_id}`, (route) =>
      route.fulfill({ json: run }),
    );
    const event: RunEvent = {
      sequence: 1,
      event_type: "finished",
      created_at: thread.updated_at,
      run_id: run.run_id,
      target_node_id: null,
      tool_name: null,
      tool_status: null,
      elapsed_ms: null,
      tool_run_id: null,
      stop_reason: "completed",
      message: null,
    };
    await page.route(`**/api/runs/${run.run_id}/events?*`, (route) =>
      route.fulfill({
        contentType: "text/event-stream",
        body: `id: 1\nevent: finished\ndata: ${JSON.stringify(event)}\n\n`,
      }),
    );
    await page.route("**/api/operations", (route) =>
      route.fulfill({ json: [makeOperationListItem()] }),
    );
    await page.route(`**/api/operations/${operationId}`, (route) =>
      route.fulfill({ json: makeOperationDetail() }),
    );
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`/app/map?thread=${thread.thread_id}`);
    await expect(page.getByText(/预览模式：只看程序和已有记录/)).toBeVisible();
    await expect(
      page.getByText("这是一条已有的问题", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("textbox", { name: "问题", exact: true }),
    ).toBeDisabled();
    await expect(
      page.getByRole("button", { name: "发送问题", exact: true }),
    ).toBeDisabled();
    await expect(
      page.getByRole("link", { name: "连接模型", exact: true }),
    ).toHaveCount(0);
    await page.getByRole("button", { name: "刷新这段对话" }).click();
    await page.getByRole("button", { name: "关闭对话" }).click();
    await expect(
      page.getByRole("textbox", { name: "想问点什么？" }),
    ).toBeDisabled();
    await page.getByRole("button", { name: "更多 ▾" }).click();
    await page.getByRole("link", { name: "设置", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "检查并确认保存" }),
    ).toBeDisabled();
    await expect(
      page.getByRole("button", { name: "重新验证一次" }),
    ).toBeDisabled();
    await page.getByRole("link", { name: "← 回到地图" }).click();
    await page.getByRole("button", { name: "更多 ▾" }).click();
    await page.getByRole("link", { name: "请求记录", exact: true }).click();
    await page.getByRole("link", { name: "查看请求", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "批准一次", exact: true }),
    ).toBeDisabled();
    await page.getByRole("button", { name: "刷新记录", exact: true }).click();
    await page.screenshot({
      path: testInfo.outputPath(`read-only-preview-${width}.png`),
      fullPage: true,
    });
    expect(writes).toEqual([]);
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth + 1,
      ),
    ).toBe(true);
  });
}

test("预览服务器拒绝直接写接口和真实访问，不依赖页面按钮", async ({
  request,
}) => {
  for (const [method, path] of [
    ["POST", "/api/threads"],
    ["POST", "/api/model-config/validate"],
    ["PUT", "/api/model-config"],
    ["DELETE", "/api/model-config"],
    ["POST", `/api/operations/${operationId}/approve`],
    ["GET", `/api/operations/${operationId}/access/`],
  ]) {
    const response = await request.fetch(path!, {
      method,
      headers: { Origin: origin, "X-TunnelMinion-Request": "same-origin" },
    });
    expect(response.status()).toBe(403);
    expect((await response.json()).detail.code).toBe("read_only_preview");
  }
  expect((await request.get("/api/threads")).status()).toBe(200);
});
