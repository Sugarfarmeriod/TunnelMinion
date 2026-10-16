import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";
import type { RunEvent, RunView } from "../src/features/chat/contracts";

for (const width of [1280, 320]) {
  test(`${width}px 重开对话继续原程序，恢复清单且切换不串用`, async ({
    page,
    request,
  }, testInfo) => {
    const overview = (await (
      await request.get("/api/resources/overview")
    ).json()) as ResourceOverview;
    const nodeId = `node_${"c".repeat(32)}`;
    const serviceId = `service_${"d".repeat(32)}`;
    const oldThreadId = `thread_${"a".repeat(32)}`;
    const recentThreadId = `thread_${"b".repeat(32)}`;
    const runId = `run_${"b".repeat(32)}`;
    overview.schema_version = "resource-overview-programs/v1";
    overview.model = {
      ...overview.model,
      configured: true,
      status: "available",
    };
    overview.nodes = {
      source: "local_observation",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      error: null,
      items: [
        {
          node_id: nodeId,
          display_name: "本机",
          platform: "windows",
          state: "local",
          source: "local_observation",
          evidence_at: overview.generated_at,
          freshness: "fresh",
          service_count: 1,
        },
      ],
    };
    overview.services = {
      source: "local_observation",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      error: null,
      items: [
        {
          service_id: serviceId,
          node_id: nodeId,
          display_name: "Python · 相册.py · 43123",
          application: {
            group_id: `application_${"e".repeat(32)}`,
            name: "相册",
            kind: "python",
          },
          protocol: "tcp",
          port: 43123,
          access_address: "tcp://127.0.0.1:43123",
          accessibility: "loopback",
          lifecycle: "active",
          state: "available",
          source: "local_observation",
          evidence_at: overview.generated_at,
          freshness: "fresh",
        },
      ],
    };
    overview.incidents.items = [];
    const waiting = {
      ...overview,
      services: {
        ...overview.services,
        items: [],
        evidence_at: null,
        freshness: "unknown",
      },
    };
    const oldThread = {
      thread_id: oldThreadId,
      created_at: "2026-10-01T08:00:00Z",
      updated_at: "2026-10-01T08:00:00Z",
      message_count: 1,
    };
    const recentThread = {
      ...oldThread,
      thread_id: recentThreadId,
      updated_at: "2026-10-15T08:28:00Z",
    };
    const newThread = {
      ...recentThread,
      thread_id: `thread_${"c".repeat(32)}`,
      message_count: 0,
    };
    const threads = [oldThread, recentThread];
    let allowRecovery = () => {};
    const recovery = new Promise<void>((resolve) => {
      allowRecovery = resolve;
    });
    let reads = 0;
    let writes = 0;
    page.on("request", (request) => {
      if (request.method() !== "GET") writes += 1;
    });
    await page.route("**/api/ui/overview", async (route) => {
      reads += 1;
      if (reads === 1) return route.fulfill({ json: waiting });
      await recovery;
      return route.fulfill({ json: overview });
    });
    await page.route("**/api/operations", (route) =>
      route.fulfill({ json: [] }),
    );
    await page.route("**/api/threads", (route) => {
      if (route.request().method() === "POST") {
        threads.push(newThread);
        return route.fulfill({ json: newThread });
      }
      return route.fulfill({ json: threads });
    });
    for (const thread of [oldThread, recentThread, newThread]) {
      await page.route(`**/api/ui/threads/${thread.thread_id}`, (route) =>
        route.fulfill({
          json: {
            thread,
            service_id: thread.thread_id === recentThreadId ? serviceId : null,
            messages:
              thread === newThread
                ? []
                : [
                    {
                      role: "user",
                      content:
                        thread.thread_id === recentThreadId
                          ? "最近一次检查：相册打不开"
                          : "以前的检查记录",
                      created_at: thread.updated_at,
                      run_id: runId,
                    },
                  ],
          },
        }),
      );
    }
    let run: RunView = {
      run_id: runId,
      thread_id: recentThreadId,
      status: "failed",
      created_at: recentThread.updated_at,
      finished_at: recentThread.updated_at,
      result: null,
      error_code: "fixture_failed",
      error_message: "上次检查没有完成",
      failure: null,
    };
    await page.route(`**/api/runs/${runId}`, (route) =>
      route.fulfill({ json: run }),
    );
    await page.route(`**/api/runs/${runId}/events?*`, (route) => {
      const event: RunEvent = {
        sequence: 1,
        event_type: run.status === "failed" ? "failed" : "finished",
        created_at: recentThread.updated_at,
        run_id: runId,
        target_node_id: null,
        tool_name: null,
        tool_status: null,
        elapsed_ms: null,
        tool_run_id: null,
        stop_reason: "completed",
        message: null,
      };
      return route.fulfill({
        contentType: "text/event-stream",
        body: `id: 1\nevent: ${event.event_type}\ndata: ${JSON.stringify(event)}\n\n`,
      });
    });
    await page.route(
      `**/api/ui/threads/${recentThreadId}/runs`,
      async (route) => {
        expect(route.request().method()).toBe("POST");
        expect(route.request().postDataJSON()).toMatchObject({
          service_id: serviceId,
          question: "我想继续刚才的检查",
        });
        run = {
          ...run,
          status: "completed",
          error_code: null,
          error_message: null,
        };
        return route.fulfill({ json: run });
      },
    );
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/app/overview");
    await expect(
      page.getByText("最近一次检查：相册打不开", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("以前的检查记录", { exact: true })).toHaveCount(
      0,
    );
    const question = page.getByRole("textbox", { name: "问题", exact: true });
    await question.fill("我想继续刚才的检查");
    await expect(question).toBeFocused();
    allowRecovery();
    await expect(page.getByLabel("正在讨论的程序")).toContainText("相册");
    await expect(question).toHaveValue("我想继续刚才的检查");
    await expect(question).toBeFocused();
    await question.scrollIntoViewIfNeeded();
    await page.screenshot({
      path: testInfo.outputPath(`conversation-program-${width}.png`),
      fullPage: true,
    });
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(
      accessibility.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth + 1,
      ),
    ).toBe(true);
    expect(reads).toBe(2);
    expect(writes).toBe(0);
    await page.reload();
    await expect(page.getByLabel("正在讨论的程序")).toContainText("相册");
    await question.fill("我想继续刚才的检查");
    await page.getByText("以往对话", { exact: true }).click();
    await page.getByRole("button", { name: /继续对话 1/ }).click();
    await expect(
      page.getByText("最近一次检查：相册打不开", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: /继续对话 2/ }).click();
    await expect(page).toHaveURL(new RegExp(`thread=${oldThreadId}$`));
    await expect(page.getByLabel("正在讨论的程序")).toHaveCount(0);
    await expect(
      page.getByText("以前的检查记录", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: /继续对话 1/ }).click();
    await expect(page).toHaveURL(new RegExp(`thread=${recentThreadId}$`));
    await expect(page.getByLabel("正在讨论的程序")).toContainText("相册");
    await expect(question).toHaveValue("我想继续刚才的检查");
    expect(writes).toBe(0);
    await expect(page.getByRole("button", { name: "发送问题" })).toBeEnabled();
    await page.getByRole("button", { name: "发送问题" }).click();
    await expect(question).toHaveValue("");
    expect(writes).toBe(1);
    await page.getByRole("button", { name: "开始新对话" }).click();
    await expect(page).toHaveURL(new RegExp(`thread=${newThread.thread_id}$`));
    await expect(page.getByLabel("正在讨论的程序")).toHaveCount(0);
    await page.reload();
    await expect(page.getByLabel("正在讨论的程序")).toHaveCount(0);
    await expect(question).toBeVisible();
    expect(writes).toBe(2);
    overview.services.items = [];
    await page.goto(`/app/overview?thread=${recentThreadId}`);
    await expect(
      page.getByText(/暂时找不到这段对话原来检查的程序/),
    ).toBeVisible();
    await expect(
      page.getByText("最近一次检查：相册打不开", { exact: true }),
    ).toBeVisible();
    await question.fill("程序不见了，这句草稿先保留");
    await expect(page.getByRole("button", { name: "发送问题" })).toBeDisabled();
    await page.screenshot({
      path: testInfo.outputPath(`conversation-program-missing-${width}.png`),
      fullPage: true,
    });
    expect(writes).toBe(2);
  });
}
