import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";

for (const width of [1280, 320]) {
  test(`${width}px 自动接上最近检查并恢复清单，保留草稿与输入位置`, async ({
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
    await page.route("**/api/threads", (route) =>
      route.fulfill({ json: [oldThread, recentThread] }),
    );
    for (const thread of [oldThread, recentThread]) {
      await page.route(`**/api/threads/${thread.thread_id}`, (route) =>
        route.fulfill({
          json: {
            thread,
            messages: [
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
    await page.route(`**/api/runs/${runId}`, (route) =>
      route.fulfill({
        json: {
          run_id: runId,
          thread_id: recentThreadId,
          status: "completed",
          created_at: recentThread.updated_at,
          finished_at: recentThread.updated_at,
          result: null,
          error_code: null,
          error_message: null,
          failure: null,
        },
      }),
    );
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`/app/overview?service_id=${serviceId}`);
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
      path: testInfo.outputPath(`workspace-continuity-${width}.png`),
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
  });
}
