import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";
import type { RunEvent, RunView } from "../src/features/chat/contracts";

for (const width of [1280, 320]) {
  test(`${width}px 未完成检查可理解、可停止，继续原程序且切换不串用`, async ({
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
      message_count: 2,
    };
    const checkedFact = "之前已核对：相册入口只接受这台电脑连接。";
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
    let releaseCreate = () => {};
    const creation = new Promise<void>((resolve) => {
      releaseCreate = resolve;
    });
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
    await page.route("**/api/model-config", (route) =>
      route.fulfill({
        json: {
          endpoint: "http://127.0.0.1:8080/v1",
          model: "qwen-local",
          timeout_seconds: 30,
          api_key_configured: false,
          profiles: [],
          status: "available",
          error_code: null,
          error_message: null,
        },
      }),
    );
    await page.route("**/api/threads", async (route) => {
      if (route.request().method() === "POST") {
        await creation;
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
                    ...(thread === recentThread
                      ? [
                          {
                            role: "assistant",
                            content: checkedFact,
                            answer_checked: true,
                            created_at: oldThread.updated_at,
                            run_id: `run_${"a".repeat(32)}`,
                          },
                        ]
                      : []),
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
      error_code: "model_network_unreachable",
      error_message: "fixture_transport_error：模型连接失败的技术记录",
      failure: null,
    };
    let stopReason: RunEvent["stop_reason"] = "completed";
    await page.route(`**/api/runs/${runId}`, (route) =>
      route.fulfill({ json: run }),
    );
    await page.route(`**/api/runs/${runId}/events?*`, (route) => {
      const event: RunEvent = {
        sequence: 1,
        event_type:
          run.status === "running"
            ? "goal"
            : run.status === "failed" || run.status === "interrupted"
              ? run.status
              : "finished",
        created_at: recentThread.updated_at,
        run_id: runId,
        target_node_id: null,
        tool_name: null,
        tool_status: null,
        elapsed_ms: null,
        tool_run_id: null,
        stop_reason: stopReason,
        message: run.error_message,
      };
      return route.fulfill({
        contentType: "text/event-stream",
        body: `id: 1\nevent: ${event.event_type}\ndata: ${JSON.stringify(event)}\n\n`,
      });
    });
    let cancelCalls = 0;
    await page.route(`**/api/runs/${runId}/cancel`, (route) => {
      expect(route.request().method()).toBe("POST");
      cancelCalls += 1;
      run = {
        ...run,
        status: "cancelled",
        finished_at: recentThread.updated_at,
      };
      stopReason = "cancelled";
      return route.fulfill({ json: run });
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
        stopReason = "completed";
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
    await page.evaluate(() => window.scrollTo(0, 0));
    await testInfo.attach("input-position", {
      body: JSON.stringify(await question.boundingBox()),
      contentType: "application/json",
    });
    await page.screenshot({
      path: testInfo.outputPath(`workspace-first-screen-${width}.png`),
    });
    if (width === 1280) await expect(question).toBeInViewport({ ratio: 1 });
    await expect(page.getByText(/连接入口 TCP 43123/)).not.toBeVisible();
    const connectionDetails = page
      .getByLabel("正在讨论的程序")
      .getByText("查看连接信息", { exact: true });
    await connectionDetails.click();
    await expect(page.getByText(/连接入口 TCP 43123/)).toBeVisible();
    await connectionDetails.click();
    const originalUrl = page.url();
    await page.getByRole("link", { name: "继续提问", exact: true }).click();
    await expect(question).toBeFocused();
    await expect(question).toHaveValue("我想继续刚才的检查");
    expect(page.url()).toBe(originalUrl);
    expect(writes).toBe(0);
    await expect(
      page.getByText("这次联系模型时遇到问题，还没查完。", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "检查模型连接" }),
    ).toHaveAttribute("href", "/app/settings");
    await page.getByRole("link", { name: "检查模型连接" }).click();
    await expect(page.getByRole("heading", { name: "模型设置" })).toBeVisible();
    await expect(question).not.toBeVisible();
    const returnToQuestion = page.getByRole("link", { name: "返回刚才的问题" });
    await expect(returnToQuestion).toHaveAttribute("href", "/app/overview");
    await page.getByLabel("新 API 密钥（可选）").fill("fixture-unsaved-key");
    await page.screenshot({
      path: testInfo.outputPath(`settings-with-return-${width}.png`),
    });
    expect(writes).toBe(0);
    await page.goBack();
    await question.scrollIntoViewIfNeeded();
    await page.screenshot({
      path: testInfo.outputPath(`settings-return-${width}.png`),
    });
    await expect(question).toHaveValue("我想继续刚才的检查");
    await expect(question).toBeFocused();
    await page.getByRole("link", { name: "检查模型连接" }).click();
    await expect(page.getByLabel("新 API 密钥（可选）")).toHaveValue("");
    await returnToQuestion.click();
    await expect(question).toHaveValue("我想继续刚才的检查");
    await expect(page.getByLabel("正在讨论的程序")).toContainText("相册");
    expect(
      await page.evaluate(() =>
        [localStorage, sessionStorage, history.state].some((value) =>
          /我想继续刚才的检查|fixture-unsaved-key/.test(JSON.stringify(value)),
        ),
      ),
    ).toBe(false);
    await expect(page.getByText(checkedFact, { exact: true })).toBeVisible();
    const technicalMessage = page.getByText(run.error_message!, {
      exact: true,
    });
    await expect(technicalMessage).not.toBeVisible();
    await page.getByText("查看用了哪些工具与证据", { exact: true }).click();
    await expect(technicalMessage).toBeVisible();
    await page.getByText("查看用了哪些工具与证据", { exact: true }).click();
    await question.scrollIntoViewIfNeeded();
    await page.screenshot({
      path: testInfo.outputPath(`run-feedback-${width}.png`),
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
    for (const [status, reason, explanation] of [
      [
        "interrupted",
        null,
        "TunnelMinion重新启动时，这次检查还没结束。已有记录保留，没有自动重做。",
      ],
      ["cancelled", "cancelled", "这次检查已停止，没有自动重新开始。"],
      ["completed", "timeout", "这次检查用时已到上限，先停在这里。"],
      ["completed", "model-limit", "这次检查已到用量上限，先停在这里。"],
      ["completed", "tool-limit", "这次检查已到用量上限，先停在这里。"],
      ["completed", "completed", "检查已结束，但没有读到可核对的结果。"],
    ] as const) {
      run = { ...run, status, error_code: null, error_message: null };
      stopReason = reason;
      await page.reload();
      await expect(page.getByText(explanation, { exact: true })).toBeVisible();
      await expect(page.getByLabel("正在讨论的程序")).toContainText("相册");
      await expect(page.getByText(checkedFact, { exact: true })).toBeVisible();
      await question.fill("这句草稿先保留");
      await page.getByRole("button", { name: "刷新这段对话" }).click();
      await expect(
        page.getByText("这段对话和检查进展已刷新，没有重新发起检查。", {
          exact: true,
        }),
      ).toBeVisible();
      await expect(question).toHaveValue("这句草稿先保留");
      expect(writes).toBe(0);
    }
    run = { ...run, status: "running", finished_at: null };
    stopReason = null;
    await page.reload();
    const stop = page.getByRole("button", { name: "停止这次检查" });
    await stop.click();
    const dialog = page.getByRole("alertdialog", {
      name: "要停止这次检查吗？",
    });
    const dismiss = dialog.getByRole("button", { name: "暂不停止" });
    await expect(dismiss).toBeFocused();
    await expect(
      dialog.getByText(`运行 ID：${runId}`, { exact: true }),
    ).not.toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(stop).toBeFocused();
    expect(writes).toBe(0);
    await stop.click();
    await page.screenshot({
      path: testInfo.outputPath(`run-stop-confirmation-${width}.png`),
      fullPage: true,
    });
    const confirmationAccessibility = await new AxeBuilder({ page }).analyze();
    expect(
      confirmationAccessibility.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
    await dialog.getByRole("button", { name: "确认停止" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(
      page.getByRole("heading", { name: "调查进展", exact: true }),
    ).toBeFocused();
    await expect(
      page.getByText("这次检查已停止，没有自动重新开始。", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(checkedFact, { exact: true })).toBeVisible();
    expect(cancelCalls).toBe(1);
    expect(writes).toBe(1);
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
    const oldConversationUrl = page.url();
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "设置", exact: true })
      .click();
    await expect(returnToQuestion).toHaveAttribute(
      "href",
      `/app/overview?thread=${oldThreadId}`,
    );
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "工作台", exact: true })
      .click();
    expect(page.url()).toBe(oldConversationUrl);
    await expect(
      page.getByText("以前的检查记录", { exact: true }),
    ).toBeVisible();
    await expect(question).toHaveValue("我想继续刚才的检查");
    await page.getByRole("button", { name: /继续对话 1/ }).click();
    await expect(page).toHaveURL(new RegExp(`thread=${recentThreadId}$`));
    await expect(page.getByLabel("正在讨论的程序")).toContainText("相册");
    await expect(question).toHaveValue("我想继续刚才的检查");
    expect(writes).toBe(1);
    await expect(page.getByRole("button", { name: "发送问题" })).toBeEnabled();
    await page.getByRole("button", { name: "发送问题" }).click();
    await expect(question).toHaveValue("");
    expect(writes).toBe(2);
    await page.getByRole("button", { name: "开始新对话" }).click();
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "设置", exact: true })
      .click();
    releaseCreate();
    await expect(returnToQuestion).toHaveAttribute(
      "href",
      `/app/overview?thread=${newThread.thread_id}`,
    );
    await expect(page).toHaveURL(/\/app\/settings$/);
    await expect(page.getByRole("heading", { name: "模型设置" })).toBeVisible();
    await returnToQuestion.click();
    await expect(page).toHaveURL(new RegExp(`thread=${newThread.thread_id}$`));
    await expect(page.getByLabel("正在讨论的程序")).toHaveCount(0);
    await page.reload();
    await expect(page.getByLabel("正在讨论的程序")).toHaveCount(0);
    await expect(question).toBeVisible();
    expect(writes).toBe(3);
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
    expect(writes).toBe(3);
  });
}
