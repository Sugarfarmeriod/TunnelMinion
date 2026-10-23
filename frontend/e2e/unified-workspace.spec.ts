import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";
import {
  makeOperationDetail,
  makeOperationListItem,
  operationId,
  targetNodeId,
} from "../src/features/operations/testFixtures";

for (const width of [1280, 881, 320]) {
  test(`${width}px 工作台长名称状态清晰且跨页不丢草稿`, async ({
    page,
    request,
  }, testInfo) => {
    const longName = "penpot-penpot-frontend-1";
    const overview = (await (
      await request.get("/api/resources/overview")
    ).json()) as ResourceOverview;
    overview.schema_version = "resource-overview-programs/v1";
    overview.nodes.items = [
      {
        node_id: targetNodeId,
        display_name: "客厅 Mac",
        platform: "macos",
        state: "online",
        source: "local_observation",
        evidence_at: overview.generated_at,
        freshness: "fresh",
        service_count: 5,
      },
    ];
    overview.services = {
      source: "local_observation",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      error: null,
      items: [
        { port: 805, protocol: "tcp", name: "gost", group: "a" },
        { port: 9527, protocol: "tcp", name: "n3n-supernode", group: "b" },
        { port: 9527, protocol: "udp", name: "n3n-supernode", group: "b" },
        { port: 8787, protocol: "tcp", name: "Wireguard Panel", group: "c" },
      ].map((value, index) => ({
        service_id: `service_${String(index + 1).repeat(32)}`,
        node_id: targetNodeId,
        display_name: `${value.name} · ${value.port}`,
        application: {
          group_id: `application_${value.group.repeat(32)}`,
          name: value.name,
          kind: value.port === 8787 ? "python" : "program",
        },
        protocol: value.protocol as "tcp" | "udp",
        port: value.port,
        access_address: `${value.protocol}://192.0.2.1:${value.port}`,
        accessibility: "network",
        lifecycle: "active",
        state: "available",
        source: "local_observation",
        evidence_at: overview.generated_at,
        freshness: "fresh",
      })),
    };
    overview.services.items.push({
      ...overview.services.items[0]!,
      service_id: `service_${"5".repeat(32)}`,
      display_name: `${longName} · 9001`,
      application: {
        group_id: `application_${"d".repeat(32)}`,
        name: longName,
        kind: "docker",
      },
      port: 9001,
      access_address: "tcp://192.0.2.1:9001",
    });
    overview.incidents.items = [];
    overview.model.status = "unconfigured";
    const threadId = `thread_${"9".repeat(32)}`;
    const thread = {
      thread_id: threadId,
      created_at: overview.generated_at,
      updated_at: overview.generated_at,
      message_count: 0,
    };
    let writes = 0;
    page.on("request", (request) => {
      if (request.method() !== "GET") writes += 1;
    });
    await page.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
      route.fulfill({ json: overview }),
    );
    await page.route("**/api/threads", (route) =>
      route.fulfill({ json: [thread] }),
    );
    await page.route(`**/api/threads/${threadId}`, (route) =>
      route.fulfill({ json: { thread, messages: [] } }),
    );
    await page.route("**/api/operations", (route) =>
      route.fulfill({ json: [makeOperationListItem()] }),
    );
    await page.route(`**/api/operations/${operationId}`, (route) =>
      route.fulfill({ json: makeOperationDetail() }),
    );
    await page.route("**/api/operations/eligible-peers", (route) =>
      route.fulfill({ json: [] }),
    );
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/app/overview");
    await expect(
      page.getByRole("navigation", { name: "主要导航" }).getByRole("link"),
    ).toHaveCount(4);
    const question = page.getByRole("textbox", { name: "问题", exact: true });
    await question.fill("帮我检查这个程序为什么打不开");
    if (width === 320)
      await page.getByText("程序与待办", { exact: true }).click();
    await expect(
      page.locator(`#application_${"c".repeat(32)} > details > summary`),
    ).toContainText("Wireguard Panel");
    const longProgram = page.locator(
      `#application_${"d".repeat(32)} > details > summary`,
    );
    await expect(longProgram.locator("strong")).toHaveText(longName);
    const status = longProgram.locator(".overview-status");
    await expect(status).toHaveText("已启动");
    await page.screenshot({
      path: testInfo.outputPath(`program-status-${width}.png`),
      fullPage: true,
    });
    expect(
      await status.evaluate((element) => {
        const range = document.createRange();
        range.selectNodeContents(element);
        return range.getClientRects().length;
      }),
    ).toBe(1);
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth + 1,
      ),
    ).toBe(true);
    await longProgram.click();
    await expect(
      page.getByRole("button", { name: `帮我看看 ${longName}`, exact: true }),
    ).toBeVisible();
    await longProgram.click();
    overview.services.items[4]!.freshness = "stale";
    await page.getByRole("button", { name: "刷新", exact: true }).click();
    const staleProgram = page.locator(
      `#service_${"5".repeat(32)} > details > summary`,
    );
    const staleStatus = staleProgram.locator(".overview-status");
    await expect(staleStatus).toHaveText("已启动（记录已过时）");
    await page.screenshot({
      path: testInfo.outputPath(`program-stale-status-${width}.png`),
      fullPage: true,
    });
    expect(
      await staleStatus.evaluate((element) => {
        const range = document.createRange();
        range.selectNodeContents(element);
        return range.getClientRects().length;
      }),
    ).toBe(1);
    await expect(staleProgram.locator("strong")).toHaveText(
      `${longName} · 9001`,
    );
    expect(
      await staleProgram.locator("strong").evaluate((element) => {
        const range = document.createRange();
        range.selectNodeContents(element);
        return range.getClientRects().length;
      }),
    ).toBeLessThanOrEqual(3);
    await page
      .locator(`#application_${"a".repeat(32)} > details > summary`)
      .click();
    await page
      .getByRole("button", { name: "帮我看看 gost", exact: true })
      .click();
    await expect(page.getByLabel("正在讨论的程序")).toContainText("gost");
    await expect(question).toHaveValue("帮我检查这个程序为什么打不开");
    await expect(page.getByRole("heading", { name: "一起处理" })).toBeFocused();
    await expect(
      page.getByRole("link", { name: "连接模型", exact: true }),
    ).toHaveAttribute("href", "/app/settings");
    await page.screenshot({
      path: testInfo.outputPath(`workspace-${width}.png`),
      fullPage: true,
    });
    const serviceUrl = page.url();
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "设置", exact: true })
      .click();
    await page.getByRole("link", { name: "返回刚才的问题" }).click();
    expect(page.url()).toBe(serviceUrl);
    await expect(page.getByLabel("正在讨论的程序")).toContainText("gost");
    await expect(question).toHaveValue("帮我检查这个程序为什么打不开");
    await expect(question).toBeFocused();
    await page.getByRole("link", { name: "请求记录", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "操作", exact: true }),
    ).toBeVisible();
    await expect(question).toHaveValue("帮我检查这个程序为什么打不开");
    await page.getByRole("link", { name: "查看请求", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "临时访问请求", exact: true }),
    ).toBeVisible();
    await expect(question).toHaveValue("帮我检查这个程序为什么打不开");
    await expect(page.getByLabel("正在讨论的程序")).toHaveCount(0);
    await expect(
      page.getByText(
        "下面的问题会带上这条请求的状态；聊天不能替你批准或执行。",
      ),
    ).toBeVisible();
    const operationUrl = page.url();
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "设置", exact: true })
      .click();
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "工作台", exact: true })
      .click();
    expect(page.url()).toBe(operationUrl);
    await expect(
      page.getByRole("heading", { name: "临时访问请求", exact: true }),
    ).toBeVisible();
    await expect(question).toHaveValue("帮我检查这个程序为什么打不开");
    expect(writes).toBe(0);
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth + 1,
      ),
    ).toBe(true);
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(
      accessibility.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
    await page
      .getByRole("navigation", { name: "主要导航" })
      .getByRole("link", { name: "工作台", exact: true })
      .click();
    await expect(page).toHaveURL(/\/app\/overview$/);
    await expect(question).toHaveValue("帮我检查这个程序为什么打不开");
  });
}
