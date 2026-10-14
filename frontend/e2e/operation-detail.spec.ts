import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";

import {
  makeOperationDetail,
  makeOperationSummary,
  requestNodeId,
  targetNodeId,
} from "../src/features/operations/testFixtures";
import type { OperationDetail } from "../src/features/operations/schemas";

const operationId = `operation_${"1".repeat(32)}`;

async function expectNoHorizontalOverflow(page: Page) {
  const overflowing = await page.locator("body *").evaluateAll((elements) => {
    const viewportWidth = document.documentElement.clientWidth;
    return elements
      .filter((element) => {
        const bounds = element.getBoundingClientRect();
        return bounds.left < -1 || bounds.right > viewportWidth + 1;
      })
      .map((element) => ({
        className: element.className,
        tagName: element.tagName,
        text: element.textContent?.slice(0, 80) ?? "",
      }));
  });
  expect(overflowing).toEqual([]);
}

function operationListItem(detail: OperationDetail) {
  return {
    ...detail.summary,
    role: detail.role,
    submission_result_unknown: detail.submission_result_unknown,
    execution_result_unknown: detail.execution_result_unknown,
    last_checked_at: detail.last_checked_at,
    error_code: detail.error_code,
  };
}

async function fulfillJson(route: Route, payload: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(payload),
  });
}

for (const viewport of [
  { name: "1280×720", width: 1280, height: 720 },
  { name: "320 CSS px", width: 320, height: 720 },
  { name: "200% 等效布局", width: 640, height: 360 },
] as const) {
  test(`${viewport.name} 下真实 operation 详情和确认框可操作`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({
      width: viewport.width,
      height: viewport.height,
    });
    await page.goto(`/app/operations/${operationId}`);

    await expect(
      page.getByRole("heading", { name: "临时访问请求" }),
    ).toBeVisible();
    await expect(page.getByText(`operation ${operationId}`)).toBeHidden();
    await expect(page.getByText("等待你决定")).toBeVisible();
    const approve = page.getByRole("button", { name: "批准一次" });
    await page.screenshot({
      path: testInfo.outputPath("request-first-screen.png"),
    });
    await expect(approve).toBeInViewport();
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      fullPage: true,
      path: testInfo.outputPath("request-page.png"),
    });

    await approve.click();
    const dialog = page.getByRole("dialog", { name: "确认批准一次" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(operationId);
    await expect(dialog.getByLabel("批准有效期截止时间")).toBeHidden();
    await expect(dialog).toContainText("最多 5 分钟");
    await page.screenshot({
      fullPage: true,
      path: testInfo.outputPath("request-confirmation.png"),
    });
    await page.screenshot({
      path: testInfo.outputPath("confirmation-first-screen.png"),
    });
    await dialog.getByText("调整批准有效期").click();
    await expect(dialog.getByLabel("批准有效期截止时间")).toBeVisible();
    await expectNoHorizontalOverflow(page);

    const results = await new AxeBuilder({ page })
      .include("[role=dialog]")
      .analyze();
    expect(
      results.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);

    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(approve).toBeFocused();
  });
}

test("浏览器完成请求、等待批准、执行、访问、重启降级和目标端拒绝", async ({
  context,
  page,
  request,
}, testInfo) => {
  const targetOperationId = `operation_${"8".repeat(32)}`;
  let requester = makeOperationDetail({
    role: "requester",
    allowed_actions: ["refresh"],
  });
  let target = makeOperationDetail({
    summary: makeOperationSummary({ operation_id: targetOperationId }),
  });
  const createPayloads: unknown[] = [];
  let executeCalls = 0;
  let rejectCalls = 0;
  const overview = (await (
    await request.get("/api/resources/overview")
  ).json()) as ResourceOverview;
  overview.nodes.items = [requestNodeId, targetNodeId].map(
    (node_id, index) => ({
      node_id,
      display_name: ["书房电脑", "客厅电脑"][index],
      platform: index === 0 ? "windows" : "macos",
      state: "online",
      source: "coordinator_directory",
      freshness: "fresh",
      evidence_at: overview.generated_at,
      service_count: 0,
    }),
  );
  await context.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
    fulfillJson(route, overview),
  );

  await context.route("**/api/operations**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();

    if (path === "/api/operations/eligible-peers") {
      await fulfillJson(route, [
        {
          node_id: targetNodeId,
          platform: "macos",
          host: "10.77.0.1",
          port: 8787,
          allowed_tools: ["get_node_summary"],
          allowed_operations: ["share_local_http_service"],
          credential_configured: true,
        },
      ]);
      return;
    }
    if (path === "/api/operations" && method === "GET") {
      await fulfillJson(route, [operationListItem(requester)]);
      return;
    }
    if (path === "/api/operations" && method === "POST") {
      createPayloads.push(request.postDataJSON());
      await fulfillJson(route, requester);
      return;
    }
    if (path === `/api/operations/${operationId}` && method === "GET") {
      await fulfillJson(route, requester);
      return;
    }
    if (
      path === `/api/operations/${operationId}/refresh` &&
      method === "POST"
    ) {
      requester = makeOperationDetail({
        role: "requester",
        state: "authorized",
        summary: makeOperationSummary({ status: "authorized" }),
        allowed_actions: ["refresh", "execute"],
        last_checked_at: "2026-08-08T09:01:00+08:00",
      });
      await fulfillJson(route, requester);
      return;
    }
    if (
      path === `/api/operations/${operationId}/execute` &&
      method === "POST"
    ) {
      executeCalls += 1;
      requester = makeOperationDetail({
        role: "requester",
        state: "succeeded",
        summary: makeOperationSummary({ status: "succeeded" }),
        allowed_actions: ["refresh", "access"],
        last_checked_at: "2026-08-08T09:02:00+08:00",
        access_expires_at: "2026-08-08T09:05:00+08:00",
      });
      await fulfillJson(route, requester);
      return;
    }
    if (path === `/api/operations/${operationId}/access/`) {
      await route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<h1>isolated shared service</h1>",
      });
      return;
    }
    if (path === `/api/operations/${targetOperationId}` && method === "GET") {
      await fulfillJson(route, target);
      return;
    }
    if (
      path === `/api/operations/${targetOperationId}/reject` &&
      method === "POST"
    ) {
      rejectCalls += 1;
      target = makeOperationDetail({
        state: "rejected",
        summary: makeOperationSummary({
          operation_id: targetOperationId,
          status: "rejected",
        }),
        allowed_actions: [],
      });
      await fulfillJson(route, target.summary);
      return;
    }
    await route.fallback();
  });

  await page.goto("/app/operations");
  await expect(page.getByRole("link", { name: "查看请求" })).toBeInViewport();
  await expect(page.getByText("申请使用：客厅电脑上的服务")).toBeVisible();
  await expect(page.getByText(requestNodeId, { exact: true })).toBeHidden();
  await expect(page.getByText(targetNodeId, { exact: true })).toBeHidden();
  await expect(page.getByRole("checkbox", { name: /我了解风险/ })).toBeHidden();
  await page.screenshot({
    fullPage: true,
    path: testInfo.outputPath("requests-list.png"),
  });
  overview.nodes.items[1].freshness = "stale";
  await page.reload();
  await expect(
    page.getByText("申请使用：名称未知的电脑上的服务"),
  ).toBeVisible();
  overview.nodes.items[1].freshness = "fresh";
  overview.nodes.items[0].display_name = "客厅电脑";
  await page.reload();
  await expect(
    page.getByText(`申请使用：客厅电脑 · ${targetNodeId.slice(-8)}上的服务`),
  ).toBeVisible();
  overview.nodes.items[0].display_name = "书房电脑";
  await page.reload();
  await expect(page.getByText("申请使用：客厅电脑上的服务")).toBeVisible();
  await page.getByText("发起新的访问请求", { exact: true }).click();
  await page.getByRole("checkbox", { name: /我了解风险/ }).check();
  await page.getByRole("button", { name: "发送访问请求" }).click();
  await expect(page).toHaveURL(`/app/operations/${operationId}`);
  await expect(page.getByText("等待对方同意", { exact: true })).toBeVisible();
  await expect(page.getByText(/请求已发出，正在等待对方同意/)).toBeVisible();
  expect(createPayloads).toEqual([
    {
      target_node_id: targetNodeId,
      service_port: 8080,
      bind_port: 18881,
      duration_seconds: 300,
      confirmed: true,
    },
  ]);

  await page.getByRole("button", { name: "查看对方状态" }).click();
  await expect(page.getByText("对方已同意", { exact: true })).toBeVisible();
  await expect(page.getByText(/对方已同意。请确认开始使用/)).toBeVisible();
  await page.getByRole("button", { name: "开始临时访问" }).click();
  const executeDialog = page.getByRole("dialog", { name: "确认开始临时访问" });
  await expect(executeDialog).toContainText(
    "结果不明确时，请先刷新，不要重复开始",
  );
  await executeDialog.getByRole("button", { name: "确认开始临时访问" }).click();
  await expect(page.getByText("访问检查通过", { exact: true })).toBeVisible();
  await expect(page.getByText(/现在可以打开临时访问/)).toBeVisible();
  await expect(
    page.getByText(/需要对方先同意|对方批准后，你才能开始使用/),
  ).toHaveCount(0);
  await expect(page.getByText("会短暂开放一个受限端口")).toBeHidden();
  await expectNoHorizontalOverflow(page);
  await page.screenshot({
    fullPage: true,
    path: testInfo.outputPath("access-state-clarity.png"),
  });
  expect(executeCalls).toBe(1);

  const accessPagePromise = context.waitForEvent("page");
  await page.getByRole("link", { name: "打开临时访问" }).click();
  const accessPage = await accessPagePromise;
  await expect(
    accessPage.getByRole("heading", { name: "isolated shared service" }),
  ).toBeVisible();
  expect(accessPage.url()).not.toMatch(/token|secret|credential/i);
  await accessPage.close();

  requester = makeOperationDetail({
    role: "requester",
    state: "expired",
    allowed_actions: ["refresh"],
  });
  await page.reload();
  await expect(page.getByText(/这次临时访问已到期，入口已关闭/)).toBeVisible();
  await expect(page.getByRole("link", { name: "打开临时访问" })).toHaveCount(0);
  await expect(page.getByText(/需要对方先同意/)).toHaveCount(0);

  requester = makeOperationDetail({
    role: "requester",
    state: "succeeded",
    summary: makeOperationSummary({ status: "succeeded" }),
    allowed_actions: ["refresh"],
    last_checked_at: "2026-08-08T09:03:00+08:00",
    error_code: "access_session_unavailable",
  });
  await page.reload();
  await expect(
    page.getByText("这台电脑已无法打开临时访问。请刷新状态，不要重复开始。"),
  ).toBeVisible();
  await page.getByText("查看技术详情与记录").click();
  await expect(page.getByText("access_session_unavailable")).toBeVisible();
  await expect(page.getByRole("link", { name: "打开临时访问" })).toHaveCount(0);

  await page.goto(`/app/operations/${targetOperationId}`);
  await page.getByRole("button", { name: "拒绝" }).click();
  const rejectDialog = page.getByRole("dialog", { name: "确认拒绝" });
  await expect(
    rejectDialog.getByRole("button", { name: "返回检查详情" }),
  ).toBeFocused();
  await rejectDialog
    .getByRole("textbox", { name: "拒绝原因" })
    .fill("本机不同意开放");
  await expect(
    rejectDialog.getByRole("textbox", { name: "拒绝原因" }),
  ).toHaveValue("本机不同意开放");
  await rejectDialog.getByRole("button", { name: "确认拒绝" }).click();
  await expect(page.getByText("已拒绝")).toBeVisible();
  expect(rejectCalls).toBe(1);
});

for (const source of [
  "server",
  "lost-response",
  "unreadable-detail",
] as const) {
  test(`${source} 的待确认结果只查同一请求，窄屏不遮挡并可恢复`, async ({
    context,
    page,
  }, testInfo) => {
    let detail = makeOperationDetail({
      submission_result_unknown: source === "server",
    });
    let detailReads = 0;
    const writes: string[] = [];
    const readPaths: string[] = [];
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await context.route("**/api/ui/overview", (route) =>
      route.fulfill({
        status: 503,
        json: {
          detail: { code: "names_unavailable", message: "名称暂不可用" },
        },
      }),
    );
    await context.route("**/api/operations**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (request.method() !== "GET") {
        writes.push(path);
        expect(path).toBe(`/api/operations/${operationId}/approve`);
        if (source === "lost-response") await route.abort("failed");
        else
          await fulfillJson(
            route,
            makeOperationSummary({ status: "authorized" }),
          );
      } else if (path === "/api/operations/eligible-peers") {
        await fulfillJson(route, []);
      } else if (path === "/api/operations") {
        await fulfillJson(route, [operationListItem(detail)]);
      } else {
        expect(path).toBe(`/api/operations/${operationId}`);
        readPaths.push(path);
        detailReads += 1;
        if (source === "unreadable-detail" && detailReads === 3) {
          await route.fulfill({
            status: 503,
            json: {
              detail: { code: "unavailable", message: "暂时读不到结果" },
            },
          });
        } else await fulfillJson(route, detail);
      }
    });
    if (source === "server") {
      await page.goto("/app/operations");
      await expect(page.getByText("结果待确认", { exact: true })).toBeVisible();
      await expect(page.getByText("等待你决定", { exact: true })).toHaveCount(
        0,
      );
      await page.getByRole("link", { name: "查看请求", exact: true }).click();
    } else {
      await page.goto(`/app/operations/${operationId}`);
      await page.getByRole("button", { name: "批准一次", exact: true }).click();
      await page
        .getByRole("dialog")
        .getByRole("button", { name: "确认批准一次", exact: true })
        .click();
    }
    const query = page.getByRole("button", {
      name: "查询这条请求",
      exact: true,
    });
    await expect(
      page.getByText("这次请求的结果还不明确。", { exact: true }),
    ).toBeVisible();
    await expect(query).toBeEnabled();
    await expect(query).toHaveCount(1);
    await expect(
      page
        .locator('[aria-labelledby="operation-detail-title"]')
        .getByRole("alert"),
    ).toHaveCount(1);
    await expect(
      page.locator(".operation-request-intent, .operation-actions"),
    ).toHaveCount(0);
    await expect(
      page.getByText(
        /认识这个请求再批准|operation ID|state 仍是|allowed_actions/,
      ),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "批准一次", exact: true }),
    ).toHaveCount(0);
    await expect(page.getByText(/使用者可能查看或修改内容/)).toBeVisible();
    for (const width of [1280, 320]) {
      await page.setViewportSize({ width, height: width === 320 ? 760 : 720 });
      await query.focus();
      await expect(query).toBeInViewport();
      await expectNoHorizontalOverflow(page);
      await page.screenshot({
        fullPage: true,
        path: testInfo.outputPath(`request-pending-${width}.png`),
      });
    }
    const technical = page.getByText("查看技术详情与记录", { exact: true });
    await technical.focus();
    await page.keyboard.press("Enter");
    await expect(
      page.getByText(`operation ${operationId}`, { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("awaiting_authorization", { exact: true }),
    ).toBeVisible();
    await page.keyboard.press("Enter");
    await query.click();
    await expect(query).toBeEnabled();
    await expect(
      page.getByText("这次请求的结果还不明确。", { exact: true }),
    ).toBeVisible();
    expect(writes).toHaveLength(source === "server" ? 0 : 1);
    const a11y = await new AxeBuilder({ page }).include("main").analyze();
    expect(
      a11y.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
    detail = makeOperationDetail({
      state: "authorized",
      allowed_actions: ["cancel"],
    });
    await query.click();
    await expect(page.getByText("等待对方开始", { exact: true })).toBeVisible();
    await expect(
      page.getByText("这次请求的结果还不明确。", { exact: true }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "取消请求", exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/批准成功|执行成功/)).toHaveCount(0);
    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      fullPage: true,
      path: testInfo.outputPath("request-result-restored.png"),
    });
    expect(writes).toEqual(
      source === "server" ? [] : [`/api/operations/${operationId}/approve`],
    );
    expect(readPaths.length).toBeGreaterThanOrEqual(3);
    expect(new Set(readPaths)).toEqual(
      new Set([`/api/operations/${operationId}`]),
    );
    expect(errors).toEqual([]);
  });
}
