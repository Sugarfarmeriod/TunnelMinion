import { expect, test } from "@playwright/test";
import {
  makeOperationDetail,
  requestNodeId,
  targetNodeId,
} from "../src/features/operations/testFixtures";
import type { ResourceOverview } from "../src/api/schemas/overview";
test("批准摘要按精确身份匹配名称，陈旧名称不冒充访问者", async ({
  page,
  request,
}, testInfo) => {
  const overview = (await (
    await request.get("/api/resources/overview")
  ).json()) as ResourceOverview;
  const detail = makeOperationDetail();
  overview.nodes.items = [
    {
      node_id: requestNodeId,
      display_name: "书房电脑",
      platform: "windows",
      state: "online",
      source: "coordinator_directory",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      service_count: 0,
    },
  ];
  await page.route(/\/api\/(?:resources\/overview|ui\/overview)$/, (route) =>
    route.fulfill({ json: overview }),
  );
  await page.route(
    `**/api/operations/${detail.summary.operation_id}`,
    (route) => route.fulfill({ json: detail }),
  );
  await page.goto(`/app/operations/${detail.summary.operation_id}`);
  await expect(
    page.getByRole("region", { name: "这次请求会做什么" }),
  ).toContainText("书房电脑");
  await expect(page.getByText("查看技术详情与记录")).toBeVisible();
  await expect(page.getByText(detail.service_fingerprint)).toBeHidden();
  await page.getByRole("button", { name: "批准一次", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("书房电脑");
  await expect(dialog).toContainText("最多 5 分钟");
  await expect(dialog).toContainText("使用者可能查看或修改内容");
  await expect(dialog).toContainText("是否需要登录、能做什么由服务决定");
  await expect(dialog).toContainText("能打开不代表安全");
  await page.screenshot({
    fullPage: true,
    path: testInfo.outputPath("named-request-confirmation.png"),
  });
  await dialog.getByText("调整批准有效期").click();
  await dialog.getByLabel("批准有效期截止时间").fill("");
  await dialog.getByText("调整批准有效期").click();
  await dialog.getByRole("button", { name: "确认批准一次" }).click();
  await expect(dialog.getByLabel("批准有效期截止时间")).toBeVisible();
  await page.keyboard.press("Escape");
  overview.nodes.items[0].freshness = "stale";
  await page.reload();
  await expect(page.getByText("访问者名称未知")).toBeVisible();
  await expect(
    page.getByText("请向发起人确认身份，不能只看设备名。"),
  ).toBeVisible();
});
