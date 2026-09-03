import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

import { resourceOverviewSchema } from "../src/api/schemas/overview";

interface FixtureReceipt {
  node_id: string;
  operation_id: string;
  incident: {
    incident_id: string;
    scenario_id: string;
    provider_name: string;
    status: string;
    conclusion: string;
    selected_tools: string[];
    normal_refresh: {
      scenario_id: string;
      incident_count: number;
      model_calls: number;
    };
    real_model_calls: number;
  };
}

async function expectDialogTabCycle(
  page: import("@playwright/test").Page,
  dialog: import("@playwright/test").Locator,
  cancelName: string,
  confirmName: string,
) {
  const cancel = dialog.getByRole("button", { name: cancelName });
  const confirm = dialog.getByRole("button", { name: confirmName });

  await expect(cancel).toBeFocused();
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Tab");
  await expect(confirm).toBeFocused();
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Tab");
  await expect(cancel).toBeFocused();
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Shift+Tab");
  await expect(confirm).toBeFocused();
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Shift+Tab");
  await expect(cancel).toBeFocused();
  await expect(dialog.locator(":focus")).toHaveCount(1);
}

function fixtureReceipt(): FixtureReceipt {
  const path = process.env.TUNNELMINION_PACKAGE_FIXTURE;
  if (path === undefined) {
    throw new Error("缺少 TUNNELMINION_PACKAGE_FIXTURE");
  }
  return JSON.parse(readFileSync(path, "utf8")) as FixtureReceipt;
}

test("正式包完整走通总览、聊天、审批、记忆与确定性降级", async ({
  page,
  request,
}) => {
  const fixture = fixtureReceipt();

  expect(fixture.incident.provider_name).toBe("offline-script");
  expect(fixture.incident.normal_refresh).toEqual({
    scenario_id: "normal-refresh",
    incident_count: 0,
    model_calls: 0,
  });
  expect(fixture.incident.real_model_calls).toBe(0);
  for (let refresh = 0; refresh < 2; refresh += 1) {
    const overviewResponse = await request.get("/api/resources/overview");
    expect(overviewResponse.status()).toBe(200);
    const overviewResult = resourceOverviewSchema.safeParse(
      await overviewResponse.json(),
    );
    expect(overviewResult.error?.issues ?? []).toEqual([]);
    expect(overviewResult.data?.incidents.items).toHaveLength(1);
    expect(overviewResult.data?.incidents.items[0]?.incident_id).toBe(
      fixture.incident.incident_id,
    );
  }

  await page.goto("/app/overview");
  await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
  await expect(page.getByText(/standalone ·/)).toBeVisible();
  await expect(page.getByText("还没有配置模型")).toBeVisible();
  await expect(
    page.getByText("未配置 Coordinator，当前按仅本机模式工作"),
  ).toBeVisible();
  await expect(page.getByText("没有配置跨节点路径")).toBeVisible();
  await expect(page.getByText("服务只能从本机访问")).toBeVisible();
  await expect(page.getByText("已确认根因")).toBeVisible();
  await expect(page.getByText(fixture.incident.conclusion)).toBeVisible();
  await page.getByRole("button", { name: "查看调查详情" }).click();
  await expect(page.getByRole("heading", { name: "调查详情" })).toBeVisible();
  await expect(
    page.locator(".incident-detail").getByText("证据充分"),
  ).toBeVisible();
  await expect(
    page.getByText("只读工具 list_network_listeners 以 success 状态结束"),
  ).toBeVisible();
  await expect(
    page.getByText("只读工具 probe_service_reachability 以 success 状态结束"),
  ).toBeVisible();
  await expect(page.getByText("没有已记录的未知项。")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "为什么这个服务只能从本机访问？" }),
  ).toBeVisible();

  await page.goto("/app/chat");
  const createThread = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/threads") &&
      response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "新建线程" }).click();
  expect((await createThread).status()).toBe(200);

  await page.goto(`/app/operations/${fixture.operation_id}`);
  await expect(
    page.getByRole("heading", { name: "package-acceptance-dashboard" }),
  ).toBeVisible();
  const approve = page.getByRole("button", { name: "批准一次" });
  await approve.click();
  const operationDialog = page.getByRole("dialog", { name: "确认批准一次" });
  await expect(operationDialog).toContainText(fixture.operation_id);
  await expect(
    operationDialog.getByRole("button", { name: "返回检查详情" }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(operationDialog).toBeHidden();

  await page.goto("/app/memories");
  await page.getByLabel("用户").fill("acceptance-user");
  await page.getByLabel("网络").fill("home");
  await page.getByLabel("节点 ID").fill(fixture.node_id);
  await page.getByRole("button", { name: "查看这个作用域" }).click();
  await expect(
    page.getByText("总览优先显示家庭网络中的本机服务"),
  ).toBeVisible();
  await expect(page.getByText("实验网络只允许只读诊断")).toBeHidden();

  await page.getByRole("button", { name: "修正这条记忆" }).click();
  await page
    .getByLabel("记忆内容")
    .fill("总览优先显示家庭网络中的本机服务与证据时间");
  await page.getByRole("button", { name: "检查并确认修正" }).click();
  const memoryDialog = page.getByRole("dialog", { name: "确认修正长期记忆" });
  await expectDialogTabCycle(page, memoryDialog, "取消", "确认修正一次");
  await page.keyboard.press("Escape");
  await expect(memoryDialog).toBeHidden();
  await expect(
    page.getByRole("button", { name: "检查并确认修正" }),
  ).toBeFocused();
  await page.getByRole("button", { name: "检查并确认修正" }).click();
  const reviseResponse = page.waitForResponse(
    (response) =>
      response.url().includes("/api/memories/") &&
      response.request().method() === "PUT",
  );
  await memoryDialog.getByRole("button", { name: "确认修正一次" }).click();
  expect((await reviseResponse).status()).toBe(200);
  await expect(memoryDialog).toBeHidden();
  await expect(
    page
      .locator(".memory-content")
      .getByText("总览优先显示家庭网络中的本机服务与证据时间"),
  ).toBeVisible();

  await page.getByLabel("网络").fill("lab");
  await page.getByRole("button", { name: "查看这个作用域" }).click();
  await expect(page.getByText("实验网络只允许只读诊断")).toBeVisible();
  await expect(
    page.getByText("总览优先显示家庭网络中的本机服务与证据时间"),
  ).toBeHidden();

  await page.goto("/app/settings");
  await expect(page.getByRole("heading", { name: "模型设置" })).toBeVisible();
  await page
    .getByLabel("OpenAI-compatible endpoint")
    .fill("http://127.0.0.1:8080/v1");
  await page.getByLabel("模型名称").fill("focus-trap-model");
  await page.getByRole("button", { name: "检查并确认保存" }).click();
  const settingsDialog = page.getByRole("dialog", {
    name: "确认保存模型配置",
  });
  await expectDialogTabCycle(page, settingsDialog, "取消", "确认保存一次");
  await page.keyboard.press("Escape");
  await expect(settingsDialog).toBeHidden();
  await expect(
    page.getByRole("button", { name: "检查并确认保存" }),
  ).toBeFocused();

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter(
      ({ impact }) => impact === "serious" || impact === "critical",
    ),
  ).toEqual([]);

  const storage = await page.evaluate(async () => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
    databases:
      typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map(({ name }) => name ?? "")
        : [],
  }));
  expect(storage).toEqual({ local: [], session: [], databases: [] });
});
