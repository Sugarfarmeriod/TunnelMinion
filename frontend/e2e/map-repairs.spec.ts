import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import {
  finishedRepair,
  makeRepair,
} from "../src/features/repairs/testFixtures";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../src/features/service-map/testFixtures";

for (const width of [1440, 760, 320]) {
  test(`${width}px 已停止服务在地图批准后修好`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    let repair = makeRepair();
    let detailReads = 0;
    let approved = false;
    const actions: string[] = [];
    await page.route("**/api/ui/overview", (route) =>
      route.fulfill({ json: makeMapOverview() }),
    );
    await page.route("**/api/services/local", (route) =>
      route.fulfill({
        json: makeLocalServices([
          makeService({
            key: repair.service_key,
            name: "相册",
            kind: "docker",
            state: repair.status === "succeeded" ? "running" : "stopped",
          }),
        ]),
      }),
    );
    await page.route("**/api/repairs", (route) =>
      route.fulfill({ json: { repairs: [repair] } }),
    );
    await page.route(/\/api\/repairs\/operation_[0-9a-f]+$/, (route) => {
      detailReads++;
      if (approved) {
        const status = ["executing", "verifying", "succeeded"][detailReads - 2];
        repair =
          status === "succeeded"
            ? finishedRepair()
            : {
                ...repair,
                status: status === "verifying" ? "verifying" : "executing",
              };
      }
      return route.fulfill({ json: repair });
    });
    await page.route("**/api/repairs/*/approve", (route) => {
      actions.push(route.request().method());
      expect(route.request().headers()["x-tunnelminion-request"]).toBe(
        "same-origin",
      );
      approved = true;
      repair = { ...repair, status: "authorized", approval_expires_at: null };
      return route.fulfill({ json: repair, status: 202 });
    });
    await page.goto("/app/map");
    await page
      .getByRole("button", { name: "这台电脑，在线，1 个服务" })
      .click();
    await expect(page.getByText("已停止", { exact: true })).toBeVisible();
    await expect(page.getByText("需要处理的事")).toBeVisible();
    const bang = page.getByRole("button", {
      name: "这台电脑有 1 个待批准的修复",
    });
    await bang.focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: "要修好“相册”吗？" });
    await expect(dialog).toBeVisible();
    await expect(
      dialog.getByText("会有什么影响", { exact: true }),
    ).toBeVisible();
    await expect(
      dialog.getByText("10 分钟内有效", { exact: false }),
    ).toBeVisible();
    expect(await dialog.locator("details").getAttribute("open")).toBeNull();
    const axe = await new AxeBuilder({ page }).analyze();
    expect(
      axe.violations.filter((item) =>
        ["serious", "critical"].includes(item.impact ?? ""),
      ),
    ).toEqual([]);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    if (width <= 760) {
      const bounds = (await dialog.boundingBox())!;
      expect(bounds.x).toBe(0);
      expect(bounds.width).toBe(width);
    }
    await dialog.getByRole("button", { name: "批准并修复" }).click();
    await expect(page.getByText("正在修……", { exact: true })).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: "关闭修复" }),
    ).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("修好了", { exact: true })).toBeVisible({
      timeout: 10_000,
    });
    await expect(bang).toHaveCount(0);
    expect(detailReads).toBe(4);
    expect(actions).toEqual(["POST"]);
    const doneAxe = await new AxeBuilder({ page }).analyze();
    expect(
      doneAxe.violations.filter((item) =>
        ["serious", "critical"].includes(item.impact ?? ""),
      ),
    ).toEqual([]);
    await dialog.getByRole("button", { name: "关闭", exact: true }).click();
    const node = page.getByRole("button", { name: "这台电脑，在线，1 个服务" });
    if ((await node.getAttribute("aria-expanded")) !== "true")
      await node.click();
    await expect(page.getByText("正常", { exact: true })).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  });
}
