import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { mockMapChat } from "./mapChatFixture";

for (const colorScheme of ["light", "dark"] as const) {
  test(`${colorScheme} 地图的更多菜单可进入所有页面并返回，保持可访问性`, async ({
    page,
  }) => {
    await mockMapChat(page);
    await page.emulateMedia({ colorScheme });
    await page.goto("/app/map");
    await expect(
      page.getByRole("heading", { name: "我的服务网络" }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "工作台", exact: true }),
    ).toHaveCount(0);
    for (const [label, path] of [
      ["请求记录", "operations"],
      ["最近事件", "incidents"],
      ["记忆", "memories"],
      ["设置", "settings"],
    ]) {
      await page.getByRole("button", { name: "更多 ▾" }).click();
      await page.getByRole("link", { name: label, exact: true }).click();
      await expect(page).toHaveURL(`/app/${path}`);
      const result = await new AxeBuilder({ page }).analyze();
      expect(
        result.violations.filter(
          (item) => item.impact === "serious" || item.impact === "critical",
        ),
      ).toEqual([]);
      await page.getByRole("link", { name: "← 回到地图" }).click();
      await expect(
        page.getByRole("heading", { name: "我的服务网络" }),
      ).toBeVisible();
    }
  });
}
