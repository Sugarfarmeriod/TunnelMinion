import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("产品外壳可导航且没有严重可访问性问题", async ({ page }) => {
  await page.goto("/app/overview");
  await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
  await page.getByRole("link", { name: "操作", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "操作", exact: true }),
  ).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter(
    ({ impact }) => impact === "serious" || impact === "critical",
  );
  expect(blocking).toEqual([]);
});

for (const colorScheme of ["light", "dark"] as const) {
  test(`${colorScheme} 桌面风格保持导航和对比度`, async ({
    page,
  }, testInfo) => {
    await page.emulateMedia({ colorScheme });
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/app/overview");
    await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
    await expect(
      page.getByRole("button", { name: "刷新", exact: true }),
    ).toBeVisible();
    const results = await new AxeBuilder({ page }).analyze();
    expect(
      results.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
    await page.screenshot({
      fullPage: true,
      path: testInfo.outputPath(`desktop-${colorScheme}.png`),
    });
    for (const label of ["聊天", "操作", "记忆", "设置"]) {
      await page.getByRole("link", { name: label, exact: true }).click();
      await expect(page.locator("main h2").first()).toBeVisible();
      const screen = await new AxeBuilder({ page }).analyze();
      expect(
        screen.violations.filter(
          ({ impact }) => impact === "serious" || impact === "critical",
        ),
      ).toEqual([]);
    }
  });
}
