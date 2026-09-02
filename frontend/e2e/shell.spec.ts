import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("产品外壳可导航且没有严重可访问性问题", async ({ page }) => {
  await page.goto("/app/overview");
  await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
  await page.getByRole("link", { name: "操作" }).click();
  await expect(
    page.getByRole("heading", { name: "操作", exact: true }),
  ).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter(
    ({ impact }) => impact === "serious" || impact === "critical",
  );
  expect(blocking).toEqual([]);
});
