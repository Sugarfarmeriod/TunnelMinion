import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("窄窗口仍能找到脱敏诊断与恢复说明", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/app/settings");

  await expect(page.getByRole("heading", { name: "模型设置" })).toBeVisible();
  const download = page.getByRole("link", { name: "下载脱敏诊断包" });
  await expect(download).toBeVisible();
  await expect(download).toHaveAttribute("href", "/api/diagnostics/export");
  await expect(
    page.getByText(/没有 Murus、防火墙日志权限或厂商 VPN 工具时/),
  ).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter(
    ({ impact }) => impact === "serious" || impact === "critical",
  );
  expect(blocking).toEqual([]);
});
