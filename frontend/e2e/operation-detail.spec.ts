import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

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

for (const viewport of [
  { name: "1280×720", width: 1280, height: 720 },
  { name: "320 CSS px", width: 320, height: 720 },
  { name: "200% 等效布局", width: 640, height: 360 },
] as const) {
  test(`${viewport.name} 下真实 operation 详情和确认框可操作`, async ({
    page,
  }) => {
    await page.setViewportSize({
      width: viewport.width,
      height: viewport.height,
    });
    await page.goto(`/app/operations/${operationId}`);

    await expect(
      page.getByRole("heading", { name: "playwright-dashboard" }),
    ).toBeVisible();
    await expect(page.getByText(`operation ${operationId}`)).toBeVisible();
    await expect(page.getByText("等待本机批准")).toBeVisible();
    await expectNoHorizontalOverflow(page);

    const approve = page.getByRole("button", { name: "批准一次" });
    await approve.click();
    const dialog = page.getByRole("dialog", { name: "确认批准一次" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(operationId);
    await expect(dialog.getByLabel("批准绝对过期时间")).toBeVisible();
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
