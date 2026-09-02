import { expect, test } from "@playwright/test";

const pages = [
  ["/app/overview", "总览"],
  ["/app/chat", "聊天"],
  ["/app/operations", "操作"],
  ["/app/memories", "长期记忆"],
  ["/app/settings", "模型设置"],
] as const;

async function expectOperable(page: import("@playwright/test").Page) {
  for (const [path, heading] of pages) {
    await page.goto(path);
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("navigation", { name: "主要导航" }),
    ).toBeVisible();
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
}

test("320 CSS px 下五个入口都可操作且没有横向阻断", async ({
  page,
  request,
}) => {
  await Promise.all(
    Array.from({ length: 3 }, () => request.post("/api/threads")),
  );
  await page.setViewportSize({ width: 320, height: 720 });
  await expectOperable(page);
});

test("1280×720 在 200% 缩放下的等效布局仍可操作", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 360 });
  await expectOperable(page);
});
