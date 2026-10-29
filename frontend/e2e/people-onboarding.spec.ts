import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// 欢迎三选一只在还没有机主身份时出现；这条用例会建立身份，只在一个浏览器里跑一次。
test.skip(
  ({ browserName }) => browserName !== "chromium",
  "会改变共享验收数据",
);

test("第一次打开网页建立机主身份，再生成加入码", async ({ page }) => {
  const responses: string[] = [];
  page.on("response", async (response) => {
    if (
      response.url().includes("/api/identity") &&
      response.request().method() !== "GET"
    )
      responses.push(response.url());
  });
  await page.goto("/app/map");
  const welcome = page.getByRole("complementary", {
    name: "这台电脑还没有加入任何人的电脑",
  });
  await expect(welcome).toBeVisible();
  await expect(welcome.getByRole("button", { name: /我是朋友/ })).toBeVisible();
  const blocking = (await new AxeBuilder({ page }).analyze()).violations.filter(
    ({ impact }) => impact === "serious" || impact === "critical",
  );
  expect(blocking).toEqual([]);

  await welcome.getByRole("button", { name: /这是我的第一台电脑/ }).click();
  await page.getByLabel("本机组网地址").fill("10.88.0.2");
  await page.getByLabel("这台电脑叫什么").fill("书房电脑");
  await page.getByRole("button", { name: "下一步" }).click();
  const shown = page.locator("p.people-code--recovery");
  await expect(shown).toBeVisible();
  const code = (await shown.textContent())?.trim() ?? "";
  expect(code.length).toBeGreaterThan(10);
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "存成文件" }).click();
  expect((await download).suggestedFilename()).toBe(
    "tunnelminion-recovery-code.txt",
  );
  await expect(page.getByRole("button", { name: "完成" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "我已经把恢复码存好了" }).check();
  await page.getByRole("button", { name: "完成" }).click();
  await expect(page.getByText("已建立你的机主身份。")).toBeVisible();
  await page.getByRole("button", { name: "好的" }).click();

  await page.getByRole("link", { name: "电脑与朋友" }).first().click();
  await expect(
    page.getByRole("heading", { name: "我的电脑（1 台）" }),
  ).toBeVisible();
  await expect(page.getByText("书房电脑")).toBeVisible();
  await expect(page.getByText(code)).toHaveCount(0);
  await page.getByRole("button", { name: "加一台我的电脑" }).click();
  await expect(page.locator("p.people-code")).toContainText("tmo1_");
  await expect(page.getByText(/24 小时内有效/)).toBeVisible();
  await page.getByRole("button", { name: "关闭" }).click();

  // 粘贴配对码后先显示对方地址，不直接连接。
  await page.getByRole("button", { name: "邀请朋友" }).click();
  const friendCode =
    (await page.locator("p.people-code").textContent())?.trim() ?? "";
  await page.getByRole("button", { name: "关闭" }).click();
  await page.getByRole("button", { name: "粘贴朋友的配对码" }).click();
  await page.getByLabel("配对码（tmf1_ 开头）").fill(friendCode);
  await page.getByRole("button", { name: "下一步" }).click();
  await expect(page.getByText(/朋友电脑：10.88.0.2:8787/)).toBeVisible();
  await page.getByRole("button", { name: "取消" }).click();

  const recoveryLeaks = await page.evaluate(
    (value) =>
      JSON.stringify(window.localStorage).includes(value) ||
      location.href.includes(value),
    code,
  );
  expect(recoveryLeaks).toBe(false);
  expect(responses.length).toBeGreaterThan(0);
});
