import { expect, test } from "@playwright/test";

import { makeRepair } from "../src/features/repairs/testFixtures";
import {
  makeLocalServices,
  makeMapOverview,
  makePeer,
  makeService,
} from "../src/features/service-map/testFixtures";

const longName =
  "一个名字特别特别长的家庭相册同步服务-photoprism-backup-worker";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/ui/overview", (route) =>
    route.fulfill({ json: makeMapOverview() }),
  );
});

test("375 宽下服务多时，名字和状态不被按钮挤成一两个字", async ({ page }) => {
  const services = Array.from({ length: 12 }, (_, index) =>
    makeService({
      key: `docker:svc${index}`,
      name: index === 0 ? longName : `服务 ${index}`,
      kind: "docker",
      state: index === 0 ? "stopped" : "running",
      endpoints: [
        {
          protocol: "tcp",
          address: "127.0.0.1",
          port: 8000 + index,
          has_web_page: true,
        },
      ],
    }),
  );
  await page.route("**/api/services/local", (route) =>
    route.fulfill({ json: makeLocalServices(services) }),
  );
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/app/map");
  await page.getByRole("button", { name: "这台电脑，在线，12 个服务" }).click();
  const panel = page.getByRole("dialog", { name: "这台电脑上的服务" });
  await expect(panel.getByText("已停止", { exact: true })).toBeVisible();

  const rows = await panel.locator(".map-service-row").evaluateAll((items) =>
    items.map((row) => {
      const name = row.querySelector(".map-service-name")!;
      const state = row.querySelector(".map-service-state")!;
      return {
        text: name.textContent ?? "",
        name: name.getBoundingClientRect().width,
        truncated: name.scrollWidth > name.clientWidth + 1,
        state: state.getBoundingClientRect().height,
        stateLine: parseFloat(getComputedStyle(state).lineHeight) || 20,
      };
    }),
  );
  expect(rows.length).toBeGreaterThan(0);
  for (const row of rows) {
    // 状态只占一行；短名字完整显示，长名字至少能显示十来个字
    expect(row.state).toBeLessThanOrEqual(row.stateLine + 2);
    if (row.text === longName) expect(row.name).toBeGreaterThan(120);
    else expect(row.truncated).toBe(false);
  }
  // 地图下方的提问框占满一行，示例提示不被“问问 Agent”按钮截断
  const askBox = (await page.getByLabel("想问点什么？").boundingBox())!;
  const formBox = (await page.locator(".map-global-ask").boundingBox())!;
  expect(askBox.width).toBeGreaterThan(formBox.width - 2);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
});

test("窄屏列表布局里本机头上的感叹号不顶出地图", async ({ page }) => {
  const repair = makeRepair();
  await page.route("**/api/services/local", (route) =>
    route.fulfill({
      json: makeLocalServices([
        makeService({ key: repair.service_key, state: "stopped" }),
      ]),
    }),
  );
  await page.route("**/api/peers", (route) =>
    route.fulfill({ json: { peers: [makePeer(1), makePeer(2)] } }),
  );
  await page.route("**/api/repairs", (route) =>
    route.fulfill({ json: { repairs: [repair] } }),
  );
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/app/map");
  const bang = page.getByRole("button", {
    name: "这台电脑有 1 个待批准的修复",
  });
  await expect(bang).toBeVisible();
  const bangBox = (await bang.boundingBox())!;
  const canvasBox = (await page.locator(".map-canvas").boundingBox())!;
  expect(bangBox.y).toBeGreaterThanOrEqual(canvasBox.y);
});

test("深色模式下加入向导的输入框跟随页面配色", async ({ page }) => {
  await page.route("**/api/services/local", (route) =>
    route.fulfill({ json: makeLocalServices() }),
  );
  await page.route("**/api/identity", (route) =>
    route.fulfill({
      json: {
        initialized: false,
        local_display_name: "书房电脑",
        owner_fingerprint: null,
        has_owner_key: false,
        removed: false,
        roster_version: null,
        trust_list_version: null,
        bind: null,
        address_candidates: ["10.88.0.2"],
        devices: [],
        friends: [],
        legacy_peers: [],
      },
    }),
  );
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/app/map");
  await page.getByRole("button", { name: "我是朋友，粘贴配对码" }).click();
  const dialog = page.getByRole("dialog", { name: "我是朋友，粘贴配对码" });
  const colors = await dialog.evaluate((element) => {
    const field = element.querySelector("textarea")!;
    const back = [...element.querySelectorAll("button")].find(
      (button) => button.textContent === "上一步",
    )!;
    const next = [...element.querySelectorAll("button")].find(
      (button) => button.textContent === "下一步",
    )!;
    return {
      dialog: getComputedStyle(element).backgroundColor,
      field: getComputedStyle(field).backgroundColor,
      text: getComputedStyle(field).color,
      body: getComputedStyle(element).color,
      back: getComputedStyle(back).backgroundColor,
      next: getComputedStyle(next).backgroundColor,
    };
  });
  expect(colors.field).toBe(colors.dialog);
  expect(colors.text).toBe(colors.body);
  // 上一步是次要按钮，不和下一步用同一个实心底色
  expect(colors.back).not.toBe(colors.next);
});
