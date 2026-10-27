import { expect, test } from "@playwright/test";

import {
  makeRemoteRepair,
  makeRepair,
} from "../src/features/repairs/testFixtures";
import { makePeer } from "../src/features/service-map/testFixtures";
import { mockMapChat } from "./mapChatFixture";

for (const width of [1440, 320]) {
  for (const remote of [false, true]) {
    test(`${width}px ${remote ? "对端" : "本机"}节点的待批准按钮和红色感叹号打开修复框`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 900 });
      await mockMapChat(page);
      const repair = makeRepair();
      const peer = makePeer(1, { pending_repairs: [makeRemoteRepair()] });
      await page.route("**/api/peers", (route) =>
        route.fulfill({ json: { peers: [peer] } }),
      );
      await page.route("**/api/peers/*/repairs/*", (route) =>
        route.fulfill({
          json: {
            node_id: peer.node_id,
            repair_id: peer.pending_repairs[0]!.repair_id,
            access: "not_allowed",
            repair: null,
          },
        }),
      );
      await page.route("**/api/repairs", (route) =>
        route.fulfill({ json: { repairs: [repair] } }),
      );
      await page.route(`**/api/repairs/${repair.repair_id}`, (route) =>
        route.fulfill({ json: repair }),
      );
      await page.goto("/app/map");
      const name = remote ? peer.display_name : "这台电脑";
      const bang = page.getByRole("button", {
        name: `${name}有 1 个待批准的修复`,
        exact: true,
      });
      const dialog = page.getByRole("dialog", {
        name: `要修好“${remote ? "远端相册" : "相册"}”吗？`,
      });
      await bang.click();
      await expect(dialog).toBeVisible();
      if (remote) {
        await expect(
          dialog.getByText(`请到 ${name} 的地图上点感叹号批准`),
        ).toBeVisible();
        await expect(
          dialog.getByRole("button", { name: "批准并修复" }),
        ).toHaveCount(0);
      } else
        await expect(
          dialog.getByRole("button", { name: "批准并修复" }),
        ).toBeEnabled();
      await dialog.getByRole("button", { name: "关闭修复" }).click();
      await expect(dialog).toBeHidden();
      await page.getByRole("button", { name: "对话", exact: true }).click();
      const drawer = page.getByRole("dialog", { name: "对话", exact: true });
      await expect(drawer).toBeVisible();
      if (width === 320) {
        await drawer.getByRole("button", { name: "关闭对话" }).click();
        await expect(drawer).toBeHidden();
      }
      await bang.locator("svg").click();
      await expect(dialog).toBeVisible();
      // 对话抽屉开着时，焦点要进入修复框，Esc 只关修复框。
      await expect
        .poll(() =>
          dialog.evaluate((element) =>
            element.contains(document.activeElement),
          ),
        )
        .toBe(true);
      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      if (width !== 320) await expect(drawer).toBeVisible();
    });
  }
}
