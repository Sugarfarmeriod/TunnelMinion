import { expect, test } from "@playwright/test";

import {
  makePeerRepair,
  makeRemoteRepair,
} from "../src/features/repairs/testFixtures";
import { makePeer } from "../src/features/service-map/testFixtures";
import { mockMapChat } from "./mapChatFixture";

for (const allowed of [true, false]) {
  test(`对端${allowed ? "允许代批准后在地图跟踪到修好" : "未允许时引导到对方批准"}`, async ({
    page,
  }) => {
    await mockMapChat(page);
    let repair = makePeerRepair();
    const summary = makeRemoteRepair();
    const peer = makePeer(1, {
      node_id: repair.node_id,
      pending_repairs: [summary],
    });
    let approved = false;
    let progressReads = 0;
    const actions: string[] = [];
    const payload = () => ({
      node_id: peer.node_id,
      repair_id: repair.repair_id,
      access: allowed ? "allowed" : "not_allowed",
      repair: allowed ? repair : null,
    });
    await page.route("**/api/peers", (route) =>
      route.fulfill({
        json: {
          peers: [{ ...peer, pending_repairs: approved ? [] : [summary] }],
        },
      }),
    );
    await page.route("**/api/repairs", (route) =>
      route.fulfill({ json: { repairs: [] } }),
    );
    await page.route(
      `**/api/peers/${peer.node_id}/repairs/${repair.repair_id}`,
      (route) => {
        if (approved) {
          const status =
            ["executing", "verifying", "succeeded"][progressReads++] ??
            "succeeded";
          repair = {
            ...repair,
            status,
            verification_passed: status === "succeeded" ? true : null,
          };
        }
        return route.fulfill({ json: payload() });
      },
    );
    await page.route(
      `**/api/peers/${peer.node_id}/repairs/${repair.repair_id}/approve`,
      (route) => {
        expect(route.request().headers()["x-tunnelminion-request"]).toBe(
          "same-origin",
        );
        expect(route.request().postData()).toBeNull();
        actions.push(route.request().method());
        approved = true;
        repair = {
          ...repair,
          status: "authorized",
          approved_by_peer: true,
          approval_expires_at: null,
        };
        return route.fulfill({ status: 202, json: payload() });
      },
    );
    await page.goto("/app/map");
    const bang = page.getByRole("button", {
      name: `${peer.display_name}有 1 个待批准的修复`,
    });
    await bang.click();
    const dialog = page.getByRole("dialog", { name: "要修好“远端相册”吗？" });
    await expect(dialog).toBeVisible();
    if (!allowed) {
      await expect(
        dialog.getByText(`请到 ${peer.display_name} 的地图上点感叹号批准`),
      ).toBeVisible();
      await expect(
        dialog.getByRole("button", { name: "批准并修复" }),
      ).toHaveCount(0);
      await dialog.getByRole("button", { name: "知道了" }).click();
      await expect(dialog).toBeHidden();
      expect(actions).toEqual([]);
      return;
    }
    await expect(
      dialog.getByText(
        `由 ${peer.display_name} 提出 · ${peer.display_name} 允许这台电脑替它批准`,
      ),
    ).toBeVisible();
    await dialog.getByText("高级", { exact: true }).click();
    await expect(
      dialog.getByText(`修复编号 ${repair.repair_id}`),
    ).toBeVisible();
    await expect(dialog.getByText(/docker|命令行后备/)).toHaveCount(0);
    await dialog.getByRole("button", { name: "批准并修复" }).click();
    await expect(bang).toHaveCount(0);
    await expect(
      dialog.getByRole("button", { name: "关闭修复" }),
    ).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('[aria-current="step"]')).toHaveText(
      "正在执行",
      { timeout: 5_000 },
    );
    await expect(dialog.locator('[aria-current="step"]')).toHaveText(
      "正在确认",
      { timeout: 5_000 },
    );
    await expect(dialog.getByText("修好了", { exact: true })).toBeVisible({
      timeout: 5_000,
    });
    expect(actions).toEqual(["POST"]);
    expect(progressReads).toBe(3);
    await dialog.getByRole("button", { name: "知道了" }).click();
    await expect(dialog).toBeHidden();
  });
}
