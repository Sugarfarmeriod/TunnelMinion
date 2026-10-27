import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { makeEvent } from "../src/features/chat/testFixtures";
import type { DelegationPhase } from "../src/features/chat/contracts";
import { makeRemoteRepair } from "../src/features/repairs/testFixtures";
import {
  makePeer,
  makePeerServices,
} from "../src/features/service-map/testFixtures";
import { mockMapChat } from "./mapChatFixture";

async function mockDelegationStream(page: Page) {
  await page.addInitScript(() => {
    class MockEventSource extends EventTarget {
      readyState = 0;
      onopen: ((event: Event) => void) | null = null;
      onerror: ((event: Event) => void) | null = null;
      private receive = (event: Event) => {
        const { type, payload } = (event as CustomEvent).detail;
        this.dispatchEvent(
          new MessageEvent(type, {
            data: JSON.stringify(payload),
            lastEventId: String(payload.sequence),
          }),
        );
      };
      constructor(_url: string) {
        super();
        window.addEventListener("mock-delegation-sse", this.receive);
        queueMicrotask(() => {
          this.readyState = 1;
          this.onopen?.(new Event("open"));
          document.documentElement.dataset.sse = "open";
        });
      }
      close() {
        this.readyState = 2;
        window.removeEventListener("mock-delegation-sse", this.receive);
      }
    }
    Object.assign(window, { EventSource: MockEventSource });
  });
  let sequence = 0;
  return async (phase: DelegationPhase | "finished") => {
    const payload =
      phase === "finished"
        ? makeEvent(++sequence, "finished", { stop_reason: "completed" })
        : makeEvent(++sequence, "delegation", {
            delegation_id: "delegation_" + "1".repeat(32),
            peer_node_id: makePeer().node_id,
            phase,
          });
    await page.evaluate(
      (payload) =>
        window.dispatchEvent(
          new CustomEvent("mock-delegation-sse", {
            detail: { type: payload.event_type, payload },
          }),
        ),
      payload,
    );
  };
}

for (const width of [1440, 760, 320]) {
  test(`${width}px 委派交回结论后只能到对端批准修复`, async ({ page }) => {
    const backend = await mockMapChat(page);
    const emit = await mockDelegationStream(page);
    const peer = makePeer();
    const services = makePeerServices(peer);
    services.services[0]!.state = "stopped";
    let pending = false;
    const repair = makeRemoteRepair();
    await page.route("**/api/peers", (route) =>
      route.fulfill({
        json: {
          peers: [{ ...peer, pending_repairs: pending ? [repair] : [] }],
        },
      }),
    );
    await page.route("**/api/peers/*/services", (route) =>
      route.fulfill({ json: services }),
    );
    await page.route("**/api/repairs", (route) =>
      route.fulfill({ json: { repairs: [] } }),
    );
    const repairRequests: string[] = [];
    await page.route("**/api/repairs/*/**", (route) => {
      repairRequests.push(route.request().url());
      return route.abort();
    });
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/app/map");
    await page.getByRole("button", { name: /^测试电脑 1，在线/ }).click();
    const panel = page.getByRole("dialog", { name: "测试电脑 1上的服务" });
    await panel.getByRole("button", { name: "问问 远端相册" }).click();
    await expect.poll(() => backend.questions.length).toBe(1);
    expect(backend.questions[0]!.about).toEqual({
      node_id: peer.node_id,
      service_key: "python:app.py",
    });
    await expect(page.locator("html")).toHaveAttribute("data-sse", "open");
    const drawer = page.getByRole("dialog", { name: "对话", exact: true });
    await emit("submitted");
    await expect(drawer.getByText("交给 测试电脑 1 · 已交给")).toBeVisible();
    if (width === 1440)
      await expect(
        page.locator('.map-packet[data-phase="submitted"]'),
      ).toBeVisible();
    else await expect(page.locator(".map-packet")).toHaveCount(0);
    await drawer.getByRole("button", { name: "关闭对话" }).click();
    await emit("investigating");
    await expect(page.getByText("正在查……", { exact: true })).toBeVisible();
    await expect(page.locator(".map-thought")).toHaveCount(
      width === 1440 ? 1 : 0,
    );
    await emit("answered");
    if (width === 1440) {
      const packet = page.locator(".map-packet.is-returning");
      await expect(packet).toBeVisible();
      const start = (await packet.boundingBox())!;
      await expect
        .poll(async () => (await packet.boundingBox())?.y)
        .not.toBe(start.y);
      await expect(packet).toHaveCount(0);
      await expect(page.locator(".map-thought")).toHaveCount(0);
    } else {
      await expect(page.locator(".map-packet, .map-thought")).toHaveCount(0);
      await expect(page.getByText("已交回", { exact: true })).toBeVisible();
    }
    pending = true;
    backend.finish("对端确认相册已停止，提出了重启建议。请到对方电脑批准。");
    await emit("finished");
    const bang = page.getByRole("button", {
      name: "测试电脑 1有 1 个待批准的修复",
    });
    await expect(bang).toBeVisible();
    await page
      .getByRole("button", { name: "对话", exact: false })
      .first()
      .click();
    await expect(
      drawer.getByText(
        "对端确认相册已停止，提出了重启建议。请到对方电脑批准。",
      ),
    ).toBeVisible();
    await drawer.getByRole("button", { name: "关闭对话" }).click();
    await expect(
      page.getByText("! 有 1 件事要在 测试电脑 1 上批准"),
    ).toBeVisible();
    await bang.focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: "要修好“远端相册”吗？" });
    await expect(
      dialog.getByText("请到 测试电脑 1 的地图上批准"),
    ).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: /批准并修复|先不用/ }),
    ).toHaveCount(0);
    await expect(
      dialog.getByText(/10 分钟内有效 · 还剩 \d:\d{2}/),
    ).toBeVisible();
    await expect(dialog.locator("details")).not.toHaveAttribute("open");
    await dialog.getByText("高级", { exact: true }).click();
    await expect(dialog.getByText(repair.how_to_approve)).toBeVisible();
    await dialog.getByRole("button", { name: "知道了" }).focus();
    await page.keyboard.press("Tab");
    await expect(
      dialog.getByRole("button", { name: "关闭修复" }),
    ).toBeFocused();
    const axe = await new AxeBuilder({ page }).analyze();
    expect(
      axe.violations.filter((item) =>
        ["serious", "critical"].includes(item.impact ?? ""),
      ),
    ).toEqual([]);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.keyboard.press("Escape");
    await expect(bang).toBeFocused();
    expect(repairRequests).toEqual([]);
  });
}

test("减少动画时数据包停在线上并保留状态文字", async ({ page }) => {
  await mockMapChat(page);
  const emit = await mockDelegationStream(page);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.route("**/api/peers", (route) =>
    route.fulfill({ json: { peers: [makePeer()] } }),
  );
  await page.route("**/api/repairs", (route) =>
    route.fulfill({ json: { repairs: [] } }),
  );
  await page.goto("/app/map");
  await page
    .getByRole("textbox", { name: "想问点什么？" })
    .fill("看看远端相册");
  await page.getByRole("button", { name: "问问 Agent" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-sse", "open");
  await emit("submitted");
  const packet = page.locator(".map-packet");
  await expect(packet).toHaveCSS("animation-name", "none");
  await expect(page.getByText("已交给", { exact: true })).toBeVisible();
  await emit("investigating");
  await expect(page.getByText("正在查……", { exact: true })).toBeVisible();
  await emit("answered");
  await expect(page.locator(".map-packet.is-returning")).toHaveCSS(
    "animation-name",
    "none",
  );
  await expect(page.getByText("已交回", { exact: true })).toBeVisible();
  await expect(page.locator(".map-thought")).toHaveCount(0);
});
