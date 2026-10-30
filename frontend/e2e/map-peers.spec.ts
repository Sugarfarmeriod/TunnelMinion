import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import {
  makePeer,
  makePeerServices,
  makeService,
} from "../src/features/service-map/testFixtures";
import { mockMapChat } from "./mapChatFixture";

for (const width of [1440, 760, 320]) {
  test(`${width}px 的 0、1、3、8 个对端均无重叠、无横向滚动`, async ({
    page,
  }) => {
    await mockMapChat(page);
    let peers = [makePeer()];
    await page.route("**/api/peers", (route) =>
      route.fulfill({ json: { peers } }),
    );
    await page.setViewportSize({ width, height: 900 });
    for (const count of [0, 1, 3, 8]) {
      peers = Array.from({ length: count }, (_, index) =>
        makePeer(index + 1, {
          reachable: index !== 2,
          network: (["wireguard", "n2n", "other", null] as const)[index % 4],
        }),
      );
      await page.goto("/app/map");
      const nodes = page.locator(".map-node");
      await expect(nodes).toHaveCount(count + 1);
      await expect(page.locator(".map-link")).toHaveCount(count);
      const labels = page.locator(".map-link-network");
      await expect(labels).toHaveCount(
        peers.filter((peer) => peer.network !== null).length,
      );
      // 组网标签不能压在任何电脑上；字体换好后再量，免得量到替代字体的宽度。
      await page.evaluate(() => document.fonts.ready);
      const nodeBoxes = await nodes.evaluateAll((items) =>
        items.map((item) => item.getBoundingClientRect().toJSON() as DOMRect),
      );
      for (const label of await labels.evaluateAll((items) =>
        items.map((item) => item.getBoundingClientRect().toJSON() as DOMRect),
      )) {
        expect(label.left).toBeGreaterThanOrEqual(0);
        for (const node of nodeBoxes) {
          expect(
            label.right <= node.left ||
              node.right <= label.left ||
              label.bottom <= node.top ||
              node.bottom <= label.top,
          ).toBe(true);
        }
      }
      const boxes = await nodes.evaluateAll((items) =>
        items.map((item) => {
          const { left, top, right, bottom } = item.getBoundingClientRect();
          return { left, top, right, bottom };
        }),
      );
      for (let i = 0; i < boxes.length; i++) {
        for (let j = i + 1; j < boxes.length; j++) {
          const a = boxes[i]!,
            b = boxes[j]!;
          expect(
            a.right <= b.left ||
              b.right <= a.left ||
              a.bottom <= b.top ||
              b.bottom <= a.top,
          ).toBe(true);
        }
      }
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBe(true);
    }
  });

  test(`${width}px 三个对端含离线电脑，远端问问携带上下文且无障碍通过`, async ({
    page,
  }, testInfo) => {
    const backend = await mockMapChat(page, [
      makeService({ name: "示例相册" }),
    ]);
    const peers = [makePeer(1), makePeer(2), makePeer(3, { reachable: false })];
    const services = makePeerServices(peers[0]);
    services.services[0]!.name = "示例相册";
    await page.route("**/api/peers", (route) =>
      route.fulfill({ json: { peers } }),
    );
    await page.route("**/api/peers/*/services", (route) =>
      route.fulfill({ json: services }),
    );
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/app/map");
    const offline = page.getByRole("button", { name: /^测试电脑 3，离线/ });
    await offline.click();
    let panel = page.getByRole("dialog", { name: "测试电脑 3上的服务" });
    await expect(panel.getByText(/离线，上次在线/)).toBeVisible();
    await expect(panel.getByRole("button", { name: /问问/ })).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(offline).toBeFocused();
    const peer = page.getByRole("button", { name: /^测试电脑 1，在线/ });
    await peer.focus();
    await page.keyboard.press("Enter");
    panel = page.getByRole("dialog", { name: "测试电脑 1上的服务" });
    await expect(panel.getByText(/清单由 测试电脑 1 报来 ·/)).toBeVisible();
    await expect(
      panel.getByRole("link", { name: "打开 示例相册" }),
    ).toHaveAttribute("href", "http://192.0.2.42:8080");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await panel.getByRole("button", { name: "问问 示例相册" }).click();
    const drawer = page.getByRole("dialog", { name: "对话", exact: true });
    await expect(
      drawer.getByText("关于：测试电脑 1 · 示例相册（Python）"),
    ).toBeVisible();
    expect(backend.questions).toEqual([]);
    const input = drawer.getByRole("textbox", { name: "问题", exact: true });
    await input.fill("怎么查看相册？");
    await drawer.getByRole("button", { name: "发送问题" }).click();
    await expect.poll(() => backend.questions.length).toBe(1);
    expect(backend.questions[0]!.about).toEqual({
      node_id: peers[0]!.node_id,
      service_key: "python:app.py",
    });
    backend.finish();
    const axe = await new AxeBuilder({ page }).analyze();
    expect(
      axe.violations.filter(
        (item) => item.impact === "serious" || item.impact === "critical",
      ),
    ).toEqual([]);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: testInfo.outputPath(`remote-drawer-${width}.png`),
    });
  });
}
