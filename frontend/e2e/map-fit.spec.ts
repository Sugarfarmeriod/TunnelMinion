import { expect, test } from "@playwright/test";

import { makePeer } from "../src/features/service-map/testFixtures";
import { mockMapChat } from "./mapChatFixture";

// 本机已经有机主身份，地图上方不出现欢迎提示，和日常使用时一样。
const identity = {
  initialized: true,
  local_display_name: "书房电脑",
  owner_fingerprint: "SHA256:example",
  has_owner_key: true,
  removed: false,
  roster_version: 1,
  trust_list_version: 1,
  bind: null,
  address_candidates: [],
  devices: [],
  friends: [],
  legacy_peers: [],
};

for (const [width, height] of [
  [1280, 800],
  [1440, 900],
  [1920, 1080],
] as const) {
  test(`${width}×${height} 下 0～8 台电脑不用滚动都在地图里，组网标签不被连线穿过`, async ({
    page,
  }) => {
    await mockMapChat(page);
    await page.route("**/api/identity", (route) =>
      route.fulfill({ json: identity }),
    );
    let peers = [makePeer()];
    await page.route("**/api/peers", (route) =>
      route.fulfill({ json: { peers } }),
    );
    await page.setViewportSize({ width, height });
    for (let count = 0; count <= 8; count++) {
      peers = [
        // 本机在别的电脑上的名字显示在“这台电脑”下面，本机节点因此更高
        makePeer(0, {
          is_local: true,
          display_name: "书房电脑",
          source: "local",
        }),
        ...Array.from({ length: count }, (_, index) =>
          makePeer(index + 1, {
            reachable: [true, false, true, null][index % 4]!,
            network: (["wireguard", "other", "n2n"] as const)[index % 3],
            service_count: 9,
          }),
        ),
      ];
      await page.goto("/app/map");
      await expect(page.locator(".map-node")).toHaveCount(count + 1);
      await expect(page.locator(".map-link-network")).toHaveCount(count);
      await page.evaluate(() => document.fonts.ready);
      const result = await page.evaluate(() => {
        const rect = (element: Element) => {
          const { left, top, right, bottom } = element.getBoundingClientRect();
          return { left, top, right, bottom };
        };
        const canvas = rect(document.querySelector(".map-canvas")!);
        const nodes = Array.from(document.querySelectorAll(".map-node")).map(
          rect,
        );
        const centers = Array.from(
          document.querySelectorAll(".map-node-position"),
        ).map((element) => {
          const box = rect(element);
          return {
            x: (box.left + box.right) / 2,
            y: (box.top + box.bottom) / 2,
          };
        });
        const labels = Array.from(
          document.querySelectorAll(".map-link-network"),
        ).map(rect);
        return {
          scrollY: window.scrollY,
          innerHeight: window.innerHeight,
          canvas,
          nodes,
          local: centers[0]!,
          peers: centers.slice(1),
          labels,
        };
      });
      expect(result.scrollY).toBe(0);
      const label = `${count} 台对端`;
      for (const node of result.nodes) {
        expect(node.top, label).toBeGreaterThanOrEqual(result.canvas.top);
        expect(node.left, label).toBeGreaterThanOrEqual(result.canvas.left);
        expect(node.right, label).toBeLessThanOrEqual(result.canvas.right);
        expect(node.bottom, label).toBeLessThanOrEqual(result.canvas.bottom);
        // 第一屏就看得到，不用往下滚
        expect(node.bottom, label).toBeLessThanOrEqual(result.innerHeight);
      }
      result.nodes.forEach((a, index) => {
        for (const b of result.nodes.slice(index + 1))
          expect(
            a.right <= b.left ||
              b.right <= a.left ||
              a.bottom <= b.top ||
              b.bottom <= a.top,
            label,
          ).toBe(true);
      });
      for (const box of result.labels) {
        expect(box.left, label).toBeGreaterThanOrEqual(result.canvas.left);
        expect(box.right, label).toBeLessThanOrEqual(result.canvas.right);
        for (const node of result.nodes)
          expect(
            box.right <= node.left ||
              node.right <= box.left ||
              box.bottom <= node.top ||
              node.bottom <= box.top,
            `${label}：标签压在电脑上`,
          ).toBe(true);
        for (const peer of result.peers)
          expect(
            crosses(result.local, peer, box),
            `${label}：连线穿过标签`,
          ).toBe(false);
      }
    }
  });
}

/** 线段是否穿过矩形（Liang-Barsky 裁剪）。 */
function crosses(
  a: { x: number; y: number },
  b: { x: number; y: number },
  box: { left: number; top: number; right: number; bottom: number },
) {
  let start = 0;
  let end = 1;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  for (const [p, q] of [
    [-dx, a.x - box.left],
    [dx, box.right - a.x],
    [-dy, a.y - box.top],
    [dy, box.bottom - a.y],
  ] as const) {
    if (p === 0) {
      if (q <= 0) return false;
      continue;
    }
    const t = q / p;
    if (p < 0) start = Math.max(start, t);
    else end = Math.min(end, t);
    if (start >= end) return false;
  }
  return true;
}
