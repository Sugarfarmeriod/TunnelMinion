import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import type { Patrol, PatrolService } from "../src/features/patrol/api";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../src/features/service-map/testFixtures";

function photos(overrides: Partial<PatrolService> = {}): PatrolService {
  return {
    key: "docker:compose:photos",
    name: "相册",
    status: "down",
    reason: "container_exited",
    reason_text: "容器已退出",
    down_since: new Date().toISOString(),
    confirmed_at: new Date().toISOString(),
    thread_id: null,
    repair_id: null,
    repair_refusal: null,
    manual_steps: [],
    windows_service: null,
    auto_repair: {
      available: true,
      kind: "restart_containers",
      enabled: false,
      enabled_on: null,
      paused: false,
      last_attempt_at: null,
      last_result: null,
      stuck_available: false,
      stuck_enabled: false,
    },
    ...overrides,
  };
}

for (const width of [1440, 320]) {
  test(`${width}px 挂了先标红，打开自动修后修好、红标消失`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.clock.install();
    let running = false;
    let enabled = false;
    const puts: unknown[] = [];
    const patrol = (): Patrol => ({
      checked_at: new Date().toISOString(),
      investigations_left_today: 11,
      services: [
        photos(
          running
            ? {
                status: "ok",
                reason: null,
                reason_text: null,
                confirmed_at: null,
                down_since: null,
              }
            : {},
        ),
      ].map((service) => ({
        ...service,
        auto_repair: {
          ...service.auto_repair,
          enabled,
          enabled_on: enabled ? "2026-10-29" : null,
          last_result: running ? "succeeded" : null,
        },
      })),
    });
    await page.route("**/api/ui/overview", (route) =>
      route.fulfill({ json: makeMapOverview() }),
    );
    await page.route("**/api/repairs", (route) =>
      route.fulfill({ json: { repairs: [] } }),
    );
    await page.route("**/api/services/local", (route) =>
      route.fulfill({
        json: makeLocalServices([
          makeService({
            key: "docker:compose:photos",
            name: "相册",
            kind: "docker",
            state: running ? "running" : "stopped",
          }),
        ]),
      }),
    );
    await page.route("**/api/patrol", (route) =>
      route.fulfill({ json: patrol() }),
    );
    await page.route("**/api/patrol/services/*/auto-repair", (route) => {
      expect(route.request().method()).toBe("PUT");
      expect(route.request().headers()["x-tunnelminion-request"]).toBe(
        "same-origin",
      );
      puts.push(route.request().postDataJSON());
      enabled = true;
      return route.fulfill({ json: patrol() });
    });

    await page.goto("/app/map");
    const node = page.getByRole("button", { name: "这台电脑，在线，1 个服务" });
    await expect(page.getByText("! 1 个服务挂了")).toBeVisible();
    await node.click();
    const dialog = page.getByRole("dialog", { name: "这台电脑上的服务" });
    await expect(dialog.getByText("挂了 · 容器已退出")).toBeVisible();
    const box = dialog.getByRole("checkbox", { name: "挂了可以自动修" });
    await expect(box).not.toBeChecked();
    await box.click();
    await expect(box).toBeChecked();
    await expect(
      dialog.getByText("从 2026年10月29日 起允许，修完会自己确认"),
    ).toBeVisible();
    expect(puts).toEqual([{ enabled: true }]);
    const axe = await new AxeBuilder({ page }).analyze();
    expect(
      axe.violations.filter((item) =>
        ["serious", "critical"].includes(item.impact ?? ""),
      ),
    ).toEqual([]);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);

    // 后端按预先允许修好了：下一次巡检刷新时红标消失，清单跟着变回正常。
    running = true;
    await page.clock.fastForward(16_000);
    await expect(dialog.getByText("正常", { exact: true })).toBeVisible();
    await expect(dialog.getByText(/挂了 ·/)).toHaveCount(0);
    await expect(page.getByText("! 1 个服务挂了")).toHaveCount(0);
  });
}
