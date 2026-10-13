import { expect, test } from "@playwright/test";
import type { ResourceOverview } from "../src/api/schemas/overview";

test("首页按程序收拢，键盘展开、刷新和返回入口保留身份", async ({
  page,
  request,
}, testInfo) => {
  const response = await request.get("/api/resources/overview");
  const overview = (await response.json()) as ResourceOverview;
  overview.schema_version = "resource-overview-programs/v1";
  const nodeId = `node_${"1".repeat(32)}`;
  overview.nodes = {
    ...overview.nodes,
    source: "local_observation",
    freshness: "fresh",
    error: null,
    evidence_at: overview.generated_at,
  };
  overview.services = {
    ...overview.services,
    source: "local_observation",
    freshness: "fresh",
    error: null,
    evidence_at: overview.generated_at,
  };
  overview.nodes.items = [
    {
      node_id: nodeId,
      display_name: "工作室 Mac",
      platform: "macos",
      state: "local",
      source: "local_observation",
      evidence_at: overview.generated_at,
      freshness: "fresh",
      service_count: 33,
    },
  ];
  const entries: [number, string, "python" | "docker" | "model", number][] = [
    [8787, "app.py", "python", 1],
    [8765, "nanobot", "python", 2],
    [18790, "nanobot", "python", 2],
    [80, "baota", "docker", 3],
    [443, "baota", "docker", 3],
    [5984, "obsidian-couchdb", "docker", 4],
    [9001, "penpot-penpot-frontend-1", "docker", 5],
    [9002, "penpot-penpot-frontend-1", "docker", 5],
    [6061, "penpot-penpot-exporter-1", "docker", 6],
    [8080, "llama.cpp", "model", 7],
  ];
  overview.services.items = entries.map(([port, name, kind, group], index) => ({
    service_id: `service_${(index + 1).toString(16).padStart(32, "0")}`,
    node_id: nodeId,
    display_name: `${kind === "python" ? "Python" : kind === "docker" ? "Docker" : "模型服务"} · ${name} · ${port}`,
    application: {
      group_id: `application_${group.toString(16).padStart(32, "0")}`,
      name,
      kind,
    },
    protocol: "tcp",
    port,
    access_address: `tcp://127.0.0.1:${port}`,
    accessibility: "loopback",
    lifecycle: "active",
    state: index === 2 ? "unavailable" : "available",
    source: "local_observation",
    evidence_at: overview.generated_at,
    freshness: "fresh",
  }));
  overview.services.items.push(
    ...Array.from({ length: 23 }, (_, index) => ({
      ...overview.services.items[0]!,
      service_id: `service_${(index + 11).toString(16).padStart(32, "0")}`,
      display_name: null,
      application: null,
      port: 50000 + index,
      access_address: `tcp://127.0.0.1:${50000 + index}`,
      state: "unknown" as const,
    })),
  );
  overview.incidents.items = [];
  await page.route(
    /\/api\/(?:resources\/overview|ui\/overview)$/,
    async (route) => {
      await route.fulfill({ json: overview });
    },
  );
  await page.route("**/api/operations", (route) => route.fulfill({ json: [] }));
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/app/overview");
  const named = page.getByRole("list", { name: "有名称的服务", exact: true });
  await expect(named.locator(":scope > li")).toHaveCount(7);
  await expect(page.getByText(/7 个程序/)).toBeVisible();
  await expect(page.getByText("部分入口需确认")).toBeVisible();
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth + 1,
    ),
  ).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath("program-groups-desktop.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 320, height: 760 });
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth + 1,
    ),
  ).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath("program-groups-narrow.png"),
    fullPage: true,
  });

  const program = page.locator(
    `#application_${"2".padStart(32, "0")} > details`,
  );
  await program.locator(":scope > summary").focus();
  await page.keyboard.press("Enter");
  await expect(program).toHaveAttribute("open", "");
  await expect(
    page.getByRole("list", { name: "nanobot 的入口" }).getByRole("listitem"),
  ).toHaveCount(2);
  await expect(program.getByText("当前不可用")).toBeVisible();
  await page.getByRole("button", { name: "刷新" }).click();
  await expect(page.getByRole("button", { name: "刷新" })).toBeEnabled();
  await expect(program).toHaveAttribute("open", "");
  await page.getByText("查看全部 33 个检测项目（技术清单）").click();
  await expect(
    page
      .getByRole("list", { name: "完整检测清单", exact: true })
      .getByRole("listitem"),
  ).toHaveCount(33);
  await page.getByText("查看全部 33 个检测项目（技术清单）").click();
  const serviceId = overview.services.items[2]!.service_id;
  await page.goto(`/app/overview#${serviceId}`);
  await expect(page.locator(`#${serviceId}`)).toBeFocused();
  await expect(program).toHaveAttribute("open", "");
  await page.screenshot({
    path: testInfo.outputPath("program-entry-return.png"),
    fullPage: true,
  });
});
