import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { makeThread } from "../chat/testFixtures";
import { ServiceMapPage } from "../service-map/ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../service-map/testFixtures";
import type { Patrol } from "./api";

const SCRIPT = "python:srv.py@18941";
const server = setupServer();
let client: QueryClient;
let forgotten: string[];
let repairReads: number;
let refuse: string | null;

const services = () =>
  makeLocalServices(
    [
      makeService({ key: "program:notes", name: "笔记", kind: "program" }),
      makeService({
        key: "docker:compose:photos",
        name: "相册",
        kind: "docker",
        state: "stopped",
      }),
      makeService({
        key: SCRIPT,
        name: "accept 240",
        kind: "python",
        state: "stopped",
      }),
    ].filter((item) => !forgotten.includes(item.key)),
  );

const patrol: Patrol = {
  checked_at: null,
  investigations_left_today: 12,
  services: [],
};

function renderMap() {
  server.use(
    http.get("/api/peers", () => HttpResponse.json({ peers: [] })),
    http.get("/api/repairs", () => {
      repairReads += 1;
      return HttpResponse.json({ repairs: [] });
    }),
    http.get("/api/ui/overview", () => HttpResponse.json(makeMapOverview())),
    http.get("/api/services/local", () => HttpResponse.json(services())),
    http.get("/api/patrol", () => HttpResponse.json(patrol)),
    http.post("/api/patrol/services/:key/forget", ({ params }) => {
      if (refuse !== null)
        return HttpResponse.json({ detail: refuse }, { status: 409 });
      forgotten.push(String(params.key));
      return HttpResponse.json(patrol);
    }),
    http.get("/api/threads", () => HttpResponse.json([])),
    http.get("/api/identity", () =>
      HttpResponse.json({ detail: "未配置" }, { status: 404 }),
    ),
    http.get("/api/ui/threads/:id", () =>
      HttpResponse.json({ thread: makeThread(), messages: [] }),
    ),
  );
  client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ServiceMapPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function openComputer() {
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("button", { name: /^这台电脑，在线/ }),
  );
  return { user, dialog: await screen.findByRole("dialog") };
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  forgotten = [];
  repairReads = 0;
  refuse = null;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
});
afterEach(() => {
  cleanup();
  client?.clear();
  server.resetHandlers();
  vi.unstubAllGlobals();
  document.head
    .querySelectorAll('meta[name="tunnelminion-read-only-preview"]')
    .forEach((item) => item.remove());
});
afterAll(() => server.close());

describe("从地图上移除已停止的服务", () => {
  it("只给已停止、不是 Docker 容器的服务；确认后交给本机接口，地图和待处理修复重新读取", async () => {
    renderMap();
    const { user, dialog } = await openComputer();
    await within(dialog).findByText("accept 240");
    expect(
      within(dialog).getAllByRole("button", { name: /^从地图上移除/ }),
    ).toHaveLength(1);
    expect(
      within(dialog).queryByRole("button", { name: "从地图上移除 笔记" }),
    ).toBeNull();
    expect(
      within(dialog).queryByRole("button", { name: "从地图上移除 相册" }),
    ).toBeNull();

    // 先要确认；取消就什么都不做。
    await user.click(
      within(dialog).getByRole("button", { name: "从地图上移除 accept 240" }),
    );
    const confirm = within(dialog).getByRole("group", {
      name: "确认移除 accept 240",
    });
    expect(confirm).toHaveTextContent("巡检对话和修复记录保留");
    expect(confirm).toHaveTextContent("以后它再运行，会重新出现在地图上");
    await user.click(within(confirm).getByRole("button", { name: "取消" }));
    expect(forgotten).toEqual([]);

    const reads = repairReads;
    await user.click(
      within(dialog).getByRole("button", { name: "从地图上移除 accept 240" }),
    );
    await user.click(within(dialog).getByRole("button", { name: "确定移除" }));
    await within(dialog).findByText("笔记");
    expect(forgotten).toEqual([SCRIPT]);
    await expect
      .poll(() => within(dialog).queryByText("accept 240"))
      .toBeNull();
    expect(repairReads).toBeGreaterThan(reads);
  });

  it("后端拒绝时把原因显示出来", async () => {
    refuse = "这个服务还在运行，不能从地图上移除";
    renderMap();
    const { user, dialog } = await openComputer();
    await user.click(
      await within(dialog).findByRole("button", {
        name: "从地图上移除 accept 240",
      }),
    );
    await user.click(within(dialog).getByRole("button", { name: "确定移除" }));
    expect(
      await within(dialog).findByText("这个服务还在运行，不能从地图上移除"),
    ).toBeVisible();
    expect(within(dialog).getByText("accept 240")).toBeVisible();
  });

  it("预览模式不提供移除", async () => {
    const meta = document.createElement("meta");
    meta.name = "tunnelminion-read-only-preview";
    meta.content = "true";
    document.head.append(meta);
    renderMap();
    const { dialog } = await openComputer();
    await within(dialog).findByText("accept 240");
    expect(
      within(dialog).queryByRole("button", { name: /^从地图上移除/ }),
    ).toBeNull();
  });
});
