import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
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

import { makeRun, makeThread } from "../chat/testFixtures";
import { ServiceMapPage } from "../service-map/ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../service-map/testFixtures";
import {
  chineseDate,
  patrolQueryKey,
  type Patrol,
  type PatrolService,
} from "./api";

const server = setupServer();
let client: QueryClient;
let patrol: Patrol;
const changes: { url: string; body: unknown }[] = [];
const threadReads: string[] = [];

function watched(overrides: Partial<PatrolService> = {}): PatrolService {
  return {
    key: "docker:compose:photos",
    name: "相册",
    status: "ok",
    reason: null,
    reason_text: null,
    down_since: null,
    confirmed_at: null,
    thread_id: null,
    repair_id: null,
    auto_repair: {
      available: true,
      kind: "restart_containers",
      enabled: false,
      enabled_on: null,
      paused: false,
      last_attempt_at: null,
      last_result: null,
    },
    ...overrides,
  };
}

const down = () =>
  watched({
    status: "down",
    reason: "container_exited",
    reason_text: "容器已退出",
    confirmed_at: new Date(Date.now() - 3 * 60_000).toISOString(),
    thread_id: "thread_0123456789abcdef0123456789abcdef",
  });

function renderMap(services = [watched()]) {
  patrol = { checked_at: null, investigations_left_today: 12, services };
  const thread = makeThread();
  server.use(
    http.get("/api/peers", () => HttpResponse.json({ peers: [] })),
    http.get("/api/repairs", () => HttpResponse.json({ repairs: [] })),
    http.get("/api/ui/overview", () => HttpResponse.json(makeMapOverview())),
    http.get("/api/services/local", () =>
      HttpResponse.json(
        makeLocalServices([
          makeService({ key: "program:notes", name: "笔记", kind: "program" }),
          makeService({
            key: "docker:compose:photos",
            name: "相册",
            kind: "docker",
            state: "stopped",
          }),
        ]),
      ),
    ),
    http.get("/api/patrol", () => HttpResponse.json(patrol)),
    http.put(
      "/api/patrol/services/:key/auto-repair",
      async ({ request, params }) => {
        const body = (await request.json()) as { enabled: boolean };
        changes.push({ url: String(params.key), body });
        patrol = {
          ...patrol,
          services: patrol.services.map((item) => ({
            ...item,
            auto_repair: {
              ...item.auto_repair,
              enabled: body.enabled,
              enabled_on: body.enabled ? "2026-10-29" : null,
              paused: false,
            },
          })),
        };
        return HttpResponse.json(patrol);
      },
    ),
    http.post("/api/patrol/services/:key/acknowledge", ({ params }) => {
      changes.push({ url: `ack:${String(params.key)}`, body: null });
      patrol = {
        ...patrol,
        services: patrol.services.map((item) => ({
          ...item,
          status: "acknowledged",
        })),
      };
      return HttpResponse.json(patrol);
    }),
    http.get("/api/threads", () => HttpResponse.json([])),
    http.get("/api/identity", () =>
      HttpResponse.json({ detail: "未配置" }, { status: 404 }),
    ),
    http.get("/api/ui/threads/:id", ({ params }) => {
      threadReads.push(String(params.id));
      return HttpResponse.json({ thread, messages: [] });
    }),
    http.get("/api/runs/:id", () => HttpResponse.json(makeRun())),
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

async function openComputer(name: RegExp = /^这台电脑，在线/) {
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name }));
  return {
    user,
    dialog: screen.getByRole("dialog", { name: "这台电脑上的服务" }),
  };
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  changes.length = 0;
  threadReads.length = 0;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
  Object.defineProperty(window, "innerWidth", {
    value: 1280,
    configurable: true,
    writable: true,
  });
});
afterEach(() => {
  cleanup();
  client?.clear();
  server.resetHandlers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());

describe("巡检", () => {
  it("挂了的服务排最前、标红写原因和确认时间，电脑头上显示挂掉的数量", async () => {
    renderMap([down()]);
    expect(await screen.findByText("! 1 个服务挂了")).toBeVisible();
    const { dialog } = await openComputer();
    const names = within(dialog)
      .getAllByRole("listitem")
      .map((item) => item.querySelector(".map-service-name")?.textContent);
    expect(names).toEqual(["相册", "笔记"]);
    expect(within(dialog).getByText("挂了 · 容器已退出")).toBeVisible();
    expect(within(dialog).getByText("巡检 3 分钟前确认")).toBeVisible();
    expect(within(dialog).getAllByRole("listitem")[0]!.className).toContain(
      "is-down",
    );
  });

  it("看巡检记录打开那条对话", async () => {
    renderMap([down()]);
    await screen.findByText("! 1 个服务挂了");
    const { user, dialog } = await openComputer();
    await user.click(
      within(dialog).getByRole("button", { name: "看 相册 的巡检记录" }),
    );
    await waitFor(() =>
      expect(threadReads).toContain("thread_0123456789abcdef0123456789abcdef"),
    );
  });

  it("'这次是我有意停的'交给本机接口，之后不再标红", async () => {
    renderMap([down()]);
    await screen.findByText("! 1 个服务挂了");
    const { user, dialog } = await openComputer();
    await user.click(
      within(dialog).getByRole("button", { name: "这次是我有意停的 相册" }),
    );
    await waitFor(() =>
      expect(changes).toEqual([
        { url: "ack:docker:compose:photos", body: null },
      ]),
    );
    expect(await within(dialog).findByText("已停止")).toBeVisible();
    expect(
      within(dialog).queryByRole("button", { name: /有意停的/ }),
    ).toBeNull();
  });

  it("后台服务的开关写明只限重新启动这个后台服务", async () => {
    renderMap([
      watched({
        auto_repair: {
          available: true,
          kind: "restart_launch_agent",
          enabled: false,
          enabled_on: null,
          paused: false,
          last_attempt_at: null,
          last_result: null,
        },
      }),
    ]);
    const { dialog } = await openComputer();
    expect(
      await within(dialog).findByText(
        "只限重新启动这个后台服务，修完会自己确认",
      ),
    ).toBeVisible();
  });

  it("开关默认关；勾上以后写明从哪天起允许，再取消就关掉", async () => {
    renderMap();
    const { user, dialog } = await openComputer();
    const box = await within(dialog).findByRole("checkbox", {
      name: "挂了可以自动修",
    });
    expect(box).not.toBeChecked();
    expect(
      within(dialog).getByText("只限重启容器，修完会自己确认"),
    ).toBeVisible();
    await user.click(box);
    await waitFor(() => expect(box).toBeChecked());
    expect(
      within(dialog).getByText("从 2026年10月29日 起允许，修完会自己确认"),
    ).toBeVisible();
    await user.click(box);
    await waitFor(() => expect(box).not.toBeChecked());
    expect(changes.map((item) => item.body)).toEqual([
      { enabled: true },
      { enabled: false },
    ]);
  });

  it("暂停时开关取消勾选并说明，重新勾上会重新打开", async () => {
    renderMap([
      watched({
        auto_repair: {
          ...watched().auto_repair,
          enabled: true,
          enabled_on: "2026-10-20",
          paused: true,
          last_result: "failed",
        },
      }),
    ]);
    const { user, dialog } = await openComputer();
    const box = await within(dialog).findByRole("checkbox", {
      name: "挂了可以自动修",
    });
    expect(box).not.toBeChecked();
    expect(
      within(dialog).getByText(
        "自动修已暂停：上次没修好。看过以后重新勾上才会再试",
      ),
    ).toBeVisible();
    await user.click(box);
    await waitFor(() =>
      expect(changes.at(-1)?.body).toEqual({ enabled: true }),
    );
  });

  it("没有现成修法的服务没有开关", async () => {
    renderMap([
      watched({
        auto_repair: {
          ...watched().auto_repair,
          available: false,
          kind: null,
        },
      }),
    ]);
    const { dialog } = await openComputer();
    await within(dialog).findByText("相册");
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
  });

  it("保存失败时提示", async () => {
    renderMap();
    server.use(
      http.put("/api/patrol/services/:key/auto-repair", () =>
        HttpResponse.json({ detail: "坏了" }, { status: 422 }),
      ),
    );
    const { user, dialog } = await openComputer();
    await user.click(
      await within(dialog).findByRole("checkbox", { name: "挂了可以自动修" }),
    );
    expect(
      await within(dialog).findByText("巡检设置没有保存，请再试一次。"),
    ).toBeVisible();
  });

  it("挂了的服务恢复后，地图重新读服务清单", async () => {
    renderMap([down()]);
    const { dialog } = await openComputer();
    await within(dialog).findByText("挂了 · 容器已退出");
    let reads = 0;
    server.use(
      http.get("/api/services/local", () => {
        reads++;
        return HttpResponse.json(
          makeLocalServices([
            makeService({
              key: "docker:compose:photos",
              name: "相册",
              kind: "docker",
            }),
          ]),
        );
      }),
    );
    patrol = { ...patrol, services: [watched()] };
    await client.invalidateQueries({ queryKey: patrolQueryKey });
    await waitFor(() => expect(reads).toBe(1));
    expect(await within(dialog).findByText("正常")).toBeVisible();
  });

  it("中文日期", () => {
    expect(chineseDate("2026-01-05")).toBe("2026年1月5日");
  });
});
