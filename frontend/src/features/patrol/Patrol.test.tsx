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
// 模拟主人还没在管理员确认框里点按钮：测试放行前 Windows 服务权限请求一直等着。
let windowsGate: Promise<void> = Promise.resolve();
let windowsRefused = false;

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
        const body = (await request.json()) as {
          enabled: boolean;
          stuck?: boolean;
        };
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
              // 和后端一致：stuck 不给时保持原样，关掉自动修时一并关掉。
              stuck_enabled: body.enabled
                ? (body.stuck ?? item.auto_repair.stuck_enabled)
                : false,
            },
          })),
        };
        return HttpResponse.json(patrol);
      },
    ),
    http.put(
      "/api/patrol/services/:key/windows-service",
      async ({ request, params }) => {
        const body = (await request.json()) as { granted: boolean };
        changes.push({ url: `windows:${String(params.key)}`, body });
        await windowsGate;
        if (windowsRefused)
          return HttpResponse.json(
            { detail: "没有完成管理员确认，权限没有改动" },
            { status: 409 },
          );
        patrol = {
          ...patrol,
          services: patrol.services.map((item) => ({
            ...item,
            windows_service: item.windows_service && {
              ...item.windows_service,
              granted: body.granted,
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
  windowsGate = Promise.resolve();
  windowsRefused = false;
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
          stuck_available: false,
          stuck_enabled: false,
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

  it("有卡住修法且已打开自动修时，才显示'卡住了也自动修'，勾上时带 stuck", async () => {
    renderMap([
      watched({
        key: "program:notes",
        name: "笔记",
        auto_repair: {
          ...watched().auto_repair,
          kind: "relaunch_program",
          stuck_available: true,
        },
      }),
    ]);
    const { user, dialog } = await openComputer();
    expect(
      await within(dialog).findByText(
        "只限按上次的方式重新运行程序，修完会自己确认",
      ),
    ).toBeVisible();
    expect(
      within(dialog).queryByRole("checkbox", { name: "卡住了也自动修" }),
    ).toBeNull();
    await user.click(
      within(dialog).getByRole("checkbox", { name: "挂了可以自动修" }),
    );
    const stuck = await within(dialog).findByRole("checkbox", {
      name: "卡住了也自动修",
    });
    expect(stuck).not.toBeChecked();
    await user.click(stuck);
    await waitFor(() => expect(stuck).toBeChecked());
    expect(changes.map((item) => item.body)).toEqual([
      { enabled: true },
      { enabled: true, stuck: true },
    ]);
  });

  it("修法被拒绝时写明原因，并给出可以照着做的步骤", async () => {
    renderMap([
      {
        ...down(),
        reason: "stuck",
        reason_text: "卡住了：端口还在听，但不再响应",
        repair_refusal: "这个程序的启动信息读不全，不能替你重新运行",
        manual_steps: [
          { text: "在程序原来的目录里重新运行", command: "node server.js" },
        ],
      },
    ]);
    const { dialog } = await openComputer();
    expect(
      await within(dialog).findByText(
        "这个程序的启动信息读不全，不能替你重新运行",
      ),
    ).toBeVisible();
    const steps = within(dialog).getByRole("region", { name: "可以照着做" });
    expect(within(steps).getByText("node server.js")).toBeVisible();
    expect(within(steps).getByRole("button", { name: "复制" })).toBeVisible();
  });

  it("Windows 服务开关：等确认时禁用并提示，确认后打开", async () => {
    let release = () => {};
    windowsGate = new Promise((resolve) => (release = resolve));
    renderMap([
      watched({
        key: "program:notes",
        name: "笔记",
        windows_service: { name: "NotesSvc", granted: false },
      }),
    ]);
    const { user, dialog } = await openComputer();
    const box = await within(dialog).findByRole("checkbox", {
      name: "允许 Agent 重启这个 Windows 服务",
    });
    expect(
      within(dialog).getByText(
        "打开时会弹一次 Windows 管理员确认，只给这一个服务加启停权限；关掉时撤回",
      ),
    ).toBeVisible();
    await user.click(box);
    expect(
      await within(dialog).findByText("等你在弹出的确认框里点“是”…"),
    ).toBeVisible();
    expect(box).toBeDisabled();
    release();
    await waitFor(() => expect(box).toBeChecked());
    expect(box).toBeEnabled();
    expect(changes).toEqual([
      { url: "windows:program:notes", body: { granted: true } },
    ]);
  });

  it("Windows 服务开关：主人点了'否'时显示后端说明，开关保持原样", async () => {
    windowsRefused = true;
    renderMap([
      watched({
        key: "program:notes",
        name: "笔记",
        windows_service: { name: "NotesSvc", granted: false },
      }),
    ]);
    const { user, dialog } = await openComputer();
    const box = await within(dialog).findByRole("checkbox", {
      name: "允许 Agent 重启这个 Windows 服务",
    });
    await user.click(box);
    expect(
      await within(dialog).findByText("没有完成管理员确认，权限没有改动"),
    ).toBeVisible();
    expect(box).not.toBeChecked();
    expect(box).toBeEnabled();
  });

  it("中文日期", () => {
    expect(chineseDate("2026-01-05")).toBe("2026年1月5日");
  });
});
