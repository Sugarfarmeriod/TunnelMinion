import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
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

import { ServiceMapPage } from "../service-map/ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makePeer,
  makeService,
} from "../service-map/testFixtures";
import { makeRun, makeThread } from "../chat/testFixtures";
import type { RepairDetail } from "./api";
import { finishedRepair, makeRemoteRepair, makeRepair } from "./testFixtures";

const server = setupServer(
  http.get("/api/peers", () => HttpResponse.json({ peers: [] })),
);
let client: QueryClient;
let repair: RepairDetail;
let reads: number;
let servicesRead: number;
let posts: string[];

function renderMap(entry = "/app/map") {
  client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Infinity },
      mutations: { retry: false },
    },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <ServiceMapPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function openRepair() {
  const button = await screen.findByRole("button", {
    name: "这台电脑有 1 个待批准的修复",
  });
  fireEvent.click(button);
  return screen.findByRole("dialog", { name: "要修好“相册”吗？" });
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  repair = makeRepair();
  reads = 0;
  servicesRead = 0;
  posts = [];
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
  server.use(
    http.get("/api/ui/overview", () => HttpResponse.json(makeMapOverview())),
    http.get("/api/services/local", () => {
      servicesRead++;
      return HttpResponse.json(
        makeLocalServices([
          makeService({
            key: "docker:photos",
            name: "相册",
            kind: "docker",
            state: repair.status === "succeeded" ? "running" : "stopped",
          }),
        ]),
      );
    }),
    http.get("/api/repairs", () => HttpResponse.json({ repairs: [repair] })),
    http.get("/api/repairs/:id", () => {
      reads++;
      return HttpResponse.json(repair);
    }),
    http.post("/api/repairs/:id/:action", ({ params, request }) => {
      expect(request.headers.get("x-tunnelminion-request")).toBe("same-origin");
      posts.push(String(params.action));
      repair = {
        ...repair,
        status: params.action === "reject" ? "rejected" : "authorized",
        approval_expires_at: null,
      };
      return HttpResponse.json(repair, {
        status: params.action === "approve" ? 202 : 200,
      });
    }),
    http.get("/api/operations", () => HttpResponse.json([])),
  );
});
afterEach(() => {
  cleanup();
  client?.clear();
  server.resetHandlers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document
    .querySelector('meta[name="tunnelminion-read-only-preview"]')
    ?.remove();
});
afterAll(() => server.close());

describe("地图上的本机修复", () => {
  it.each([1440, 320])(
    "%ipx 点节点感叹号直接打开本机或对端修复框",
    async (width) => {
      vi.stubGlobal("innerWidth", width);
      const peer = makePeer(1, { pending_repairs: [makeRemoteRepair()] });
      server.use(
        http.get("/api/peers", () => HttpResponse.json({ peers: [peer] })),
      );
      const user = userEvent.setup();
      renderMap();
      for (const name of ["这台电脑", peer.display_name]) {
        const bang = await screen.findByRole("button", {
          name: `${name}有 1 个待批准的修复`,
        });
        await user.click(bang.querySelector("svg")!);
        const dialog = await screen.findByRole("dialog", {
          name: `要修好“${name === "这台电脑" ? "相册" : "远端相册"}”吗？`,
        });
        if (name === "这台电脑")
          expect(
            within(dialog).getByRole("button", { name: "批准并修复" }),
          ).toBeEnabled();
        else {
          expect(
            within(dialog).getByText(`请到 ${name} 的地图上点感叹号批准`),
          ).toBeVisible();
          expect(
            within(dialog).queryByRole("button", { name: "批准并修复" }),
          ).toBeNull();
        }
        await user.click(
          within(dialog).getByRole("button", { name: "关闭修复" }),
        );
        expect(bang).toHaveFocus();
      }
      expect(posts).toEqual([]);
    },
  );

  it("聊天打开时点地图感叹号也能进入修复框", async () => {
    vi.stubGlobal("innerWidth", 1440);
    server.use(http.get("/api/threads", () => HttpResponse.json([])));
    const user = userEvent.setup();
    renderMap();
    const bang = await screen.findByRole("button", {
      name: "这台电脑有 1 个待批准的修复",
    });
    await user.click(screen.getByRole("button", { name: "对话", exact: true }));
    expect(
      screen.getByRole("dialog", { name: "对话", exact: true }),
    ).toBeVisible();
    await user.click(bang.querySelector("svg")!);
    expect(
      await screen.findByRole("dialog", { name: "要修好“相册”吗？" }),
    ).toBeVisible();
  });

  it("服务按打不开、已停止、正常排列，已停止不能打开", async () => {
    server.use(
      http.get("/api/services/local", () =>
        HttpResponse.json(
          makeLocalServices([
            makeService({
              key: "program:ok",
              name: "正常服务",
              state: "running",
            }),
            makeService({
              key: "program:stopped",
              name: "停止服务",
              state: "stopped",
            }),
            makeService({
              key: "program:down",
              name: "故障服务",
              endpoints: [
                {
                  protocol: "tcp",
                  address: "127.0.0.1",
                  port: 8080,
                  has_web_page: false,
                },
              ],
            }),
          ]),
        ),
      ),
    );
    renderMap();
    fireEvent.click(
      await screen.findByRole("button", { name: "这台电脑，在线，3 个服务" }),
    );
    const list = screen.getByRole("list", { name: "这台电脑上的服务" });
    expect(
      within(list)
        .getAllByRole("listitem")
        .map((item) => item.querySelector(".map-service-name")?.textContent),
    ).toEqual(["故障服务", "停止服务", "正常服务"]);
    expect(
      screen.queryByRole("link", { name: "打开 停止服务" }),
    ).not.toBeInTheDocument();
  });
  it("只给本机未过期的待批准修复显示感叹号，服务框可打开同一个五项批准框", async () => {
    const other = makeRepair({
      repair_id: "operation_" + "b".repeat(32),
      node_id: "node_" + "f".repeat(32),
    });
    server.use(
      http.get("/api/repairs", () =>
        HttpResponse.json({
          repairs: [
            other,
            makeRepair({
              approval_expires_at: new Date(Date.now() - 1_000).toISOString(),
            }),
            repair,
          ],
        }),
      ),
    );
    renderMap();
    await screen.findByText("! 有 1 件事要你批准");
    fireEvent.click(
      await screen.findByRole("button", { name: "这台电脑，在线，1 个服务" }),
    );
    expect(screen.getByText("已停止")).toBeVisible();
    const panel = screen.getByRole("dialog", { name: "这台电脑上的服务" });
    expect(within(panel).getByText("需要处理的事")).toBeVisible();
    fireEvent.click(within(panel).getByRole("button", { name: "看看怎么修" }));
    const dialog = await screen.findByRole("dialog", {
      name: "要修好“相册”吗？",
    });
    for (const text of [
      "要做什么",
      "为什么",
      "会有什么影响",
      "怎么确认修好",
      "没修好怎么办",
      repair.reason,
      repair.impact_summary,
    ])
      expect(within(dialog).getByText(text)).toBeVisible();
    const advanced = within(dialog).getByText("高级：将执行的命令");
    expect(advanced.closest("details")).not.toHaveAttribute("open");
    fireEvent.click(advanced);
    expect(within(dialog).getByText("docker start fake-photos")).toBeVisible();
    expect(screen.getByRole("button", { name: "关闭修复" })).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(screen.getByRole("button", { name: "先不用" })).toHaveFocus();
  });

  it.each(["Escape", "×"])("%s 只关框，不会拒绝", async (key) => {
    renderMap();
    const dialog = await openRepair();
    if (key === "Escape") fireEvent.keyDown(dialog, { key });
    else
      fireEvent.click(within(dialog).getByRole("button", { name: "关闭修复" }));
    expect(
      screen.queryByRole("dialog", { name: "要修好“相册”吗？" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "这台电脑有 1 个待批准的修复" }),
    ).toBeVisible();
    expect(posts).toEqual([]);
  });

  it("倒计时归零后禁用批准，感叹号消失", async () => {
    vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] });
    repair = makeRepair({
      approval_expires_at: new Date(Date.now() + 2_000).toISOString(),
    });
    renderMap();
    await openRepair();
    expect(screen.getByText("10 分钟内有效 · 还剩 0:02")).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(screen.getByText("10 分钟内有效 · 还剩 0:01")).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(screen.getByText("10 分钟内有效 · 已过期")).toBeVisible();
    expect(screen.getByRole("button", { name: "批准并修复" })).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: /待批准的修复/ }),
    ).not.toBeInTheDocument();
  });

  it.each(["succeeded", "rolled_back"] as const)(
    "批准后每秒轮询，展示 %s 并刷新服务，终态后停止轮询",
    async (status) => {
      vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
      renderMap();
      const dialog = await openRepair();
      fireEvent.click(screen.getByRole("button", { name: "批准并修复" }));
      await screen.findByText("正在修……");
      expect(screen.getByRole("button", { name: "关闭修复" })).toBeDisabled();
      expect(screen.getByLabelText("修复进度")).toHaveTextContent(
        "再核对一次正在执行正在确认",
      );
      fireEvent.keyDown(dialog, { key: "Escape" });
      expect(dialog).toBeVisible();
      const initial = reads;
      repair = { ...repair, status: "executing" };
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_000);
      });
      await waitFor(() => expect(reads).toBe(initial + 1));
      repair = { ...repair, status: "verifying" };
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_000);
      });
      await waitFor(() => expect(reads).toBe(initial + 2));
      repair = finishedRepair(status);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_000);
      });
      await screen.findByText(status === "succeeded" ? "修好了" : "没修好", {
        exact: true,
      });
      if (status === "rolled_back")
        expect(
          screen.getByText("容器重启了，但服务还是没起来。"),
        ).toBeVisible();
      await waitFor(() => expect(servicesRead).toBeGreaterThan(1));
      const stopped = reads;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3_000);
      });
      expect(reads).toBe(stopped);
      expect(posts).toEqual(["approve"]);
      expect(
        screen.queryByRole("button", { name: /待批准的修复/ }),
      ).not.toBeInTheDocument();
    },
  );

  it("先不用调用拒绝接口，取消后移除感叹号", async () => {
    renderMap();
    await openRepair();
    fireEvent.click(screen.getByRole("button", { name: "先不用" }));
    await screen.findByText("已取消");
    expect(posts).toEqual(["reject"]);
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: /待批准的修复/ }),
      ).not.toBeInTheDocument(),
    );
  });

  it.each(["approve", "reject"])(
    "%s 出错后保留可重试的批准框",
    async (action) => {
      server.use(
        http.post("/api/repairs/:id/:action", () =>
          HttpResponse.json({ detail: "临时失败" }, { status: 409 }),
        ),
      );
      renderMap();
      await openRepair();
      fireEvent.click(
        screen.getByRole("button", {
          name: action === "approve" ? "批准并修复" : "先不用",
        }),
      );
      await screen.findByRole("alert");
      expect(screen.getByRole("button", { name: "批准并修复" })).toBeEnabled();
      expect(screen.getByRole("button", { name: "先不用" })).toBeEnabled();
    },
  );

  it("只读预览能查看但没有批准和拒绝按钮", async () => {
    const meta = document.createElement("meta");
    meta.name = "tunnelminion-read-only-preview";
    meta.content = "true";
    document.head.append(meta);
    renderMap();
    await openRepair();
    expect(
      screen.getByText("只读预览：可以查看修复，不能批准或拒绝。"),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "批准并修复" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "先不用" }),
    ).not.toBeInTheDocument();
    expect(posts).toEqual([]);
  });

  it("对话中只匹配来源线程的回答按钮，打开和关闭批准框后可继续看对话", async () => {
    const thread = makeThread(repair.origin.thread_id!);
    server.use(
      http.get("/api/threads", () => HttpResponse.json([thread])),
      http.get("/api/ui/threads/:id", () =>
        HttpResponse.json({
          thread,
          messages: [
            {
              role: "assistant",
              content: "建议修好相册",
              created_at: thread.created_at,
              run_id: repair.origin.run_id,
              answer_checked: true,
              answer_basis: "inferred",
            },
          ],
        }),
      ),
      http.get("/api/runs/:id", () => HttpResponse.json(makeRun("completed"))),
    );
    renderMap(`/app/map?thread=${thread.thread_id}`);
    const drawer = await screen.findByRole("dialog", {
      name: "对话",
    });
    const button = await within(drawer).findByRole("button", {
      name: "看看怎么修",
    });
    await userEvent.setup().click(button);
    const dialog = await screen.findByRole("dialog", {
      name: "要修好“相册”吗？",
    });
    fireEvent.keyDown(dialog, { key: "Escape" });
    await screen.findByRole("dialog", { name: "对话" });
    expect(posts).toEqual([]);
  });
});
