import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
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

import { ServiceMapPage } from "../service-map/ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../service-map/testFixtures";
import { allowedToolNames } from "./api";
import type {
  ConversationAbout,
  RunView,
  ThreadDetail,
  ThreadSummary,
} from "./contracts";
import {
  completedRun,
  FakeEventSource,
  makeEvent,
  makeRun,
  makeThread,
  timestamp,
} from "./testFixtures";

const server = setupServer();
let client: QueryClient;
let threads: ThreadDetail[];
let runs: Record<string, RunView>;
let posts: {
  question: string;
  about?: ConversationAbout;
  tool_names: string[];
}[];
let cancels: number;
const local = makeLocalServices();

function renderMap(entry = "/app/map", services = local.services) {
  server.use(
    http.get("/api/services/local", () =>
      HttpResponse.json(makeLocalServices(services)),
    ),
    http.get("/api/ui/overview", () => HttpResponse.json(makeMapOverview())),
    http.get("/api/threads", () =>
      HttpResponse.json(threads.map((item) => item.thread)),
    ),
    http.post("/api/threads", () => {
      const thread = makeThread(
        `thread_${String(threads.length + 1).padStart(32, "0")}`,
      );
      threads.push({ thread, messages: [], context: null });
      return HttpResponse.json(thread);
    }),
    http.get("/api/ui/threads/:id", ({ params }) => {
      const detail = threads.find(
        (item) => item.thread.thread_id === params.id,
      );
      return detail
        ? HttpResponse.json(detail)
        : new HttpResponse(null, { status: 404 });
    }),
    http.get("/api/threads/:id", ({ params }) => {
      const detail = threads.find(
        (item) => item.thread.thread_id === params.id,
      );
      return detail
        ? HttpResponse.json(detail)
        : new HttpResponse(null, { status: 404 });
    }),
    http.post("/api/threads/:id/runs", async ({ params, request }) => {
      const body = (await request.json()) as (typeof posts)[number];
      posts.push(body);
      const thread = threads.find(
        (item) => item.thread.thread_id === params.id,
      )!;
      const runId = `run_${String(posts.length).padStart(32, "0")}`;
      const run = makeRun("running", {
        run_id: runId,
        thread_id: String(params.id),
      });
      runs[runId] = run;
      thread.messages.push({
        role: "user",
        content: body.question,
        run_id: runId,
        created_at: timestamp,
      });
      const context = body.about
        ? {
            ...body.about,
            service_name:
              services.find((item) => item.key === body.about?.service_key)
                ?.name ?? null,
          }
        : null;
      thread.context = context;
      thread.thread = {
        ...thread.thread,
        title: body.question.slice(0, 40),
        context,
        message_count: thread.messages.length,
      };
      return HttpResponse.json(run);
    }),
    http.get("/api/runs/:id", ({ params }) =>
      runs[String(params.id)]
        ? HttpResponse.json(runs[String(params.id)])
        : new HttpResponse(null, { status: 404 }),
    ),
    http.post("/api/runs/:id/cancel", () => {
      cancels += 1;
      return HttpResponse.json(makeRun("cancelled"));
    }),
    http.get("/api/operations", () => HttpResponse.json([])),
  );
  client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Infinity },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <ServiceMapPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function source(index = 0) {
  await waitFor(() =>
    expect(FakeEventSource.instances.length).toBeGreaterThan(index),
  );
  return FakeEventSource.instances[index]!;
}

async function answer(index = 0, content = "服务运行正常") {
  const stream = await source(index);
  const id = /\/runs\/([^/]+)\//.exec(stream.url)![1]!;
  const run = runs[id]!;
  runs[id] = { ...completedRun(content), run_id: id, thread_id: run.thread_id };
  runs[id]!.result!.answer_basis = "inferred";
  const detail = threads.find(
    (item) => item.thread.thread_id === run.thread_id,
  )!;
  detail.messages.push({
    role: "assistant",
    content,
    created_at: timestamp,
    run_id: id,
    answer_checked: true,
    answer_basis: "inferred",
  });
  act(() =>
    stream.emit(
      "finished",
      makeEvent(1, "finished", { run_id: id, stop_reason: "completed" }),
    ),
  );
  await waitFor(() => expect(stream.closed).toBe(true));
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  threads = [];
  runs = {};
  posts = [];
  cancels = 0;
  FakeEventSource.reset();
  vi.stubGlobal("EventSource", FakeEventSource);
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

describe("地图对话抽屉", () => {
  it("发送返回未知结果时复读已有消息和运行，关闭再打开也不重复发送", async () => {
    renderMap();
    server.use(
      http.post("/api/threads/:id/runs", async ({ params, request }) => {
        const value = (await request.json()) as (typeof posts)[number];
        posts.push(value);
        const detail = threads.find(
          (item) => item.thread.thread_id === params.id,
        )!;
        const run = makeRun("running", { thread_id: detail.thread.thread_id });
        runs[run.run_id] = run;
        detail.messages.push({
          role: "user",
          content: value.question,
          created_at: timestamp,
          run_id: run.run_id,
        });
        return HttpResponse.json({ detail: "结果暂时未知" }, { status: 503 });
      }),
    );
    const user = userEvent.setup();
    await user.type(
      screen.getByRole("textbox", { name: "想问点什么？" }),
      "查看现状",
    );
    await user.click(screen.getByRole("button", { name: "问问 Agent" }));
    await source();
    expect(await screen.findByText(/问题不会自动重发/)).toBeVisible();
    expect(screen.getByText("查看现状", { exact: true })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "关闭对话" }));
    await user.click(screen.getByRole("button", { name: "对话" }));
    expect(posts).toHaveLength(1);
    expect(cancels).toBe(0);
  });
  it("正常服务只预填对象并聚焦，手动发送沿用自动工具，关闭后服务页码仍在", async () => {
    const services = Array.from({ length: 21 }, (_, index) =>
      makeService({ key: `python:${index}`, name: `服务${index}` }),
    );
    renderMap("/app/map", services);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: /这台电脑，在线，21 个服务/ }),
    );
    await user.click(screen.getByRole("button", { name: "下一页" }));
    const before = screen.getByRole("navigation", {
      name: "服务分页",
    }).textContent;
    const ask = screen.getAllByRole("button", { name: /^问问 服务/ })[0]!;
    await user.click(ask);
    const question = screen.getByRole("textbox", { name: "问题" });
    expect(question).toHaveFocus();
    expect(
      screen.getByText(/关于：这台电脑 · 服务\d+（Python）/),
    ).toBeVisible();
    expect(posts).toHaveLength(0);
    expect(threads).toHaveLength(0);
    await user.type(question, "  为什么会慢？  ");
    await user.click(screen.getByRole("button", { name: "发送问题" }));
    await source();
    expect(posts[0]).toMatchObject({
      question: "  为什么会慢？  ",
      tool_names: [...allowedToolNames],
      about: { node_id: local.node_id },
    });
    expect(posts[0]?.about?.service_key).toMatch(/^python:/);
    await user.click(screen.getByRole("button", { name: "关闭对话" }));
    expect(
      screen.getByRole("navigation", { name: "服务分页" }).textContent,
    ).toBe(before);
    expect(ask).toHaveFocus();
    expect(cancels).toBe(0);
  });

  it("停止的服务立即提问，缺少 state 的服务按正常服务处理", async () => {
    renderMap("/app/map", [makeService({ state: "stopped" })]);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: /这台电脑，在线，1 个服务/ }),
    );
    expect(
      screen.queryByRole("link", { name: "打开 WireGuard Panel" }),
    ).toBeNull();
    await user.click(
      screen.getByRole("button", { name: "问问 WireGuard Panel" }),
    );
    await source();
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({
      question: "WireGuard Panel怎么打不开？",
      about: { node_id: local.node_id, service_key: "python:app.py" },
    });
    await answer();
    expect(await screen.findByText("推断 · 尚未逐条核对")).toBeVisible();
  });

  it("电脑提问只带电脑；Esc、顶栏切换和焦点循环都能关闭且不取消", async () => {
    renderMap();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: /这台电脑，在线，1 个服务/ }),
    );
    const ask = screen.getByRole("button", { name: "问问 这台电脑 的 Agent" });
    await user.click(ask);
    const input = screen.getByRole("textbox", { name: "问题" });
    await user.type(input, "检查内存");
    await user.tab();
    expect(screen.getByRole("button", { name: "发送问题" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "新对话" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "对话" })).toBeNull();
    expect(ask).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "对话" }));
    expect(screen.getByRole("textbox", { name: "问题" })).toHaveValue(
      "检查内存",
    );
    await user.click(screen.getByRole("button", { name: "发送问题" }));
    await source();
    expect(posts[0]?.about).toEqual({
      node_id: local.node_id,
      service_key: null,
    });
    await user.click(screen.getByRole("button", { name: "对话" }));
    expect(screen.queryByRole("dialog", { name: "对话" })).toBeNull();
    expect(cancels).toBe(0);
  });

  it("全局提问和示例各开新对话，后台回答标未读并直接打开对应对话", async () => {
    renderMap();
    const user = userEvent.setup();
    await user.type(
      screen.getByRole("textbox", { name: "想问点什么？" }),
      "有哪些服务？",
    );
    await user.click(screen.getByRole("button", { name: "问问 Agent" }));
    const first = await source();
    await user.click(screen.getByRole("button", { name: "关闭对话" }));
    expect(first.closed).toBe(false);
    await user.click(
      screen.getByRole("button", { name: "哪个程序最占内存？" }),
    );
    await source(1);
    await user.click(screen.getByRole("button", { name: "关闭对话" }));
    await answer(0, "第一段回答");
    await answer(1, "第二段回答");
    expect(await screen.findByLabelText("2 条未读回答")).toBeVisible();
    await user.click(screen.getByRole("button", { name: /^对话/ }));
    expect(await screen.findByText("第二段回答")).toBeVisible();
    expect(screen.queryByText("第一段回答")).toBeNull();
    expect(screen.queryByLabelText(/条未读回答/)).toBeNull();
    expect(posts.map((item) => item.about)).toEqual([undefined, undefined]);
    expect(cancels).toBe(0);
  });

  it("以往对话每页 20 条，显示标题、时间与电脑，点击后继续原线程", async () => {
    threads = Array.from({ length: 41 }, (_, index) => ({
      thread: {
        ...makeThread(`thread_${String(index + 1).padStart(32, "0")}`),
        title: `以往问题 ${index}`,
        context: {
          node_id: local.node_id,
          service_key: null,
          service_name: null,
        },
      },
      messages: [],
      context: null,
    }));
    renderMap();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "对话" }));
    await user.click(screen.getByRole("tab", { name: "以往对话" }));
    const history = screen.getByRole("tabpanel", { name: "以往对话" });
    await waitFor(() =>
      expect(within(history).getAllByRole("listitem")).toHaveLength(20),
    );
    expect(within(history).getAllByText(/这台电脑/)).toHaveLength(20);
    expect(within(history).getAllByText(/2026/)).toHaveLength(20);
    await user.click(screen.getByRole("button", { name: "下一页对话" }));
    expect(within(history).getAllByRole("listitem")).toHaveLength(20);
    await user.click(screen.getByRole("button", { name: "下一页对话" }));
    expect(within(history).getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText("第 3 / 3 页")).toBeVisible();
    await user.click(screen.getByRole("button", { name: /^以往问题 40/ }));
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "问题" })).toBeEnabled(),
    );
    await user.type(screen.getByRole("textbox", { name: "问题" }), "继续问");
    await user.click(screen.getByRole("button", { name: "发送问题" }));
    await source();
    expect(threads).toHaveLength(41);
    expect(threads[40]?.messages[0]?.content).toBe("继续问");
  });

  it("新对话清空问题与对象，已选的旧线程上下文可以恢复", async () => {
    const thread: ThreadSummary = {
      ...makeThread(),
      title: "原来的问题",
      context: {
        node_id: local.node_id,
        service_key: "python:app.py",
        service_name: "WireGuard Panel",
      },
    };
    threads = [{ thread, messages: [], context: thread.context }];
    renderMap(`/app/map?thread=${thread.thread_id}`);
    const user = userEvent.setup();
    expect(
      await screen.findByText("关于：这台电脑 · WireGuard Panel（Python）"),
    ).toBeVisible();
    await user.type(screen.getByRole("textbox", { name: "问题" }), "草稿");
    await user.click(screen.getByRole("button", { name: "新对话" }));
    expect(screen.getByRole("textbox", { name: "问题" })).toHaveValue("");
    expect(screen.queryByText(/关于：/)).toBeNull();
    expect(posts).toHaveLength(0);
  });

  it("只读预览允许看历史，所有提问入口不可发送", async () => {
    const meta = document.createElement("meta");
    meta.name = "tunnelminion-read-only-preview";
    meta.content = "true";
    document.head.append(meta);
    try {
      renderMap();
      const user = userEvent.setup();
      expect(
        screen.getByRole("textbox", { name: "想问点什么？" }),
      ).toBeDisabled();
      await user.click(
        await screen.findByRole("button", { name: /这台电脑，在线，1 个服务/ }),
      );
      expect(
        screen.getByRole("button", { name: "问问 WireGuard Panel" }),
      ).toBeDisabled();
      expect(
        screen.getByRole("button", { name: "问问 这台电脑 的 Agent" }),
      ).toBeDisabled();
      await user.click(screen.getByRole("button", { name: "对话" }));
      expect(screen.getByRole("textbox", { name: "问题" })).toBeDisabled();
      await user.click(screen.getByRole("tab", { name: "以往对话" }));
      expect(await screen.findByText("还没有以往对话。")).toBeVisible();
      expect(posts).toHaveLength(0);
    } finally {
      meta.remove();
    }
  });
});
