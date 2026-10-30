import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
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
import { router } from "./router";
import {
  makeMapOverview,
  makeLocalServices,
} from "../features/service-map/testFixtures";
import { makeThread } from "../features/chat/testFixtures";

const server = setupServer();
let client: QueryClient;
let currentRouter: ReturnType<typeof createMemoryRouter>;
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
  server.use(
    http.get("/api/services/local", () =>
      HttpResponse.json(makeLocalServices()),
    ),
    http.get("/api/ui/overview", () => HttpResponse.json(makeMapOverview())),
    http.get("/api/threads", () => HttpResponse.json([makeThread()])),
    http.get("/api/ui/threads/:id", () =>
      HttpResponse.json({ thread: makeThread(), messages: [] }),
    ),
    http.get("/api/*", () => new HttpResponse(null, { status: 503 })),
  );
});
afterEach(() => {
  cleanup();
  currentRouter?.dispose();
  client?.clear();
  server.resetHandlers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());
function mount(entry: string) {
  currentRouter = createMemoryRouter(router.routes, {
    initialEntries: [entry],
  });
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={currentRouter} />
    </QueryClientProvider>,
  );
}
describe("地图产品外壳", () => {
  it.each(["/app", "/app/overview", "/app/chat"])(
    "%s 跳转到唯一主页面",
    async (entry) => {
      mount(entry);
      expect(
        await screen.findByRole("heading", { name: "我的服务网络" }),
      ).toBeVisible();
      expect(currentRouter.state.location.pathname).toBe("/app/map");
      expect(screen.queryByRole("link", { name: "工作台" })).toBeNull();
      expect(screen.getByText("只连接这台电脑上的 TunnelMinion")).toBeVisible();
      expect(
        screen
          .getByRole("navigation", { name: "主要导航" })
          .querySelectorAll("a"),
      ).toHaveLength(1);
    },
  );
  it.each(["overview", "chat"])(
    "旧 %s 链接保留 thread 并打开对应对话",
    async (path) => {
      const thread = makeThread();
      mount(`/app/${path}?thread=${thread.thread_id}`);
      expect(await screen.findByRole("dialog", { name: "对话" })).toBeVisible();
      expect(currentRouter.state.location.search).toBe(
        `?thread=${thread.thread_id}`,
      );
      await waitFor(() =>
        expect(screen.getByRole("textbox", { name: "问题" })).toBeEnabled(),
      );
    },
  );
  it.each([
    ["请求记录", "operations"],
    ["最近事件", "incidents"],
    ["记忆", "memories"],
    ["设置", "settings"],
  ])("更多里的%s能进入并回到地图", async (label, path) => {
    mount("/app/map");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "更多 ▾" }));
    const link = screen.getByRole("link", { name: label });
    expect(link).toHaveAttribute("href", `/app/${path}`);
    await user.click(link);
    expect(currentRouter.state.location.pathname).toBe(`/app/${path}`);
    await user.click(screen.getByRole("link", { name: "← 回到地图" }));
    expect(
      await screen.findByRole("heading", { name: "我的服务网络" }),
    ).toBeVisible();
  });
  it("更多菜单支持键盘选择和 Esc 回到按钮", async () => {
    mount("/app/map");
    const user = userEvent.setup();
    const button = await screen.findByRole("button", { name: "更多 ▾" });
    await user.click(button);
    await user.keyboard("{ArrowDown}");
    expect(screen.getByRole("link", { name: "请求记录" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("navigation", { name: "更多" })).toBeNull();
    expect(button).toHaveFocus();
  });
});
describe("钥匙串等授权", () => {
  const hint = "请在 Mac 屏幕上的钥匙串弹框点始终允许";
  const pending = () =>
    HttpResponse.json(
      { detail: { code: "keychain_approval_pending", message: hint } },
      { status: 503 },
    );
  it("地图读不到服务时直接显示去 Mac 上点允许，点完重新读取后提示消失", async () => {
    let approved = false;
    server.use(
      http.get("/api/services/local", () =>
        approved ? HttpResponse.json(makeLocalServices()) : pending(),
      ),
    );
    mount("/app/map");
    await waitFor(() =>
      expect(
        [...document.querySelectorAll(".map-status")].map((p) => p.textContent),
      ).toContain(`${hint} 重试`),
    );
    expect(document.querySelector(".keychain-notice")).toHaveTextContent(hint);
    expect(screen.queryByText(/暂时无法查看这台电脑上的服务/)).toBeNull();
    approved = true;
    const status = [...document.querySelectorAll(".map-status")].find((p) =>
      p.textContent?.startsWith(hint),
    ) as HTMLElement;
    await userEvent
      .setup()
      .click(within(status).getByRole("button", { name: "重试" }));
    await waitFor(() => expect(screen.queryByText(hint)).toBeNull());
  });
  it("人员页读不到身份时也显示同一句提示", async () => {
    server.use(http.get("/api/identity", pending));
    mount("/app/people");
    expect((await screen.findAllByText(hint)).length).toBeGreaterThan(0);
    expect(document.querySelector(".keychain-notice")).toHaveTextContent(hint);
  });
  it("其他失败不显示钥匙串提示", async () => {
    server.use(
      http.get(
        "/api/services/local",
        () => new HttpResponse(null, { status: 500 }),
      ),
    );
    mount("/app/map");
    expect(
      await screen.findByText(/暂时无法查看这台电脑上的服务/),
    ).toBeVisible();
    expect(document.querySelector(".keychain-notice")).toBeNull();
  });
});
