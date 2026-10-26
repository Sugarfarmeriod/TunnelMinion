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

import { localServicesQueryKey, type LocalServices } from "./api";
import { ComputerNode } from "./ComputerNode";
import { ServiceMapPage } from "./ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "./testFixtures";

const server = setupServer();
let client: QueryClient;

function renderMap(
  data = makeLocalServices(),
  platform: "windows" | "macos" = "windows",
  status = 200,
) {
  const reads = vi.fn(() => HttpResponse.json(data, { status }));
  server.use(
    http.get("/api/services/local", reads),
    http.get("/api/ui/overview", () =>
      HttpResponse.json(makeMapOverview(platform)),
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
  return reads;
}

async function openComputer(user = userEvent.setup()) {
  const node = await screen.findByRole("button", {
    name: /^这台电脑，在线，\d+ 个服务$/,
  });
  await user.click(node);
  return {
    user,
    node,
    dialog: screen.getByRole("dialog", { name: "这台电脑上的服务" }),
  };
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
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
  Object.defineProperty(window, "innerHeight", {
    value: 900,
    configurable: true,
    writable: true,
  });
});
afterEach(() => {
  cleanup();
  client?.clear();
  server.resetHandlers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());

describe("服务地图页面", () => {
  it("未观察完时每五秒请求，取得结果后停止轮询", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const data = { ...makeLocalServices([]), observed_at: null };
    const reads = renderMap(data);
    await screen.findByText("正在查看这台电脑上的程序……");
    await waitFor(() =>
      expect(client.getQueryData(localServicesQueryKey)).toEqual(data),
    );
    server.use(
      http.get("/api/services/local", () => {
        reads();
        return HttpResponse.json(makeLocalServices());
      }),
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    await screen.findByRole("button", { name: "这台电脑，在线，1 个服务" });
    expect(reads).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("button", { name: "这台电脑，在线，1 个服务" }),
    ).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(reads).toHaveBeenCalledTimes(2);
  });

  it("三个档位保持接口顺序，隐藏项默认折叠，显示类型、端口和正确按钮", async () => {
    renderMap(
      makeLocalServices([
        makeService({ key: "program:z", name: "Z 服务", kind: "program" }),
        makeService({
          key: "docker:a",
          name: "A 服务",
          kind: "docker",
          endpoints: [
            {
              protocol: "tcp",
              address: "127.0.0.1",
              port: 444,
              has_web_page: false,
            },
          ],
        }),
        makeService({
          key: "python:review",
          name: "待确认程序",
          tier: "review",
        }),
        makeService({
          key: "program:hidden",
          name: "已隐藏程序",
          tier: "hidden",
          mark: "hidden",
        }),
      ]),
    );
    const { user, dialog } = await openComputer();
    expect(
      within(dialog)
        .getAllByRole("listitem")
        .map((item) => item.querySelector(".map-service-name")?.textContent),
    ).toEqual(["Z 服务", "A 服务", "待确认程序"]);
    expect(within(dialog).getByText("Docker · 444")).toBeVisible();
    expect(within(dialog).getByText("Python · 8787")).toBeVisible();
    expect(
      within(dialog).getByRole("link", { name: "打开 Z 服务" }),
    ).toHaveAttribute("href", "http://localhost:8787");
    expect(
      within(dialog).queryByRole("link", { name: "打开 A 服务" }),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", { name: "是我的服务 待确认程序" }),
    ).toBeVisible();
    expect(within(dialog).queryByText("已隐藏程序")).not.toBeInTheDocument();
    await user.click(
      within(dialog).getByRole("button", { name: "已隐藏的 1 个" }),
    );
    expect(
      within(dialog).getByRole("button", { name: "恢复 已隐藏程序" }),
    ).toBeVisible();
    expect(within(dialog).queryByRole("searchbox")).not.toBeInTheDocument();
  });

  it("超过八项时搜索名字、类型、端口，并能用按钮和左右键翻页", async () => {
    const services = Array.from({ length: 14 }, (_, index) =>
      makeService({
        key: `python:${index}`,
        name: `服务 ${index}`,
        kind: index === 13 ? "docker" : "python",
        endpoints: [
          {
            protocol: "tcp",
            address: "::",
            port: 8000 + index,
            has_web_page: true,
          },
        ],
      }),
    );
    renderMap(makeLocalServices(services));
    const { user, dialog } = await openComputer();
    const list = within(dialog).getByRole("list");
    const size = within(list).getAllByRole("listitem").length;
    expect(size).toBeGreaterThanOrEqual(3);
    expect(size).toBeLessThanOrEqual(6);
    expect(dialog).toHaveClass("is-compact");
    await user.click(within(dialog).getByRole("button", { name: "下一页" }));
    expect(within(dialog).getByText(new RegExp(`第 2 /`))).toBeVisible();
    await user.keyboard("{ArrowLeft}");
    expect(
      within(dialog).getByRole("button", { name: "上一页" }),
    ).toBeDisabled();
    await user.keyboard("{ArrowRight}");
    expect(
      within(dialog).getByRole("button", { name: "上一页" }),
    ).toBeEnabled();
    const search = within(dialog).getByRole("searchbox", { name: "搜索服务" });
    for (const query of ["服务 13", "Docker", "8013"]) {
      await user.clear(search);
      await user.type(search, query);
      expect(within(list).getAllByRole("listitem")).toHaveLength(1);
      expect(within(list).getByText("服务 13")).toBeVisible();
      expect(within(dialog).getByText("第 1 / 1 页")).toBeVisible();
    }
    await user.keyboard("{ArrowLeft}");
    expect(search).toHaveFocus();
    await user.clear(search);
    await user.type(search, "不存在");
    expect(within(dialog).getByText("没有找到匹配的服务。")).toBeVisible();
  });

  it("PUT 与 DELETE 编码服务 key，并直接使用返回清单，不追加 GET", async () => {
    const pending = makeService({
      key: "python:我的 app#?.py",
      name: "待确认程序",
      tier: "review",
    });
    const hidden = makeService({
      key: "program:old.exe",
      name: "隐藏程序",
      tier: "hidden",
      mark: "hidden",
    });
    const initial = makeLocalServices([pending, hidden]);
    const reads = renderMap(initial);
    const put = vi.fn();
    const remove = vi.fn();
    const promoted = makeLocalServices([
      makeService({
        ...pending,
        name: "已确认的新名字",
        tier: "show",
        mark: "mine",
      }),
      hidden,
    ]);
    server.use(
      http.put("/api/services/marks/:key", async ({ request, params }) => {
        put(
          request.url,
          params.key,
          await request.json(),
          request.headers.get("X-TunnelMinion-Request"),
        );
        return HttpResponse.json(promoted);
      }),
      http.delete("/api/services/marks/:key", ({ params }) => {
        remove(params.key);
        return HttpResponse.json(
          makeLocalServices([
            promoted.services[0]!,
            makeService({
              ...hidden,
              name: "已恢复的程序",
              tier: "review",
              mark: null,
            }),
          ]),
        );
      }),
    );
    const { user, dialog } = await openComputer();
    await user.click(
      within(dialog).getByRole("button", { name: "是我的服务 待确认程序" }),
    );
    expect(await within(dialog).findByText("已确认的新名字")).toBeVisible();
    expect(put).toHaveBeenCalledWith(
      expect.stringContaining(encodeURIComponent(pending.key)),
      pending.key,
      { mark: "mine" },
      "same-origin",
    );
    expect(within(dialog).queryByText("待确认程序")).not.toBeInTheDocument();
    await user.click(
      within(dialog).getByRole("button", { name: "已隐藏的 1 个" }),
    );
    await user.click(
      within(dialog).getByRole("button", { name: "恢复 隐藏程序" }),
    );
    expect(await within(dialog).findByText("已恢复的程序")).toBeVisible();
    expect(remove).toHaveBeenCalledWith(hidden.key);
    expect(reads).toHaveBeenCalledTimes(1);
    expect(
      (client.getQueryData(localServicesQueryKey) as LocalServices).services[1]!
        .mark,
    ).toBeNull();
  });

  it.each(["show", "review"] as const)(
    "%s 档位可隐藏，失败时保留服务并显示错误",
    async (tier) => {
      const data = makeLocalServices([makeService({ tier })]);
      renderMap(data);
      const put = vi.fn();
      server.use(
        http.put("/api/services/marks/:key", async ({ request }) => {
          put(await request.json());
          return HttpResponse.json(
            { detail: { code: "unavailable", message: "失败" } },
            { status: 500 },
          );
        }),
      );
      const { user, dialog } = await openComputer();
      const button = within(dialog).getByRole("button", {
        name: `${tier === "show" ? "不再显示" : "隐藏"} WireGuard Panel`,
      });
      await user.click(button);
      expect(await within(dialog).findByRole("alert")).toHaveTextContent(
        "标记没有保存",
      );
      expect(put).toHaveBeenCalledWith({ mark: "hidden" });
      expect(within(dialog).getByText("WireGuard Panel")).toBeVisible();
      server.use(
        http.put("/api/services/marks/:key", () =>
          HttpResponse.json(
            makeLocalServices([
              makeService({ tier: "hidden", mark: "hidden" }),
            ]),
          ),
        ),
      );
      await user.click(button);
      expect(
        await within(dialog).findByRole("button", { name: "已隐藏的 1 个" }),
      ).toBeVisible();
      expect(
        within(dialog).queryByText("WireGuard Panel"),
      ).not.toBeInTheDocument();
    },
  );

  it("Enter 打开时焦点进入，Esc、再次点击电脑和空白关闭后回到电脑", async () => {
    renderMap();
    const user = userEvent.setup();
    const node = await screen.findByRole("button", {
      name: "这台电脑，在线，1 个服务",
    });
    node.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("button", { name: "关闭服务框" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(node).toHaveFocus();
    await user.click(node);
    await user.click(node);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(node).toHaveFocus();
    await user.click(node);
    fireEvent.pointerDown(screen.getByLabelText("电脑拓扑图"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(node).toHaveFocus();
  });

  it("宽度 760 及以下使用下方面板，并随窗口变化切换", async () => {
    window.innerWidth = 760;
    renderMap(makeLocalServices(), "macos");
    const { dialog } = await openComputer();
    expect(dialog).toHaveClass("is-inline");
    expect(within(dialog).getByText("macOS")).toBeVisible();
    expect(
      document.querySelector("svg[data-platform='mini']"),
    ).toBeInTheDocument();
    act(() => {
      window.innerWidth = 761;
      fireEvent(window, new Event("resize"));
    });
    expect(dialog).toHaveClass("is-floating");
  });

  it.each([
    ["0.0.0.0", "http://localhost:8787"],
    ["::1", "http://localhost:8787"],
    ["127.0.0.2", "http://localhost:8787"],
    ["2001:db8::1", "http://[2001:db8::1]:8787"],
    ["192.0.2.1", "http://192.0.2.1:8787"],
  ])("打开按钮规范化 %s 并使用新标签页", async (address, expected) => {
    const service = makeService();
    service.endpoints[0]!.address = address;
    renderMap(makeLocalServices([service]));
    const { dialog } = await openComputer();
    const link = within(dialog).getByRole("link", {
      name: "打开 WireGuard Panel",
    });
    expect(link).toHaveAttribute("href", expected);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("读取失败提供重试，恢复后展示接口结果", async () => {
    renderMap(makeLocalServices(), "windows", 503);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("暂时无法查看"),
    );
    server.use(
      http.get("/api/services/local", () =>
        HttpResponse.json(makeLocalServices()),
      ),
    );
    await userEvent.click(screen.getByRole("button", { name: "重试" }));
    await screen.findByRole("button", { name: "这台电脑，在线，1 个服务" });
  });

  it("电脑组件支持离线状态，停止光标闪烁", () => {
    render(
      <ComputerNode
        name="离线电脑"
        platform="windows"
        online={false}
        serviceCount={2}
        selected={false}
        buttonRef={() => {}}
        onClick={() => {}}
      />,
    );
    expect(
      screen.getByRole("button", { name: "离线电脑，离线，2 个服务" }),
    ).toHaveClass("is-offline");
    expect(document.querySelector(".map-blink")).not.toBeInTheDocument();
  });
});
