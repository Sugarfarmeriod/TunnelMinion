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
  expect,
  it,
  vi,
} from "vitest";

import { FakeEventSource, makeRun, makeThread } from "../chat/testFixtures";
import { makeRepair } from "../repairs/testFixtures";
import { ServiceMapPage } from "./ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makePeer,
  makePeerServices,
} from "./testFixtures";
import { mapLayout, relativeTime } from "./topology";

const server = setupServer();
let client: QueryClient;
let questions: {
  question: string;
  about: { node_id: string; service_key: string | null };
}[];
let peersRead = vi.fn<() => Response>();
let servicesRead = vi.fn<() => Response>();

function renderMap(
  peers = [makePeer()],
  view = makePeerServices(peers[0]),
  repairs: ReturnType<typeof makeRepair>[] = [],
) {
  peersRead = vi.fn(() => HttpResponse.json({ peers }));
  servicesRead = vi.fn(() => HttpResponse.json(view));
  const thread = makeThread();
  server.use(
    http.get("/api/peers", peersRead),
    http.get("/api/peers/:id/services", servicesRead),
    http.get("/api/services/local", () =>
      HttpResponse.json(makeLocalServices()),
    ),
    http.get("/api/ui/overview", () => HttpResponse.json(makeMapOverview())),
    http.get("/api/repairs", () => HttpResponse.json({ repairs })),
    http.get("/api/threads", () => HttpResponse.json([])),
    http.post("/api/threads", () => HttpResponse.json(thread)),
    http.get("/api/ui/threads/:id", () =>
      HttpResponse.json({ thread, messages: [] }),
    ),
    http.get("/api/runs/:id", () => HttpResponse.json(makeRun())),
    http.post("/api/threads/:id/runs", async ({ request }) => {
      questions.push((await request.json()) as (typeof questions)[number]);
      return HttpResponse.json(makeRun());
    }),
  );
  client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ServiceMapPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  questions = [];
  vi.stubGlobal("EventSource", FakeEventSource);
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
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());

it.each([0, 1, 3, 8])("%i 个对端只与中心电脑相连", async (count) => {
  const peers = Array.from({ length: count }, (_, index) =>
    makePeer(index + 1, { reachable: index !== 2 }),
  );
  const { container } = renderMap(peers);
  await screen.findByText(
    `${1 + peers.filter((peer) => peer.reachable).length} 台在线`,
    { exact: false },
  );
  await waitFor(() =>
    expect(container.querySelectorAll(".map-node")).toHaveLength(count + 1),
  );
  const links = container.querySelectorAll(".map-link");
  expect(links).toHaveLength(count);
  links.forEach((link, index) => {
    expect(link).toHaveAttribute("data-from", makeLocalServices().node_id);
    expect(link).toHaveAttribute("data-to", peers[index]!.node_id);
    expect(link.classList.contains("is-unreachable")).toBe(index === 2);
  });
  const layout = mapLayout(count, false);
  expect(layout.local.x).toBe(50);
  for (const narrow of [false, true]) {
    const points = mapLayout(count, narrow);
    expect(
      new Set(points.peers.map((point) => `${point.x},${point.y}`)).size,
    ).toBe(count);
    expect(
      points.peers.every((point) => point.y > 0 && point.y < points.height),
    ).toBe(true);
  }
});

async function openPeer(peer = makePeer()) {
  fireEvent.click(
    await screen.findByRole("button", {
      name: new RegExp(`^${peer.display_name}，`),
    }),
  );
  return screen.findByRole("dialog", { name: `${peer.display_name}上的服务` });
}

it("远端清单使用对端地址、报来时间，不显示标记按钮；同 key 不混用本机名称", async () => {
  renderMap();
  const dialog = await openPeer();
  await within(dialog).findByText("远端相册");
  expect(
    within(dialog).getByRole("link", { name: "打开 远端相册" }),
  ).toHaveAttribute("href", "http://192.0.2.42:8080");
  expect(within(dialog).getByText(/清单由 测试电脑 1 报来 ·/)).toBeVisible();
  expect(
    within(dialog).queryByRole("button", {
      name: /不再显示|是我的服务|隐藏|恢复/,
    }),
  ).toBeNull();
  fireEvent.click(
    within(dialog).getByRole("button", { name: "问问 远端相册" }),
  );
  expect(
    await screen.findByText("关于：测试电脑 1 · 远端相册（Python）"),
  ).toBeVisible();
  expect(questions).toEqual([]);
  const user = userEvent.setup();
  await user.type(
    screen.getByRole("textbox", { name: "问题" }),
    "相册怎么用？",
  );
  await user.click(screen.getByRole("button", { name: "发送问题" }));
  await waitFor(() => expect(questions).toHaveLength(1));
  expect(questions[0]!.about).toEqual({
    node_id: makePeer().node_id,
    service_key: "python:app.py",
  });
});

it.each(["stopped", "unopenable"])("远端 %s 服务直接发问", async (state) => {
  const view = makePeerServices();
  if (state === "stopped") view.services[0]!.state = "stopped";
  else view.services[0]!.ports[0]!.has_web_page = false;
  renderMap([makePeer()], view);
  const dialog = await openPeer();
  fireEvent.click(
    await within(dialog).findByRole("button", { name: "问问 远端相册" }),
  );
  await waitFor(() => expect(questions).toHaveLength(1));
  expect(questions[0]).toMatchObject({
    question: "远端相册怎么打不开？",
    about: { node_id: makePeer().node_id, service_key: "python:app.py" },
  });
});

it("远端问题草稿在关闭抽屉并选择本机后仍保留服务名称", async () => {
  renderMap();
  const dialog = await openPeer();
  fireEvent.click(
    await within(dialog).findByRole("button", { name: "问问 远端相册" }),
  );
  await screen.findByText("关于：测试电脑 1 · 远端相册（Python）");
  fireEvent.click(screen.getByRole("button", { name: "关闭对话" }));
  fireEvent.click(
    screen.getByRole("button", { name: "这台电脑，在线，1 个服务" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "对话" }));
  expect(
    screen.getByText("关于：测试电脑 1 · 远端相册（Python）"),
  ).toBeVisible();
});

it("电脑入口只预填远端电脑，发送时只有节点身份", async () => {
  renderMap();
  const dialog = await openPeer();
  fireEvent.click(
    within(dialog).getByRole("button", { name: "问问 测试电脑 1 的 Agent" }),
  );
  expect(await screen.findByText("关于：测试电脑 1")).toBeVisible();
  expect(questions).toEqual([]);
  const user = userEvent.setup();
  await user.type(
    screen.getByRole("textbox", { name: "问题" }),
    "电脑怎么样？",
  );
  await user.click(screen.getByRole("button", { name: "发送问题" }));
  await waitFor(() => expect(questions).toHaveLength(1));
  expect(questions[0]!.about).toEqual({
    node_id: makePeer().node_id,
    service_key: null,
  });
});

it.each([
  [{ reachable: false }, /离线，上次在线/, false],
  [{ reachable: null }, /尚未确认能否连上/, false],
  [{ services_visible: false }, /这台电脑不分享服务清单/, true],
  [
    { source: "coordinator", services_visible: false, service_count: 4 },
    /只能看到数量：4 个服务/,
    true,
  ],
] as const)("远端边界 %j 不读取清单", async (overrides, message, canAsk) => {
  const peer = makePeer(1, overrides);
  const { container } = renderMap([peer]);
  const dialog = await openPeer(peer);
  expect(within(dialog).getByText(message)).toBeVisible();
  expect(within(dialog).queryByText("远端相册")).toBeNull();
  expect(within(dialog).queryByRole("button", { name: /问问/ }) !== null).toBe(
    canAsk,
  );
  expect(servicesRead).not.toHaveBeenCalled();
  expect(container.querySelector(".map-node.is-offline") !== null).toBe(
    peer.reachable !== true,
  );
});

it("远端清单保留分页和左右键", async () => {
  const view = makePeerServices();
  view.services = Array.from({ length: 14 }, (_, index) => ({
    ...view.services[0]!,
    key: `service:${index}`,
    name: `服务 ${index}`,
  }));
  renderMap([makePeer()], view);
  const dialog = await openPeer();
  const pager = await within(dialog).findByRole("navigation", {
    name: "服务分页",
  });
  expect(pager).toHaveTextContent(/第 1 \//);
  fireEvent.keyDown(dialog, { key: "ArrowRight" });
  expect(pager).toHaveTextContent(/第 2 \//);
  fireEvent.keyDown(dialog, { key: "ArrowLeft" });
  expect(pager).toHaveTextContent(/第 1 \//);
});

it("每六十秒刷新电脑和当前远端清单", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  renderMap();
  const dialog = await openPeer();
  await within(dialog).findByText("远端相册");
  await act(async () => {
    await vi.advanceTimersByTimeAsync(59_000);
  });
  expect(peersRead).toHaveBeenCalledTimes(1);
  expect(servicesRead).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_000);
  });
  await waitFor(() => expect(peersRead).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(servicesRead).toHaveBeenCalledTimes(2));
});

it("本机修复的感叹号只挂在本机，远端面板没有修复按钮", async () => {
  renderMap([makePeer()], makePeerServices(), [makeRepair()]);
  const bang = await screen.findByRole("button", {
    name: "这台电脑有 1 个待批准的修复",
  });
  expect(bang.parentElement?.querySelector(".map-node-name")).toHaveTextContent(
    "这台电脑",
  );
  const dialog = await openPeer();
  expect(
    within(dialog).queryByRole("button", { name: "看看怎么修" }),
  ).toBeNull();
});

it("相对时间使用分钟、小时、天和未知时间", () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-27T08:00:00Z"));
  expect(relativeTime(null)).toBe("时间未知");
  expect(relativeTime("2026-10-27T08:00:00Z")).toBe("刚刚");
  expect(relativeTime("2026-10-27T07:58:00Z")).toBe("2 分钟前");
  expect(relativeTime("2026-10-27T06:00:00Z")).toBe("2 小时前");
  expect(relativeTime("2026-10-24T08:00:00Z")).toBe("3 天前");
});
