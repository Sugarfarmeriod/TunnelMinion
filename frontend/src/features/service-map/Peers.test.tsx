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

import {
  FakeEventSource,
  makeEvent,
  makeRun,
  makeThread,
} from "../chat/testFixtures";
import { makeRepair, makeRemoteRepair } from "../repairs/testFixtures";
import type { DelegationPhase } from "../chat/contracts";
import { RemoteRepairDialog } from "../repairs/RemoteRepairDialog";
import { ServiceMapPage } from "./ServiceMapPage";
import {
  makeLocalServices,
  makeMapOverview,
  makePeer,
  makePeerServices,
} from "./testFixtures";
import { mapLayout, relativeTime } from "./topology";

const server = setupServer(
  http.get("/api/peers/:node/repairs/:id", ({ params }) =>
    HttpResponse.json({
      node_id: params.node,
      repair_id: params.id,
      access: "not_allowed",
      repair: null,
    }),
  ),
);
let client: QueryClient;
let questions: {
  question: string;
  about: { node_id: string; service_key: string | null };
}[];
let peersRead = vi.fn<() => Response>();
let servicesRead = vi.fn<() => Response>();

// 本机也有同名服务身份的巡检记录：别的电脑的服务框不能借用它显示开关或"挂了"。
const patrolWithLocalScript = {
  checked_at: null,
  investigations_left_today: 12,
  services: [
    {
      key: "python:app.py",
      name: "本机脚本",
      status: "down",
      reason: "script_exited",
      reason_text: "脚本已退出",
      down_since: null,
      confirmed_at: null,
      thread_id: null,
      repair_id: null,
      auto_repair: {
        available: true,
        kind: "relaunch_python",
        enabled: false,
        enabled_on: null,
        paused: false,
        last_attempt_at: null,
        last_result: null,
      },
    },
  ],
};

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
    http.get("/api/patrol", () => HttpResponse.json(patrolWithLocalScript)),
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
  FakeEventSource.reset();
  Object.defineProperty(window, "innerWidth", {
    value: 1440,
    writable: true,
    configurable: true,
  });
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
      name: /不再显示|是我的服务|隐藏|恢复|有意停的|巡检记录/,
    }),
  ).toBeNull();
  expect(within(dialog).queryByText("挂了可以自动修")).toBeNull();
  expect(within(dialog).queryByText(/挂了 ·/)).toBeNull();
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

it("对方巡检报来挂了：标红原因和确认时间，写明对方会自己修，没有本机才有的按钮", async () => {
  const view = makePeerServices();
  view.services[0] = {
    ...view.services[0]!,
    state: "stopped",
    patrol: {
      status: "down",
      reason: "script_exited",
      reason_text: "脚本已退出",
      confirmed_at: new Date(Date.now() - 2 * 60_000).toISOString(),
      auto_repair: true,
    },
  };
  renderMap([makePeer()], view);
  const dialog = await openPeer();
  expect(await within(dialog).findByText("挂了 · 脚本已退出")).toBeVisible();
  expect(
    within(dialog).getByText(
      "测试电脑 1的巡检 2 分钟前确认 · 测试电脑 1会自己修",
    ),
  ).toBeVisible();
  expect(
    within(dialog).queryByRole("button", { name: /有意停的|巡检记录/ }),
  ).toBeNull();
  expect(within(dialog).queryByRole("checkbox")).toBeNull();
  fireEvent.click(
    within(dialog).getByRole("button", { name: "问问 远端相册" }),
  );
  await waitFor(() => expect(questions).toHaveLength(1));
  expect(questions[0]!.question).toBe("远端相册怎么打不开？");
});

it("对方报来的状态不是 down 时不标红", async () => {
  const view = makePeerServices();
  view.services[0] = {
    ...view.services[0]!,
    patrol: {
      status: "recovering",
      reason: null,
      reason_text: null,
      confirmed_at: null,
      auto_repair: false,
    },
  };
  renderMap([makePeer()], view);
  const dialog = await openPeer();
  expect(await within(dialog).findByText("正常")).toBeVisible();
  expect(within(dialog).queryByText(/挂了 ·/)).toBeNull();
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
  [{ reachable: false, auth_rejected: true }, /对方不认这台电脑/, false],
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

it("对端在线状态还没确定时每五秒再问，确定后恢复六十秒", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  const peer = makePeer(1, { reachable: null });
  renderMap([peer]);
  await screen.findByRole("img", {
    name: `这台电脑到${peer.display_name}：连不上`,
  });
  peersRead.mockImplementation(() =>
    HttpResponse.json({ peers: [{ ...peer, reachable: true }] }),
  );
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5_000);
  });
  await waitFor(() => expect(peersRead).toHaveBeenCalledTimes(2));
  expect(
    await screen.findByRole("img", {
      name: `这台电脑到${peer.display_name}：能连上`,
    }),
  ).toBeInTheDocument();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30_000);
  });
  expect(peersRead).toHaveBeenCalledTimes(2);
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

async function startDelegating() {
  fireEvent.change(screen.getByRole("textbox", { name: "想问点什么？" }), {
    target: { value: "看看远端相册" },
  });
  fireEvent.click(screen.getByRole("button", { name: "问问 Agent" }));
  await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
  const stream = FakeEventSource.instances[0]!;
  act(() => stream.open());
  let sequence = 0;
  return (phase: DelegationPhase, peer = makePeer(), id = "1") => {
    act(() =>
      stream.emit(
        "delegation",
        makeEvent(++sequence, "delegation", {
          delegation_id: `delegation_${id.repeat(32)}`,
          peer_node_id: peer.node_id,
          phase,
        }),
      ),
    );
  };
}

it("委派包发出、气泡调查、回包结束清除；抽屉关闭后继续更新", async () => {
  const { container } = renderMap();
  await screen.findByText("测试电脑 1");
  const emit = await startDelegating();
  emit("submitted");
  await screen.findByText("交给 测试电脑 1 · 已交给");
  expect(
    container.querySelector('.map-packet[data-phase="submitted"]'),
  ).not.toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "关闭对话" }));
  emit("investigating");
  const status = await screen.findByText("正在查……");
  expect(status).toHaveAttribute("aria-live", "polite");
  expect(container.querySelector(".map-thought")).not.toBeNull();
  expect(container.querySelector(".map-packet")).toBeNull();
  emit("answered");
  await screen.findByText("已交回", { exact: true });
  const packet = container.querySelector(".map-packet.is-returning")!;
  expect(packet).not.toBeNull();
  expect(container.querySelector(".map-thought")).not.toBeNull();
  fireEvent(packet, new Event("webkitAnimationEnd", { bubbles: true }));
  expect(container.querySelector(".map-thought")).toBeNull();
  expect(container.querySelector(".map-packet")).toBeNull();
});

it.each(["failed", "cancelled"] as const)(
  "%s 清除气泡且不发回包",
  async (phase) => {
    const { container } = renderMap();
    await screen.findByText("测试电脑 1");
    const emit = await startDelegating();
    emit("investigating");
    await waitFor(() =>
      expect(container.querySelector(".map-thought")).not.toBeNull(),
    );
    emit(phase);
    await waitFor(() =>
      expect(container.querySelector(".map-thought")).toBeNull(),
    );
    expect(container.querySelector(".map-packet")).toBeNull();
    expect(
      screen.getByText(phase === "failed" ? "没查成" : "已取消", {
        exact: true,
      }),
    ).toBeVisible();
  },
);

it("离线、未确认和未知对端不画委派", async () => {
  const offline = makePeer(1, { reachable: false });
  const unknown = makePeer(2, { reachable: null });
  const { container } = renderMap([offline, unknown]);
  await screen.findByText(offline.display_name);
  const emit = await startDelegating();
  for (const phase of ["submitted", "investigating", "answered"] as const) {
    emit(phase, offline);
    emit(phase, unknown, "2");
    emit(phase, makePeer(3), "3");
    await waitFor(() =>
      expect(container.querySelector(".map-packet, .map-thought")).toBeNull(),
    );
  }
  expect(screen.queryByText("正在查……")).toBeNull();
});

it("多个委派各自结束，不清除其他调查中的气泡", async () => {
  const { container } = renderMap([makePeer(), makePeer(2)]);
  await screen.findByText("测试电脑 2");
  const emit = await startDelegating();
  emit("investigating");
  emit("submitted", makePeer(2), "2");
  emit("investigating", makePeer(), "3");
  await waitFor(() =>
    expect(container.querySelectorAll(".map-thought")).toHaveLength(1),
  );
  emit("failed");
  expect(container.querySelectorAll(".map-thought")).toHaveLength(1);
  expect(container.querySelectorAll(".map-node-position")).toHaveLength(3);
  expect(container.querySelectorAll(".map-packet")).toHaveLength(1);
});

it("减少动画时显示静态包和状态", async () => {
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({ matches: true })),
  );
  const { container } = renderMap();
  await screen.findByText("测试电脑 1");
  const emit = await startDelegating();
  emit("submitted");
  await waitFor(() =>
    expect(container.querySelector(".map-packet")).toHaveStyle({
      animation: "none",
    }),
  );
  expect(screen.getByText("已交给", { exact: true })).toBeVisible();
  emit("investigating");
  await screen.findByText("正在查……");
  emit("answered");
  await waitFor(() =>
    expect(container.querySelector(".map-packet.is-returning")).toHaveStyle({
      animation: "none",
    }),
  );
  expect(container.querySelector(".map-thought")).toBeNull();
});

it.each([760, 320])("%ipx 列表只在对端显示委派文字", async (width) => {
  window.innerWidth = width;
  const { container } = renderMap();
  await screen.findByText("测试电脑 1");
  const emit = await startDelegating();
  for (const phase of ["submitted", "investigating", "answered"] as const) {
    emit(phase);
    await waitFor(() =>
      expect(container.querySelector(".map-packet, .map-thought")).toBeNull(),
    );
  }
  expect(screen.getByText("已交回", { exact: true })).toBeVisible();
});

it("远端感叹号和服务框都打开只读批准框，键盘锁焦点且 Esc 返回", async () => {
  const repair = makeRemoteRepair();
  const peer = makePeer(1, { pending_repairs: [repair] });
  renderMap([peer]);
  const bang = await screen.findByRole("button", {
    name: "测试电脑 1有 1 个待批准的修复",
  });
  expect(screen.getByText("! 有 1 件事要在 测试电脑 1 上批准")).toBeVisible();
  const user = userEvent.setup();
  bang.focus();
  await user.keyboard("{Enter}");
  const dialog = screen.getByRole("dialog", { name: "要修好“远端相册”吗？" });
  expect(
    await within(dialog).findByText("请到 测试电脑 1 的地图上点感叹号批准"),
  ).toBeVisible();
  expect(within(dialog).getByText("重启远端相册")).toBeVisible();
  expect(
    within(dialog).getByText(
      /10 分钟内有效 · 还剩 8:|10 分钟内有效 · 还剩 9:00/,
    ),
  ).toBeVisible();
  expect(
    within(dialog).queryByRole("button", { name: /批准并修复|先不用/ }),
  ).toBeNull();
  expect(dialog.querySelector("details")).not.toHaveAttribute("open");
  await user.click(within(dialog).getByText("高级"));
  expect(dialog.querySelector("pre")?.textContent).toBe(repair.how_to_approve);
  expect(within(dialog).getByText(/命令行后备/)).toBeVisible();
  within(dialog).getByRole("button", { name: "知道了" }).focus();
  await user.tab();
  expect(
    within(dialog).getByRole("button", { name: "关闭修复" }),
  ).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(bang).toHaveFocus();
  const panel = await openPeer(peer);
  expect(within(panel).getByText("需要处理的事")).toBeVisible();
  await user.click(within(panel).getByRole("button", { name: "看看怎么修" }));
  expect(
    await screen.findByText("请到 测试电脑 1 的地图上点感叹号批准"),
  ).toBeVisible();
  await user.click(screen.getByRole("button", { name: "关闭修复" }));
  expect(
    screen.queryByRole("dialog", { name: "要修好“远端相册”吗？" }),
  ).toBeNull();
});

it("远端倒计时按秒更新，过期仍可关闭，地图不再显示感叹号", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] });
  const repair = makeRemoteRepair({
    expires_at: new Date(Date.now() + 2_000).toISOString(),
  });
  renderMap([makePeer(1, { pending_repairs: [repair] })]);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "测试电脑 1有 1 个待批准的修复",
    }),
  );
  expect(await screen.findByText("10 分钟内有效 · 还剩 0:02")).toBeVisible();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_000);
  });
  expect(screen.getByText("10 分钟内有效 · 还剩 0:01")).toBeVisible();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_000);
  });
  expect(screen.getByText("10 分钟内有效 · 已过期")).toBeVisible();
  expect(
    screen.queryByRole("button", { name: /有 1 个待批准的修复/ }),
  ).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "知道了" }));
  expect(
    screen.queryByRole("dialog", { name: "要修好“远端相册”吗？" }),
  ).toBeNull();
});

it("已过期或终态摘要不显示远端感叹号，已打开的终态修复标为过期", async () => {
  renderMap([
    makePeer(1, {
      pending_repairs: [
        makeRemoteRepair({ status: "succeeded" }),
        makeRemoteRepair({
          expires_at: new Date(Date.now() - 1).toISOString(),
        }),
      ],
    }),
  ]);
  await screen.findByText("测试电脑 1");
  expect(
    screen.queryByRole("button", { name: /有 .* 个待批准的修复/ }),
  ).toBeNull();
  cleanup();
  render(
    <QueryClientProvider client={client}>
      <RemoteRepairDialog
        nodeId={makePeer().node_id}
        repair={makeRemoteRepair({ status: "authorization_expired" })}
        name="测试电脑"
        onClose={vi.fn()}
      />
    </QueryClientProvider>,
  );
  expect(await screen.findByText("10 分钟内有效 · 已过期")).toBeVisible();
});
