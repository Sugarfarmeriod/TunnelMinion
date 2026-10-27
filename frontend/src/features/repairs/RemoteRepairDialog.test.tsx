import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  expect,
  it,
  vi,
} from "vitest";

import { peersQueryKey } from "../service-map/api";
import { makePeer } from "../service-map/testFixtures";
import { peerRepairAccessSchema, type PeerRepair } from "./api";
import { RemoteRepairDialog } from "./RemoteRepairDialog";
import { makePeerRepair, makeRemoteRepair } from "./testFixtures";

const server = setupServer();
let client: QueryClient;
let repair: PeerRepair;
let access: "allowed" | "not_allowed" | "not_found" | "unreachable";
let reads: number;
let posts: string[];
let onClose = vi.fn<() => void>();

function response() {
  return {
    node_id: repair.node_id,
    repair_id: repair.repair_id,
    access,
    repair: access === "allowed" ? repair : null,
  };
}

function open() {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  client.setQueryData(peersQueryKey, {
    peers: [
      makePeer(1, {
        node_id: repair.node_id,
        pending_repairs: [makeRemoteRepair()],
      }),
    ],
  });
  onClose = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <RemoteRepairDialog
        nodeId={repair.node_id}
        repair={makeRemoteRepair()}
        name="书房电脑"
        onClose={onClose}
      />
    </QueryClientProvider>,
  );
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  repair = makePeerRepair();
  access = "allowed";
  reads = 0;
  posts = [];
  server.use(
    http.get("/api/peers/:node/repairs/:id", () => {
      reads++;
      return HttpResponse.json(response());
    }),
    http.post("/api/peers/:node/repairs/:id/:action", ({ request, params }) => {
      expect(request.headers.get("x-tunnelminion-request")).toBe("same-origin");
      posts.push(String(params.action));
      repair = {
        ...repair,
        status: params.action === "approve" ? "authorized" : "rejected",
        approval_expires_at: null,
        approved_by_peer: params.action === "approve" ? true : null,
      };
      return HttpResponse.json(response(), {
        status: params.action === "approve" ? 202 : 200,
      });
    }),
  );
});
afterEach(() => {
  cleanup();
  client?.clear();
  server.resetHandlers();
  vi.useRealTimers();
  document
    .querySelector('meta[name="tunnelminion-read-only-preview"]')
    ?.remove();
});
afterAll(() => server.close());

async function tick(milliseconds: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(milliseconds);
  });
}

it("打开时保留要做什么并询问权限", async () => {
  let release!: () => void;
  server.use(
    http.get("/api/peers/:node/repairs/:id", async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return HttpResponse.json(response());
    }),
  );
  open();
  expect(screen.getByText("重启远端相册")).toBeVisible();
  expect(screen.getByText("正在问 书房电脑 能不能在这里批准……")).toBeVisible();
  await waitFor(() => expect(release).toBeDefined());
  release();
  await screen.findByText("由 书房电脑 提出 · 书房电脑 允许这台电脑替它批准");
});

it.each([
  ["not_allowed", "请到 书房电脑 的地图上点感叹号批准"],
  ["not_found", "书房电脑 上已经没有这个修复了，可能已经处理或过期。"],
  [
    "unreachable",
    "现在连不上 书房电脑，没法在这里批准。可以稍后再试，或到 书房电脑 的地图上批准。",
  ],
] as const)("%s 只查一次，显示对应文案", async (state, text) => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  access = state;
  open();
  await screen.findByText(text);
  await tick(12_000);
  expect(reads).toBe(1);
  expect(screen.queryByRole("button", { name: "批准并修复" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "知道了" }));
  expect(onClose).toHaveBeenCalledOnce();
});

it("连不上时可以重新询问，读取失败也显示连不上", async () => {
  server.use(
    http.get("/api/peers/:node/repairs/:id", () => HttpResponse.error()),
  );
  open();
  await screen.findByText(/现在连不上 书房电脑/);
  server.use(
    http.get("/api/peers/:node/repairs/:id", () =>
      HttpResponse.json(response()),
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "再试一次" }));
  await screen.findByRole("button", { name: "批准并修复" });
});

it("获准后展示五件事、有效期和只有编号的高级信息", async () => {
  open();
  await screen.findByText(repair.reason);
  for (const text of [
    "要做什么",
    "为什么",
    "会有什么影响",
    "怎么确认修好",
    "没修好怎么办",
    "批准后由 书房电脑 动手修。动手前 书房电脑 会再核对一次，情况变了就不修。",
  ])
    expect(screen.getByText(text)).toBeVisible();
  expect(screen.getByText(/10 分钟内有效 · 还剩/)).toBeVisible();
  fireEvent.click(screen.getByText("高级"));
  expect(screen.getByText(`修复编号 ${repair.repair_id}`)).toBeVisible();
  expect(screen.queryByText(/docker|命令行后备/)).toBeNull();
});

it("已获准后读取失败也停止轮询，手动重试后才能继续批准", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  open();
  await screen.findByRole("button", { name: "批准并修复" });
  server.use(
    http.get("/api/peers/:node/repairs/:id", () => {
      reads++;
      return HttpResponse.error();
    }),
  );
  await tick(3_000);
  await screen.findByText(/现在连不上 书房电脑/);
  expect(screen.queryByRole("button", { name: "批准并修复" })).toBeNull();
  const stopped = reads;
  await tick(9_000);
  expect(reads).toBe(stopped);
  server.use(
    http.get("/api/peers/:node/repairs/:id", () =>
      HttpResponse.json(response()),
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "再试一次" }));
  expect(
    await screen.findByRole("button", { name: "批准并修复" }),
  ).toBeEnabled();
});

it.each(["succeeded", "rolled_back"])(
  "批准后每三秒轮询直到 %s，移除提示后仍保留对话框",
  async (status) => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    open();
    fireEvent.click(await screen.findByRole("button", { name: "批准并修复" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "关闭修复" })).toBeDisabled(),
    );
    await waitFor(() =>
      expect(
        client.getQueryData<{ peers: ReturnType<typeof makePeer>[] }>(
          peersQueryKey,
        )?.peers[0]?.pending_repairs,
      ).toEqual([]),
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
    expect(
      screen.getByLabelText("修复进度").querySelector('[aria-current="step"]'),
    ).toHaveTextContent("再核对一次");
    const initial = reads;
    repair = { ...repair, status: "executing" };
    await tick(2_999);
    expect(reads).toBe(initial);
    await tick(1);
    await waitFor(() => expect(reads).toBe(initial + 1));
    expect(
      screen.getByLabelText("修复进度").querySelector('[aria-current="step"]'),
    ).toHaveTextContent("正在执行");
    repair = { ...repair, status: "verifying" };
    await tick(3_000);
    await waitFor(() => expect(reads).toBe(initial + 2));
    expect(
      screen.getByLabelText("修复进度").querySelector('[aria-current="step"]'),
    ).toHaveTextContent("正在确认");
    repair = {
      ...repair,
      status,
      verification_passed: status === "succeeded",
      error_code: status === "succeeded" ? null : "verification_failed",
      error_message: status === "succeeded" ? null : "相册还是打不开",
    };
    await tick(3_000);
    await screen.findByText(status === "succeeded" ? "修好了" : "没修好");
    if (status === "rolled_back")
      expect(screen.getByText("相册还是打不开")).toBeVisible();
    const stopped = reads;
    await tick(9_000);
    expect(reads).toBe(stopped);
    expect(posts).toEqual(["approve"]);
    expect(dialog).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "知道了" }));
    expect(onClose).toHaveBeenCalledOnce();
  },
);

it("发决定时禁用按钮和 Esc，显示正在交给对方", async () => {
  let release!: () => void;
  server.use(
    http.post("/api/peers/:node/repairs/:id/:action", async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      repair = { ...repair, status: "rejected" };
      return HttpResponse.json(response());
    }),
  );
  open();
  fireEvent.click(await screen.findByRole("button", { name: "先不用" }));
  await screen.findByText("正在把批准交给 书房电脑……");
  for (const name of ["批准并修复", "先不用", "关闭修复"])
    expect(screen.getByRole("button", { name })).toBeDisabled();
  fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
  expect(onClose).not.toHaveBeenCalled();
  await waitFor(() => expect(release).toBeDefined());
  release();
  await screen.findByText("已取消");
});

it("先不用只拒绝一次并去掉提示", async () => {
  open();
  fireEvent.click(await screen.findByRole("button", { name: "先不用" }));
  await screen.findByText("已取消");
  expect(posts).toEqual(["reject"]);
  expect(
    client.getQueryData<{ peers: ReturnType<typeof makePeer>[] }>(peersQueryKey)
      ?.peers[0]?.pending_repairs,
  ).toEqual([]);
});

it("批准发送期间的旧轮询不能覆盖已经批准的进度", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  open();
  await screen.findByRole("button", { name: "批准并修复" });
  let releasePost!: () => void;
  let releasePoll!: () => void;
  server.use(
    http.post("/api/peers/:node/repairs/:id/:action", async () => {
      await new Promise<void>((resolve) => {
        releasePost = resolve;
      });
      repair = {
        ...repair,
        status: "authorized",
        approved_by_peer: true,
        approval_expires_at: null,
      };
      return HttpResponse.json(response(), { status: 202 });
    }),
    http.get("/api/peers/:node/repairs/:id", async () => {
      const stale = response();
      await new Promise<void>((resolve) => {
        releasePoll = resolve;
      });
      return HttpResponse.json(stale);
    }),
  );
  fireEvent.click(screen.getByRole("button", { name: "批准并修复" }));
  await waitFor(() => expect(releasePost).toBeDefined());
  await tick(3_000);
  await waitFor(() => expect(releasePoll).toBeDefined());
  releasePost();
  await screen.findByLabelText("修复进度");
  releasePoll();
  await act(async () => {});
  expect(screen.queryByRole("button", { name: "批准并修复" })).toBeNull();
  expect(screen.getByRole("button", { name: "关闭修复" })).toBeDisabled();
});

it.each([403, 409, 502])("批准时 %i 提示原因并重新读取", async (status) => {
  server.use(
    http.post("/api/peers/:node/repairs/:id/:action", () => {
      if (status === 403) access = "not_allowed";
      if (status === 409)
        repair = { ...repair, status: "authorized", approved_by_peer: false };
      return HttpResponse.json({ detail: "示例失败" }, { status });
    }),
  );
  open();
  fireEvent.click(await screen.findByRole("button", { name: "批准并修复" }));
  const text =
    status === 403
      ? "书房电脑 已经不允许这台电脑替它批准了，请到 书房电脑 的地图上批准。"
      : status === 409
        ? "这个修复已经不等批准了（可能已过期，或 书房电脑 本机已经处理）。"
        : "连不上 书房电脑，稍后再试";
  expect(await screen.findByRole("alert")).toHaveTextContent(text);
  await waitFor(() => expect(reads).toBe(2));
  if (status === 409)
    expect(
      await screen.findByText("书房电脑 本机已经批准，再核对一次"),
    ).toBeVisible();
});

it("只读预览下不能批准或拒绝", async () => {
  const meta = document.createElement("meta");
  meta.name = "tunnelminion-read-only-preview";
  meta.content = "true";
  document.head.append(meta);
  open();
  expect(
    await screen.findByRole("button", { name: "批准并修复" }),
  ).toBeDisabled();
  expect(screen.getByRole("button", { name: "先不用" })).toBeDisabled();
});

it("批准到期禁用按钮，终态不再轮询", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] });
  repair = {
    ...repair,
    approval_expires_at: new Date(Date.now() + 1_000).toISOString(),
  };
  open();
  await screen.findByRole("button", { name: "批准并修复" });
  await tick(1_000);
  expect(screen.getByText("10 分钟内有效 · 已过期")).toBeVisible();
  expect(screen.getByRole("button", { name: "批准并修复" })).toBeDisabled();
  repair = {
    ...repair,
    status: "authorization_expired",
    approval_expires_at: null,
  };
  await tick(2_000);
  await screen.findByText("已过期", { exact: true });
  const stopped = reads;
  await tick(9_000);
  expect(reads).toBe(stopped);
});

it("摘要允许未来字段和修法，不把未知字段交给界面", () => {
  const parsed = peerRepairAccessSchema.parse({
    ...response(),
    repair: {
      ...repair,
      kind: "future_kind",
      status: "future_status",
      future_field: "可忽略",
    },
  });
  expect(parsed.repair?.kind).toBe("future_kind");
  expect(parsed.repair).not.toHaveProperty("future_field");
});
