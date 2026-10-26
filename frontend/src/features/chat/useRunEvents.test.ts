import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
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
import { useRunEvents } from "./useRunEvents";
import {
  completedRun,
  FakeEventSource,
  makeEvent,
  makeRun,
  runId,
} from "./testFixtures";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  FakeEventSource.reset();
  vi.stubGlobal("EventSource", FakeEventSource);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  server.resetHandlers();
});
afterAll(() => server.close());

async function source(index: number) {
  await waitFor(() =>
    expect(FakeEventSource.instances.length).toBeGreaterThan(index),
  );
  return FakeEventSource.instances[index]!;
}

it("事件缺口先复读状态，再从最后确认序号续传；重复事件不重复显示", async () => {
  let final = makeRun();
  const reads = vi.fn(() => HttpResponse.json(final));
  const settled = vi.fn();
  server.use(http.get(`/api/runs/${runId}`, reads));
  const { result } = renderHook(() =>
    useRunEvents(makeRun(), { onRunSettled: settled }, { reconnectDelayMs: 1 }),
  );
  const first = await source(0);
  act(() => {
    first.open();
    first.emit("goal", makeEvent(1, "goal"));
    first.emit(
      "tool",
      makeEvent(2, "tool", {
        tool_name: "get_node_summary",
        tool_status: "success",
      }),
    );
    first.emit(
      "tool",
      makeEvent(2, "tool", {
        tool_name: "get_node_summary",
        tool_status: "success",
      }),
    );
    first.emit("tool", makeEvent(4, "tool"));
  });
  const next = await source(1);
  expect(first.closed).toBe(true);
  expect(reads).toHaveBeenCalledTimes(1);
  expect(next.url).toMatch(/\?after=2$/);
  expect(result.current.events).toHaveLength(2);
  final = completedRun("已经查完");
  act(() => {
    next.emit("tool", makeEvent(3, "tool"));
    next.emit(
      "finished",
      makeEvent(4, "finished", { stop_reason: "completed" }),
    );
  });
  await waitFor(() => expect(settled).toHaveBeenCalledTimes(1));
  expect(result.current.events.map((event) => event.sequence)).toEqual([
    1, 2, 3, 4,
  ]);
  expect(next.closed).toBe(true);
});

it("断线从 after 续上，卸载只关闭订阅，不发取消请求", async () => {
  server.use(
    http.get(`/api/runs/${runId}`, () => HttpResponse.json(makeRun())),
  );
  const { unmount } = renderHook(() =>
    useRunEvents(makeRun(), {}, { reconnectDelayMs: 1 }),
  );
  const first = await source(0);
  act(() => {
    first.emit("goal", makeEvent(1, "goal"));
    first.fail();
  });
  const next = await source(1);
  expect(next.url).toMatch(/\?after=1$/);
  unmount();
  expect(next.closed).toBe(true);
});

it("空闲超时只复读 run 并恢复订阅", async () => {
  const read = vi.fn(() => HttpResponse.json(makeRun()));
  server.use(http.get(`/api/runs/${runId}`, read));
  renderHook(() =>
    useRunEvents(makeRun(), {}, { idleTimeoutMs: 50, reconnectDelayMs: 1 }),
  );
  const first = await source(0);
  act(() => first.open());
  const next = await source(1);
  expect(read).toHaveBeenCalled();
  expect(next.url).toMatch(/\?after=0$/);
});

it("终态读取失败保持已知终态，提供读取失败标记", async () => {
  server.use(
    http.get(
      `/api/runs/${runId}`,
      () => new HttpResponse(null, { status: 503 }),
    ),
  );
  const { result } = renderHook(() => useRunEvents(makeRun()));
  const stream = await source(0);
  act(() =>
    stream.emit(
      "finished",
      makeEvent(1, "finished", { stop_reason: "completed" }),
    ),
  );
  await waitFor(() => expect(result.current.terminalReadFailed).toBe(true));
  expect(result.current.terminalStatus).toBe("completed");
  expect(result.current.phase).toBe("terminal");
});
