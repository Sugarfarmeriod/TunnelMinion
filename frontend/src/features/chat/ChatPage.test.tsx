import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

import { ChatPage } from "./ChatPage";
import type {
  RunEvent,
  RunStatus,
  RunView,
  ThreadMessage,
  ThreadSummary,
} from "./contracts";

const server = setupServer();
const timestamp = "2026-08-08T10:00:00+08:00";
const threadId = "thread_f8ba7a45920b4f2b8f16309c993680b1";
const secondThreadId = "thread_df72fe2995774ab88ab833457a4e5fd2";
const runId = "run_1220d96035cc487ab102491376c665e7";
const nodeId = "node_a93279a30fbd4597b9e2b755cd36629c";
const toolRun2 = "toolrun_00000000000000000000000000000002";
const toolRun3 = "toolrun_00000000000000000000000000000003";

class FakeEventSource {
  static instances: FakeEventSource[] = [];

  readonly url: string;
  readonly withCredentials = false;
  readyState = 0;
  closed = false;
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  private readonly listeners = new Map<
    string,
    Set<EventListenerOrEventListenerObject>
  >();

  constructor(url: string | URL) {
    this.url = String(url);
    FakeEventSource.instances.push(this);
  }

  addEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
  ) {
    if (listener === null) {
      return;
    }
    const listeners = this.listeners.get(type) ?? new Set();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
  ) {
    if (listener !== null) {
      this.listeners.get(type)?.delete(listener);
    }
  }

  dispatchEvent(event: Event): boolean {
    for (const listener of this.listeners.get(event.type) ?? []) {
      if (typeof listener === "function") {
        listener.call(this, event);
      } else {
        listener.handleEvent(event);
      }
    }
    return true;
  }

  open() {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  emit(type: RunEvent["event_type"], payload: RunEvent) {
    this.dispatchEvent(
      new MessageEvent(type, {
        data: JSON.stringify(payload),
        lastEventId: String(payload.sequence),
      }),
    );
  }

  fail() {
    this.onerror?.(new Event("error"));
  }

  close() {
    this.readyState = 2;
    this.closed = true;
  }

  static reset() {
    FakeEventSource.instances = [];
  }
}

interface Backend {
  threadIds: string[];
  messages: Map<string, ThreadMessage[]>;
  runs: Map<string, RunView>;
  runReads: number;
}

function installBackend(initialMessages: ThreadMessage[] = []): Backend {
  const backend: Backend = {
    threadIds: [threadId],
    messages: new Map([[threadId, initialMessages]]),
    runs: new Map(),
    runReads: 0,
  };
  server.use(
    http.get("/api/threads", () =>
      HttpResponse.json(
        backend.threadIds.map((id) =>
          makeThread(id, backend.messages.get(id)?.length ?? 0),
        ),
      ),
    ),
    http.get("/api/threads/:threadId", ({ params }) => {
      const id = String(params.threadId);
      if (!backend.threadIds.includes(id)) {
        return HttpResponse.json({ detail: "线程不存在" }, { status: 404 });
      }
      const messages = backend.messages.get(id) ?? [];
      return HttpResponse.json({
        thread: makeThread(id, messages.length),
        messages,
      });
    }),
    http.get("/api/runs/:runId", ({ params }) => {
      backend.runReads += 1;
      const run = backend.runs.get(String(params.runId));
      return run === undefined
        ? HttpResponse.json({ detail: "运行不存在" }, { status: 404 })
        : HttpResponse.json(run);
    }),
  );
  return backend;
}

function makeThread(id = threadId, messageCount = 0): ThreadSummary {
  return {
    thread_id: id,
    created_at: timestamp,
    updated_at: timestamp,
    message_count: messageCount,
  };
}

function makeMessage(
  role: ThreadMessage["role"],
  content: string,
  id = runId,
): ThreadMessage {
  return {
    role,
    content,
    created_at: timestamp,
    run_id: id,
  };
}

function makeRun(
  status: RunStatus = "running",
  values: Partial<RunView> = {},
): RunView {
  return {
    run_id: runId,
    thread_id: threadId,
    status,
    created_at: timestamp,
    finished_at: status === "running" ? null : timestamp,
    result: null,
    error_code: null,
    error_message: null,
    failure: null,
    ...values,
  };
}

function makeEvent(
  sequence: number,
  eventType: RunEvent["event_type"],
  values: Partial<RunEvent> = {},
): RunEvent {
  return {
    sequence,
    event_type: eventType,
    created_at: timestamp,
    run_id: runId,
    target_node_id: null,
    tool_name: null,
    tool_status: null,
    elapsed_ms: null,
    tool_run_id: null,
    stop_reason: null,
    message: null,
    ...values,
  };
}

function completedRun(answer: string): RunView {
  return makeRun("completed", {
    result: {
      answer,
      model_rounds: 1,
      tool_calls: 2,
      tool_run_ids: [toolRun2, toolRun3],
      selected_tools: ["get_node_summary"],
      stop_reason: "completed",
      elapsed_ms: 36,
      usage: {
        input_tokens: 10,
        output_tokens: 20,
        total_tokens: 30,
        estimated_cost: null,
      },
      limits: {
        max_model_rounds: 8,
        max_tool_calls: 12,
        timeout_seconds: 120,
      },
      evidence_answer: {
        summary: answer,
        confirmed_facts: [],
        inferences: [],
        unknowns: [],
        evidence: [
          {
            tool_run_id: toolRun3,
            tool_name: "get_node_summary",
            status: "success",
          },
        ],
        stop_reason: "completed",
      },
      context_records: [],
      failures: [],
    },
  });
}

async function waitForSource(index = 0) {
  await waitFor(() => {
    expect(FakeEventSource.instances.length).toBeGreaterThan(index);
  });
  return FakeEventSource.instances[index]!;
}

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

beforeEach(() => {
  FakeEventSource.reset();
  vi.stubGlobal("EventSource", FakeEventSource);
});

afterEach(() => {
  cleanup();
  server.resetHandlers();
  vi.unstubAllGlobals();
});

afterAll(() => {
  server.close();
});

describe("ChatPage", () => {
  it("新建、选择并确认删除线程，同时明确长期记忆不受影响", async () => {
    const backend = installBackend();
    let createCalls = 0;
    let deleteCalls = 0;
    server.use(
      http.post("/api/threads", ({ request }) => {
        createCalls += 1;
        expect(request.headers.get("X-TunnelMinion-Request")).toBe(
          "same-origin",
        );
        backend.threadIds.push(secondThreadId);
        backend.messages.set(secondThreadId, []);
        return HttpResponse.json(makeThread(secondThreadId));
      }),
      http.delete("/api/threads/:threadId", ({ params, request }) => {
        deleteCalls += 1;
        expect(request.headers.get("X-TunnelMinion-Request")).toBe(
          "same-origin",
        );
        const id = String(params.threadId);
        backend.threadIds = backend.threadIds.filter((item) => item !== id);
        backend.messages.delete(id);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();

    render(<ChatPage />);
    await screen.findByRole("heading", { name: "继续当前线程" });

    await user.click(screen.getByRole("button", { name: "新建线程" }));
    expect(createCalls).toBe(1);
    const second = await screen.findByRole("button", {
      name: /继续对话 2/,
    });
    expect(second).toHaveAttribute("aria-pressed", "true");

    await user.click(screen.getByRole("button", { name: "删除所选线程" }));
    const dialog = screen.getByRole("alertdialog", {
      name: "确认删除这个线程？",
    });
    expect(dialog).toHaveTextContent("独立的长期记忆不会被删除");
    expect(dialog).toHaveTextContent(secondThreadId);
    expect(screen.getByRole("button", { name: "保留线程" })).toHaveFocus();

    await user.click(screen.getByRole("button", { name: "确认删除" }));
    expect(deleteCalls).toBe(1);
    expect(
      await screen.findByText("线程及其短期消息已删除，独立长期记忆未受影响。"),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: /继续对话 2/ })).toBeNull();
  });

  it("把恶意与超长消息作为可换行纯文本呈现", async () => {
    const malicious = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const longMessage = "很长的公开回答".repeat(1_000);
    const backend = installBackend([
      makeMessage("assistant", malicious),
      makeMessage("assistant", longMessage),
    ]);
    backend.runs.set(runId, makeRun("completed"));

    const { container } = render(<ChatPage />);

    expect(await screen.findByText(malicious)).toBeVisible();
    const longText = screen.getByText(longMessage);
    expect(longText).toHaveClass("chat-untrusted-text");
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("发起 run、按 after 恢复缺口、去重工具事件并在终态关闭", async () => {
    const backend = installBackend();
    let startCalls = 0;
    const maliciousTool = '<script data-secret="no">bad tool</script>';
    const finalAnswer = "完成：<script>alert('answer')</script>";
    server.use(
      http.post("/api/threads/:threadId/runs", async ({ request }) => {
        startCalls += 1;
        expect(request.headers.get("X-TunnelMinion-Request")).toBe(
          "same-origin",
        );
        expect(await request.json()).toEqual({
          question: "检查本机",
          tool_names: ["get_node_summary"],
        });
        backend.messages.set(threadId, [makeMessage("user", "检查本机")]);
        const running = makeRun();
        backend.runs.set(runId, running);
        return HttpResponse.json(running);
      }),
    );
    const user = userEvent.setup();

    const { container } = render(
      <ChatPage streamIdleTimeoutMs={10_000} streamReconnectDelayMs={0} />,
    );
    const question = await screen.findByLabelText("问题");
    await user.type(question, "检查本机");
    await user.click(screen.getByRole("button", { name: "发送并开始运行" }));
    expect(startCalls).toBe(1);

    const firstSource = await waitForSource();
    expect(firstSource.url).toBe(`/api/runs/${runId}/events?after=0`);
    act(() => {
      firstSource.open();
      firstSource.emit("goal", makeEvent(1, "goal", { message: "检查本机" }));
    });
    act(() => {
      firstSource.emit(
        "tool",
        makeEvent(2, "tool", {
          target_node_id: nodeId,
          tool_name: maliciousTool,
          tool_status: "failed",
          elapsed_ms: 14,
          tool_run_id: toolRun2,
        }),
      );
      firstSource.emit(
        "tool",
        makeEvent(2, "tool", {
          target_node_id: nodeId,
          tool_name: maliciousTool,
          tool_status: "duplicate",
          elapsed_ms: 14,
          tool_run_id: toolRun2,
        }),
      );
      backend.runs.set(runId, completedRun(finalAnswer));
      firstSource.emit("tool", makeEvent(4, "tool"));
    });

    expect(await screen.findByText(maliciousTool)).toBeVisible();
    expect(screen.getAllByText(maliciousTool)).toHaveLength(1);
    expect(screen.getByText("failed")).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();

    const recoveredSource = await waitForSource(1);
    expect(firstSource.closed).toBe(true);
    expect(recoveredSource.url).toBe(`/api/runs/${runId}/events?after=2`);
    act(() => {
      recoveredSource.open();
      recoveredSource.emit(
        "tool",
        makeEvent(3, "tool", {
          target_node_id: nodeId,
          tool_name: "get_node_summary",
          tool_status: "success",
          elapsed_ms: 22,
          tool_run_id: toolRun3,
        }),
      );
    });

    backend.messages.set(threadId, [
      makeMessage("user", "检查本机"),
      makeMessage("assistant", finalAnswer),
    ]);
    backend.runs.set(runId, completedRun(finalAnswer));
    act(() => {
      recoveredSource.emit(
        "finished",
        makeEvent(4, "finished", {
          elapsed_ms: 36,
          stop_reason: "completed",
          message: finalAnswer,
        }),
      );
    });

    expect(await screen.findByText("已完成")).toBeVisible();
    expect(recoveredSource.closed).toBe(true);
    expect(screen.getAllByText(toolRun3).length).toBeGreaterThan(0);
    expect(screen.getAllByText(finalAnswer).length).toBeGreaterThan(0);
    expect(container.querySelector("script")).toBeNull();
  });

  it("断线后先复读 run，再从最后序号重连，并在卸载时清理连接", async () => {
    const backend = installBackend([makeMessage("user", "恢复运行")]);
    backend.runs.set(runId, makeRun());

    const view = render(
      <ChatPage streamIdleTimeoutMs={10_000} streamReconnectDelayMs={0} />,
    );
    const firstSource = await waitForSource();
    act(() => {
      firstSource.open();
      firstSource.emit("goal", makeEvent(1, "goal", { message: "恢复运行" }));
    });
    const readsBeforeDisconnect = backend.runReads;
    act(() => firstSource.fail());

    const recoveredSource = await waitForSource(1);
    expect(backend.runReads).toBeGreaterThan(readsBeforeDisconnect);
    expect(recoveredSource.url).toBe(`/api/runs/${runId}/events?after=1`);
    expect(firstSource.closed).toBe(true);

    const sourceCount = FakeEventSource.instances.length;
    view.unmount();
    expect(recoveredSource.closed).toBe(true);
    await new Promise((resolve) => window.setTimeout(resolve, 20));
    expect(FakeEventSource.instances).toHaveLength(sourceCount);
  });

  it("事件流空闲超时后复读 run，再安全恢复", async () => {
    const backend = installBackend([makeMessage("user", "等待事件")]);
    backend.runs.set(runId, makeRun());

    const view = render(
      <ChatPage streamIdleTimeoutMs={15} streamReconnectDelayMs={0} />,
    );
    const firstSource = await waitForSource();
    const readsBeforeTimeout = backend.runReads;
    act(() => firstSource.open());

    const recoveredSource = await waitForSource(1);
    expect(backend.runReads).toBeGreaterThan(readsBeforeTimeout);
    expect(firstSource.closed).toBe(true);
    expect(recoveredSource.url).toBe(`/api/runs/${runId}/events?after=0`);
    view.unmount();
  });

  it("发送结果未知时只复读线程，不自动重放 POST 或工具调用", async () => {
    const backend = installBackend();
    let startCalls = 0;
    server.use(
      http.post("/api/threads/:threadId/runs", ({ request }) => {
        startCalls += 1;
        expect(request.headers.get("X-TunnelMinion-Request")).toBe(
          "same-origin",
        );
        backend.messages.set(threadId, [makeMessage("user", "未知结果")]);
        backend.runs.set(runId, makeRun());
        return HttpResponse.error();
      }),
    );
    const user = userEvent.setup();

    render(<ChatPage streamIdleTimeoutMs={10_000} />);
    await user.type(await screen.findByLabelText("问题"), "未知结果");
    await user.click(screen.getByRole("button", { name: "发送并开始运行" }));

    expect(
      await screen.findByText(/发送结果未知；正在复读当前线程/),
    ).toBeVisible();
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
    await new Promise((resolve) => window.setTimeout(resolve, 20));
    expect(startCalls).toBe(1);
    expect(screen.getByDisplayValue("未知结果")).toBeDisabled();
  });

  it("HTTP 5xx 写结果也只复读，不自动重放 POST", async () => {
    const backend = installBackend();
    let startCalls = 0;
    server.use(
      http.post("/api/threads/:threadId/runs", () => {
        startCalls += 1;
        backend.messages.set(threadId, [makeMessage("user", "服务端超时")]);
        backend.runs.set(runId, makeRun());
        return HttpResponse.json(
          {
            detail: {
              code: "gateway_timeout",
              message: "结果无法确认",
            },
          },
          { status: 500 },
        );
      }),
    );
    const user = userEvent.setup();

    render(<ChatPage streamIdleTimeoutMs={10_000} />);
    await user.type(await screen.findByLabelText("问题"), "服务端超时");
    await user.click(screen.getByRole("button", { name: "发送并开始运行" }));

    expect(
      await screen.findByText(/发送结果未知；正在复读当前线程/),
    ).toBeVisible();
    await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
    await new Promise((resolve) => window.setTimeout(resolve, 20));
    expect(startCalls).toBe(1);
  });

  it("终态 SSE 后即使 run 复读失败也解锁输入并提供只读刷新", async () => {
    const backend = installBackend([makeMessage("user", "等待终态")]);
    backend.runs.set(runId, makeRun());
    let failRunRead = false;
    server.use(
      http.get("/api/runs/:runId", ({ params }) => {
        if (failRunRead) {
          return HttpResponse.error();
        }
        const run = backend.runs.get(String(params.runId));
        return run === undefined
          ? HttpResponse.json({ detail: "运行不存在" }, { status: 404 })
          : HttpResponse.json(run);
      }),
    );

    render(<ChatPage streamIdleTimeoutMs={10_000} />);
    const source = await waitForSource();
    act(() => source.open());
    backend.messages.set(threadId, [
      makeMessage("user", "等待终态"),
      makeMessage("assistant", "服务端已经完成"),
    ]);
    backend.runs.set(runId, completedRun("服务端已经完成"));
    failRunRead = true;
    act(() => {
      source.emit(
        "finished",
        makeEvent(1, "finished", {
          stop_reason: "completed",
          message: "服务端已经完成",
        }),
      );
    });

    expect(await screen.findByText("已完成")).toBeVisible();
    expect(screen.getByLabelText("问题")).toBeEnabled();
    expect(screen.queryByRole("button", { name: "取消这次运行" })).toBeNull();
    expect(
      await screen.findByText(/已收到并应用终态事件，但暂时无法复读/),
    ).toBeVisible();
    const refresh = screen.getByRole("button", { name: "重新读取线程" });

    failRunRead = false;
    await userEvent.setup().click(refresh);
    expect(
      await screen.findByText("已通过只读请求重新读取线程与运行状态。"),
    ).toBeVisible();
    await waitFor(() => {
      expect(
        screen.queryByText(/已收到并应用终态事件，但暂时无法复读/),
      ).toBeNull();
    });
  });

  it("模型不可用时不创建事件连接，取消竞态则采用服务端终态", async () => {
    const backend = installBackend();
    let startCalls = 0;
    server.use(
      http.post("/api/threads/:threadId/runs", () => {
        startCalls += 1;
        return HttpResponse.json({ detail: "模型未配置" }, { status: 503 });
      }),
    );
    const user = userEvent.setup();
    const firstView = render(<ChatPage />);

    await user.type(await screen.findByLabelText("问题"), "需要模型");
    await user.click(screen.getByRole("button", { name: "发送并开始运行" }));
    expect(
      await screen.findByText(/模型服务返回不可用；写入结果仍按未知处理/),
    ).toBeVisible();
    expect(startCalls).toBe(1);
    expect(FakeEventSource.instances).toHaveLength(0);
    firstView.unmount();

    FakeEventSource.reset();
    backend.messages.set(threadId, [makeMessage("user", "取消竞态")]);
    backend.runs.set(runId, makeRun());
    let cancelCalls = 0;
    server.use(
      http.post("/api/runs/:runId/cancel", ({ request }) => {
        cancelCalls += 1;
        expect(request.headers.get("X-TunnelMinion-Request")).toBe(
          "same-origin",
        );
        const completed = completedRun("服务端已先完成");
        backend.runs.set(runId, completed);
        backend.messages.set(threadId, [
          makeMessage("user", "取消竞态"),
          makeMessage("assistant", "服务端已先完成"),
        ]);
        return HttpResponse.json(completed);
      }),
    );
    const secondView = render(<ChatPage streamIdleTimeoutMs={10_000} />);
    const source = await waitForSource();
    act(() => source.open());

    await user.click(screen.getByRole("button", { name: "取消这次运行" }));
    const cancelDialog = screen.getByRole("alertdialog", {
      name: "确认取消这次运行？",
    });
    expect(cancelDialog).toHaveTextContent(runId);
    expect(cancelCalls).toBe(0);
    await user.click(screen.getByRole("button", { name: "确认取消此运行" }));
    expect(
      await screen.findByText(/运行状态：已完成；不会再次发送取消请求/),
    ).toBeVisible();
    expect(cancelCalls).toBe(1);
    expect(source.closed).toBe(true);
    expect(screen.queryByRole("button", { name: "取消这次运行" })).toBeNull();
    secondView.unmount();
  });
});
