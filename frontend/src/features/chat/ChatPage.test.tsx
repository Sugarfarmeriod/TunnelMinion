import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
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

import { ChatPage } from "./ChatPage";
import {
  makeOperationDetail,
  makeOperationListItem,
} from "../operations/testFixtures";
import type { ResourceOverview } from "../../api/schemas/overview";
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
const program: ResourceOverview["services"]["items"][number] = {
  service_id: `service_${"a".repeat(32)}`,
  node_id: nodeId,
  display_name: "gost · 805",
  application: {
    group_id: `application_${"a".repeat(32)}`,
    name: "gost",
    kind: "program",
  },
  protocol: "tcp",
  port: 805,
  access_address: "tcp://192.0.2.1:805",
  accessibility: "network",
  lifecycle: "active",
  state: "available",
  source: "local_observation",
  evidence_at: timestamp,
  freshness: "fresh",
};
const computers: ResourceOverview["nodes"]["items"] = [
  {
    node_id: nodeId,
    display_name: "客厅 Mac",
    platform: "macos",
    state: "local",
    source: "local_observation",
    evidence_at: timestamp,
    freshness: "fresh",
    service_count: 1,
  },
];

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
  updatedAt: Map<string, string>;
  messages: Map<string, ThreadMessage[]>;
  runs: Map<string, RunView>;
  runReads: number;
  serviceIds: Map<string, string | null>;
}

function installBackend(initialMessages: ThreadMessage[] = []): Backend {
  const backend: Backend = {
    threadIds: [threadId],
    updatedAt: new Map(),
    messages: new Map([[threadId, initialMessages]]),
    runs: new Map(),
    runReads: 0,
    serviceIds: new Map(),
  };
  server.use(
    http.get("/api/threads", () =>
      HttpResponse.json(
        backend.threadIds.map((id) =>
          makeThread(
            id,
            backend.messages.get(id)?.length ?? 0,
            backend.updatedAt.get(id),
          ),
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
    http.get("/api/ui/threads/:threadId", ({ params }) => {
      const id = String(params.threadId);
      if (!backend.threadIds.includes(id)) {
        return HttpResponse.json({}, { status: 404 });
      }
      const messages = backend.messages.get(id) ?? [];
      return HttpResponse.json({
        thread: makeThread(id, messages.length),
        messages,
        service_id: backend.serviceIds.get(id) ?? null,
      });
    }),
    http.get("/api/runs/:runId", ({ params }) => {
      backend.runReads += 1;
      const run = backend.runs.get(String(params.runId));
      return run === undefined
        ? HttpResponse.json({ detail: "运行不存在" }, { status: 404 })
        : HttpResponse.json(run);
    }),
    http.get("/api/operations", () => HttpResponse.json([])),
  );
  return backend;
}

function makeThread(
  id = threadId,
  messageCount = 0,
  updatedAt = timestamp,
): ThreadSummary {
  return {
    thread_id: id,
    created_at: timestamp,
    updated_at: updatedAt,
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
    answer_checked: role === "assistant",
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
      answer_checked: true,
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

async function replayTerminalRun(status: RunStatus = "completed") {
  const source = await waitForSource();
  const eventType =
    status === "failed" || status === "interrupted" ? status : "finished";
  act(() => {
    source.emit(
      eventType,
      makeEvent(1, eventType, {
        stop_reason: status === "cancelled" ? "cancelled" : "completed",
      }),
    );
  });
  await waitFor(() => expect(source.closed).toBe(true));
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
  it.each([
    ["model_network_unreachable", "这次联系模型时遇到问题，还没查完。", true],
    [
      "model_authentication_failed",
      "模型连接没有通过验证，这次检查没能完成。",
      true,
    ],
    ["model_timeout", "等模型回答等得太久，这次检查先停下了。", false],
    ["tool_failed", "读取程序情况时遇到问题，这次还没查完。", false],
    [
      "unknown_fixture",
      "这次检查没有完成，还不能据此判断程序是否有问题。",
      false,
    ],
    ["__proto__", "这次检查没有完成，还不能据此判断程序是否有问题。", false],
  ] as const)(
    "未完成检查按已知原因说明，不从原始文字猜测（%s）",
    async (reason, explanation, settings) => {
      const backend = installBackend([makeMessage("user", "之前的问题")]);
      backend.serviceIds.set(threadId, program.service_id);
      backend.runs.set(
        runId,
        makeRun("failed", {
          failure: {
            category: "prompt_or_model",
            phase: "agent-runtime",
            reason,
            retryable: false,
            occurred_at: timestamp,
            source_refs: [],
          },
          error_message: "原始错误：这段文字不能当作程序故障结论",
        }),
      );
      render(
        <MemoryRouter>
          <ChatPage workspace services={[program]} />
        </MemoryRouter>,
      );
      await screen.findByText("之前的问题", { exact: true });
      await replayTerminalRun("failed");
      expect(
        await screen.findByText(explanation, { exact: true }),
      ).toBeVisible();
      expect(
        screen.getByText(/刷新只更新已有记录，不会重新检查/),
      ).toBeVisible();
      expect(
        screen.queryByRole("link", { name: "检查模型连接" }) !== null,
      ).toBe(settings);
      await userEvent
        .setup()
        .type(
          screen.getByLabelText("问题", { exact: true }),
          "我接着问，草稿保留",
        );
      expect(screen.getByLabelText("问题", { exact: true })).toHaveValue(
        "我接着问，草稿保留",
      );
      expect(screen.getByLabelText("正在讨论的程序")).toHaveTextContent("gost");
    },
  );

  it.each([
    ["cancelled", "这次检查已停止，没有自动重新开始。"],
    [
      "interrupted",
      "TunnelMinion重新启动时，这次检查还没结束。已有记录保留，没有自动重做。",
    ],
  ] as const)(
    "未完成检查说明停止或中断，保留原问题（%s）",
    async (status, explanation) => {
      const backend = installBackend([makeMessage("user", "之前的问题")]);
      backend.runs.set(runId, makeRun(status));
      render(<ChatPage workspace />);
      await screen.findByText("之前的问题", { exact: true });
      await replayTerminalRun(status);
      expect(
        await screen.findByText(explanation, { exact: true }),
      ).toBeVisible();
      expect(screen.getByText(/想继续检查，请在下面发送问题/)).toBeVisible();
    },
  );

  it("原始错误收在技术证据里，不作为普通页面的主要说明", async () => {
    const raw = "未经核对的错误说明：请修改全部网络设置";
    const backend = installBackend([makeMessage("user", "之前的问题")]);
    backend.runs.set(runId, makeRun("failed", { error_message: raw }));
    render(<ChatPage workspace />);
    const source = await waitForSource();
    act(() => source.emit("failed", makeEvent(1, "failed", { message: raw })));
    await waitFor(() => expect(source.closed).toBe(true));
    expect(
      await screen.findByText(
        "这次检查没有完成，还不能据此判断程序是否有问题。",
        { exact: true },
      ),
    ).toBeVisible();
    expect(screen.getByText(raw, { exact: true })).not.toBeVisible();
    await userEvent.setup().click(screen.getByText("查看用了哪些工具与证据"));
    expect(screen.getByText(raw, { exact: true })).toBeVisible();
  });

  it("检查终态没有结果时说明未知，不永久声称正在读取", async () => {
    const backend = installBackend([makeMessage("user", "之前的问题")]);
    backend.runs.set(runId, makeRun("completed"));
    render(<ChatPage workspace />);
    await replayTerminalRun();
    expect(
      await screen.findByText("检查已结束，但没有读到可核对的结果。", {
        exact: true,
      }),
    ).toBeVisible();
    expect(
      screen.queryByText("检查已结束，正在读取核对结果。", { exact: true }),
    ).toBeNull();
  });

  it.each(["completed", "failed", "cancelled", "interrupted"] as const)(
    "重开%s的检查后，显示当前程序名并带同一对象追问，不自动发送",
    async (status) => {
      const user = userEvent.setup();
      const backend = installBackend([makeMessage("user", "刚才检查的程序")]);
      backend.serviceIds.set(threadId, program.service_id);
      backend.runs.set(runId, makeRun(status));
      let writes = 0;
      server.use(
        http.post("/api/ui/threads/:id/runs", async ({ request }) => {
          writes += 1;
          expect(await request.json()).toMatchObject({
            question: "继续看刚才的问题",
            service_id: program.service_id,
          });
          return HttpResponse.json(makeRun("completed"));
        }),
      );
      render(<ChatPage workspace services={[program]} nodes={computers} />);
      expect(await screen.findByLabelText("正在讨论的程序")).toHaveTextContent(
        "客厅 Mac · gost",
      );
      await replayTerminalRun(status);
      await user.type(
        await screen.findByLabelText("问题", { exact: true }),
        "继续看刚才的问题",
      );
      expect(writes).toBe(0);
      await user.click(screen.getByRole("button", { name: "发送问题" }));
      await waitFor(() => expect(writes).toBe(1));
    },
  );

  it.each(["missing", "stale", "ambiguous", "unavailable"] as const)(
    "原程序%s时保留消息和草稿，不悄悄变成无对象提问",
    async (state) => {
      const user = userEvent.setup();
      const backend = installBackend([makeMessage("user", "已有检查记录")]);
      backend.serviceIds.set(threadId, program.service_id);
      backend.runs.set(runId, makeRun("failed"));
      const services =
        state === "missing"
          ? []
          : state === "stale"
            ? [{ ...program, freshness: "stale" as const }]
            : state === "ambiguous"
              ? [program, program]
              : undefined;
      const view = render(<ChatPage workspace services={services} />);
      expect(
        await screen.findByText("已有检查记录", { exact: true }),
      ).toBeVisible();
      await replayTerminalRun("failed");
      expect(
        screen.getByText(/暂时找不到这段对话原来检查的程序/),
      ).toBeVisible();
      const question = screen.getByLabelText("问题", { exact: true });
      await user.type(question, "草稿不能丢");
      expect(question).toHaveValue("草稿不能丢");
      expect(screen.getByRole("button", { name: "发送问题" })).toBeDisabled();
      expect(
        screen.getByText(/先从程序列表重新选择程序，再继续问。/),
      ).toBeVisible();
      expect(FakeEventSource.instances).toHaveLength(1);
      view.rerender(
        <ChatPage workspace services={[program]} nodes={computers} />,
      );
      expect(screen.getByLabelText("问题", { exact: true })).toHaveValue(
        "草稿不能丢",
      );
      expect(screen.getByRole("button", { name: "发送问题" })).toBeEnabled();
    },
  );

  it.each(["checked", "unchecked", "explicit-empty"] as const)(
    "旧记录只从可信核对结果恢复，明确空关联不被覆盖（%s）",
    async (state) => {
      const backend = installBackend([makeMessage("user", "旧检查记录")]);
      const run = completedRun("保留的结论");
      run.result!.checked_service_id = program.service_id;
      run.result!.answer_checked = state !== "unchecked";
      backend.runs.set(runId, run);
      if (state !== "explicit-empty") {
        server.use(
          http.get("/api/ui/threads/:id", () =>
            HttpResponse.json({}, { status: 404 }),
          ),
        );
      }
      render(<ChatPage workspace services={[program]} nodes={computers} />);
      await screen.findByText("旧检查记录", { exact: true });
      await waitFor(() => expect(backend.runReads).toBeGreaterThan(0));
      await replayTerminalRun();
      if (state === "checked") {
        expect(
          await screen.findByLabelText("正在讨论的程序"),
        ).toHaveTextContent("gost");
      } else {
        expect(screen.queryByLabelText("正在讨论的程序")).toBeNull();
      }
      await userEvent
        .setup()
        .type(screen.getByLabelText("问题", { exact: true }), "继续问");
      expect(screen.getByRole("button", { name: "发送问题" })).toHaveProperty(
        "disabled",
        state === "unchecked",
      );
    },
  );

  it.each(["incident", "operation"] as const)(
    "%s 不继承程序对话的对象，仍走原来的提问入口",
    async (mode) => {
      const backend = installBackend([makeMessage("user", "普通程序对话")]);
      backend.serviceIds.set(threadId, program.service_id);
      backend.runs.set(runId, makeRun("completed"));
      const incidentId = `incident_${"a".repeat(32)}`;
      let writes = 0;
      server.use(
        http.post(
          mode === "incident"
            ? `/api/incidents/${incidentId}/follow-up`
            : "/api/threads/:id/runs",
          async ({ request }) => {
            writes += 1;
            const payload = await request.json();
            expect(payload).not.toHaveProperty("service_id");
            expect(payload).toHaveProperty(
              "question",
              expect.stringContaining("继续问这件事"),
            );
            return HttpResponse.json(makeRun("completed"));
          },
        ),
      );
      render(
        <ChatPage
          workspace
          services={[program]}
          serviceContext={program}
          {...(mode === "incident"
            ? { incidentId, incidentThreadId: threadId }
            : { operationContext: makeOperationDetail() })}
        />,
      );
      await replayTerminalRun();
      await userEvent
        .setup()
        .type(
          await screen.findByLabelText("问题", { exact: true }),
          "继续问这件事",
        );
      expect(screen.queryByLabelText("正在讨论的程序")).toBeNull();
      expect(writes).toBe(0);
      await userEvent
        .setup()
        .click(screen.getByRole("button", { name: "发送问题" }));
      await waitFor(() => expect(writes).toBe(1));
    },
  );

  it("任务记录还没读到时，不显示上一段对话的程序", async () => {
    const backend = installBackend();
    backend.serviceIds.set(threadId, program.service_id);
    const view = render(<ChatPage workspace services={[program]} />);
    await screen.findByLabelText("正在讨论的程序");
    view.rerender(<ChatPage workspace services={[program]} contextBlocked />);
    expect(screen.queryByLabelText("正在讨论的程序")).toBeNull();
    expect(
      screen.getByText("还没读到这项任务的完整记录，暂时不能针对它提问。"),
    ).toBeVisible();
  });

  it("默认接上最近的对话，手动选择旧对话后刷新不跳走", async () => {
    const backend = installBackend([makeMessage("user", "以前的检查")]);
    const recentRunId = `run_${"4".repeat(32)}`;
    backend.threadIds.push(secondThreadId);
    backend.updatedAt.set(secondThreadId, "2026-10-15T08:28:00Z");
    backend.messages.set(secondThreadId, [
      makeMessage("user", "刚才的检查", recentRunId),
    ]);
    backend.runs.set(runId, makeRun("completed"));
    backend.runs.set(
      recentRunId,
      makeRun("completed", { run_id: recentRunId, thread_id: secondThreadId }),
    );
    render(<ChatPage workspace />);
    expect(
      await screen.findByText("刚才的检查", { exact: true }),
    ).toBeVisible();
    expect(screen.queryByText("以前的检查", { exact: true })).toBeNull();
    const user = userEvent.setup();
    await user.click(screen.getByText("以往对话", { exact: true }));
    await user.click(screen.getByRole("button", { name: /继续对话 2/ }));
    expect(
      await screen.findByText("以前的检查", { exact: true }),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: "刷新这段对话" }));
    await screen.findByText("这段对话和检查进展已刷新，没有重新发起检查。");
    expect(screen.getByText("以前的检查", { exact: true })).toBeVisible();
    expect(screen.queryByText("刚才的检查", { exact: true })).toBeNull();
  });

  it.each(["incident", "deep-link"])(
    "%s 指定的对话优先于最近对话",
    async (entry) => {
      const backend = installBackend([makeMessage("user", "指定的检查")]);
      backend.threadIds.push(secondThreadId);
      backend.updatedAt.set(secondThreadId, "2026-10-15T08:28:00Z");
      backend.messages.set(secondThreadId, [
        makeMessage("user", "另一段更新的对话"),
      ]);
      const originalUrl = window.location.href;
      try {
        if (entry === "deep-link")
          window.history.replaceState({}, "", `?thread=${threadId}`);
        render(
          <ChatPage
            workspace
            {...(entry === "incident"
              ? {
                  incidentId: `incident_${"a".repeat(32)}`,
                  incidentThreadId: threadId,
                }
              : {})}
          />,
        );
        expect(
          await screen.findByText("指定的检查", { exact: true }),
        ).toBeVisible();
        expect(
          screen.queryByText("另一段更新的对话", { exact: true }),
        ).toBeNull();
      } finally {
        window.history.replaceState({}, "", originalUrl);
      }
    },
  );

  it.each(["fresh", "stale"] as const)(
    "工作台只传所选程序身份，归属由服务端核对且不丢草稿（%s）",
    async (freshness) => {
      const user = userEvent.setup();
      const backend = installBackend();
      backend.serviceIds.set(threadId, program.service_id);
      let writes = 0;
      server.use(
        http.post("/api/ui/threads/:id/runs", async ({ request }) => {
          writes += 1;
          const payload = (await request.json()) as {
            question: string;
            service_id: string;
            tool_names: string[];
          };
          expect(payload.question).toBe("为什么别的电脑打不开？");
          expect(payload.service_id).toBe(service.service_id);
          expect(payload.tool_names).toEqual([
            "get_node_summary",
            "get_wireguard_status",
            "list_network_listeners",
            "get_process_summary",
            "list_docker_services",
            "probe_service_reachability",
          ]);
          backend.messages.set(threadId, [
            makeMessage("user", payload.question),
          ]);
          backend.runs.set(runId, makeRun("completed"));
          return HttpResponse.json(makeRun("completed"));
        }),
      );
      const service = {
        ...program,
        service_id: `service_${"b".repeat(32)}`,
        freshness,
      };
      const view = render(<ChatPage workspace services={[program]} />);
      await user.type(
        await screen.findByLabelText("问题", { exact: true }),
        "为什么别的电脑打不开？",
      );
      view.rerender(
        <ChatPage
          workspace
          services={[program]}
          serviceContext={service}
          computerName="客厅 Mac"
        >
          <p>当前请求</p>
        </ChatPage>,
      );
      expect(screen.getByLabelText("问题", { exact: true })).toHaveValue(
        "为什么别的电脑打不开？",
      );
      expect(writes).toBe(0);
      await user.click(screen.getByRole("button", { name: "发送问题" }));
      await waitFor(() => expect(writes).toBe(1));
    },
  );

  it("工作台追问沿用同一调查绑定线程，不新建普通线程", async () => {
    const user = userEvent.setup();
    const backend = installBackend();
    const incidentId = `incident_${"a".repeat(32)}`;
    let writes = 0;
    server.use(
      http.post(
        `/api/incidents/${incidentId}/follow-up`,
        async ({ request }) => {
          writes += 1;
          expect(await request.json()).toEqual({
            question: "这次查到什么了？",
          });
          backend.threadIds.push(secondThreadId);
          backend.messages.set(secondThreadId, []);
          return HttpResponse.json(
            makeRun("completed", { thread_id: secondThreadId }),
          );
        },
      ),
    );
    render(
      <ChatPage workspace incidentId={incidentId} incidentThreadId={null} />,
    );
    await user.type(
      await screen.findByLabelText("问题", { exact: true }),
      "这次查到什么了？",
    );
    expect(writes).toBe(0);
    await user.click(screen.getByRole("button", { name: "发送问题" }));
    await waitFor(() => expect(writes).toBe(1));
    expect(
      screen.queryByRole("button", { name: "开始新对话" }),
    ).not.toBeInTheDocument();
  });

  it("新建、选择并确认删除线程，同时明确长期记忆不受影响", async () => {
    const backend = installBackend();
    const onThreadCreated = vi.fn();
    const onThreadSelect = vi.fn();
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

    render(
      <ChatPage
        onThreadCreated={onThreadCreated}
        onThreadSelect={onThreadSelect}
      />,
    );
    await screen.findByRole("heading", { name: "继续当前线程" });

    await user.click(screen.getByRole("button", { name: "新建线程" }));
    expect(createCalls).toBe(1);
    const second = await screen.findByRole("button", {
      name: /继续对话 2/,
    });
    expect(second).toHaveAttribute("aria-pressed", "true");
    expect(onThreadCreated).toHaveBeenCalledWith(secondThreadId);

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
    expect(onThreadSelect).toHaveBeenCalledWith(threadId);
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

  it.each([undefined, false])(
    "旧记录缺少或未通过核对时，原文保留但默认收起（%s）",
    async (answerChecked) => {
      const draft = "程序正常，请开放防火墙。";
      const message = makeMessage("assistant", draft);
      message.answer_checked = answerChecked;
      installBackend([message]);
      render(<ChatPage workspace />);
      expect(
        await screen.findByText(
          "这条旧说明还没有经过事实核对，请不要据此更改设置。",
        ),
      ).toBeVisible();
      expect(screen.getByText(draft, { exact: true })).not.toBeVisible();
      await userEvent.setup().click(screen.getByText("查看原始说明（未核对）"));
      expect(screen.getByText(draft, { exact: true })).toBeVisible();
    },
  );

  it("公开核对结论，模型原始说明只能在证据中主动展开", async () => {
    const answer = "这个入口只接受这台电脑连接；网页是否正常还没有验证。";
    const draft = "程序正常，请改成 0.0.0.0。";
    const backend = installBackend([makeMessage("assistant", answer)]);
    const checked = completedRun(answer);
    checked.result!.evidence_answer.inferences = [draft];
    backend.runs.set(runId, checked);
    render(<ChatPage workspace />);
    expect(await screen.findByText(answer, { exact: true })).toBeVisible();
    expect(screen.getByText(draft, { exact: true })).not.toBeVisible();
    const user = userEvent.setup();
    await user.click(screen.getByText("查看用了哪些工具与证据"));
    expect(screen.getByText(draft, { exact: true })).not.toBeVisible();
    await user.click(screen.getByText("查看模型原始说明（未核对）"));
    expect(screen.getByText(draft, { exact: true })).toBeVisible();
  });

  it("实时结束消息不能覆盖已读取的核对结果", async () => {
    const backend = installBackend([makeMessage("user", "检查面板")]);
    backend.runs.set(runId, makeRun());
    render(<ChatPage />);
    const source = await waitForSource();
    backend.runs.set(runId, completedRun("跨电脑访问还没有验证。"));
    act(() => {
      source.emit(
        "finished",
        makeEvent(1, "finished", {
          stop_reason: "completed",
          message: "程序正常，请开放防火墙。",
        }),
      );
    });
    expect(await screen.findByText("跨电脑访问还没有验证。")).toBeVisible();
    expect(screen.queryByText("程序正常，请开放防火墙。")).toBeNull();
  });

  it("把共享工具证据的操作链接到现有详情页", async () => {
    const backend = installBackend([makeMessage("assistant", "检查完成")]);
    backend.runs.set(runId, completedRun("检查完成"));
    const related = makeOperationListItem({
      tool_run_ids: [toolRun3],
      tool_name: "share_local_http_service",
    });
    server.use(http.get("/api/operations", () => HttpResponse.json([related])));

    render(<ChatPage />);

    const link = await screen.findByRole("link", {
      name: "share_local_http_service · awaiting_authorization",
    });
    expect(link).toHaveAttribute(
      "href",
      `/app/operations/${related.operation_id}`,
    );
  });

  it.each([
    ["timeout", "暂时没查完"],
    ["model-limit", "已达到调查上限"],
    ["tool-limit", "已达到调查上限"],
    ["cancelled", "已停止检查"],
  ] as const)("%s 停止不显示为调查完成", async (reason, label) => {
    const backend = installBackend([makeMessage("user", "检查面板")]);
    const stopped = completedRun("还没有完整结论。");
    stopped.result!.stop_reason = reason;
    stopped.result!.evidence_answer.stop_reason = reason;
    backend.runs.set(runId, stopped);
    render(<ChatPage workspace />);
    expect(await screen.findByText(label, { exact: true })).toBeVisible();
    expect(
      screen.queryByText("已完成", { exact: true }),
    ).not.toBeInTheDocument();
  });

  it("只有超时终态事件且详情读取失败时，也不显示已完成", async () => {
    const backend = installBackend([makeMessage("user", "检查面板")]);
    backend.runs.set(runId, makeRun());
    render(<ChatPage workspace />);
    const source = await waitForSource();
    server.use(
      http.get(
        "/api/runs/:runId",
        () => new HttpResponse(null, { status: 503 }),
      ),
    );
    act(() => {
      source.open();
      source.emit(
        "finished",
        makeEvent(1, "finished", { stop_reason: "timeout" }),
      );
    });
    expect(
      await screen.findByText("暂时没查完", { exact: true }),
    ).toBeVisible();
    expect(
      screen.queryByText("已完成", { exact: true }),
    ).not.toBeInTheDocument();
  });

  it("回答正文与程序附加的证据编号分开，编号按需查看", async () => {
    const index = `probe_service_reachability: ${toolRun2} (success)`;
    const answer = `面板目前只接受这台电脑的连接。\n\n证据索引（程序生成）：\n${index}`;
    const backend = installBackend([makeMessage("assistant", answer)]);
    backend.runs.set(runId, completedRun(answer));
    const user = userEvent.setup();
    render(<ChatPage workspace />);
    expect(
      await screen.findByText("面板目前只接受这台电脑的连接。"),
    ).toBeVisible();
    expect(screen.getByText(index, { exact: true })).not.toBeVisible();
    await user.click(screen.getByText("查看证据编号", { exact: true }));
    expect(screen.getByText(index, { exact: true })).toBeVisible();
  });

  it("不把用户输入中的证据索引文字折叠或删掉", async () => {
    const content = "我的问题\n\n证据索引（程序生成）：\n这也是问题正文";
    installBackend([makeMessage("user", content)]);
    const { container } = render(<ChatPage workspace />);
    await screen.findByRole("heading", { name: "消息" });
    expect(
      container.querySelector(".chat-message--user")?.textContent,
    ).toContain(content);
    expect(screen.queryByText("查看证据编号")).not.toBeInTheDocument();
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

    expect(await screen.findByText("本次检查已结束")).toBeVisible();
    expect(recoveredSource.closed).toBe(true);
    expect(
      screen.queryByText("正在检查，结果会区分已查明和还不能确认的部分。"),
    ).toBeNull();
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

    expect(await screen.findByText("本次检查已结束")).toBeVisible();
    expect(screen.getByLabelText("问题")).toBeEnabled();
    expect(screen.queryByRole("button", { name: "停止这次检查" })).toBeNull();
    expect(
      await screen.findByText(/已收到并应用终态事件，但暂时无法复读/),
    ).toBeVisible();
    expect(screen.queryByText("服务端已经完成", { exact: true })).toBeNull();
    expect(screen.getByText("检查已结束，暂时未取得核对结果。")).toBeVisible();
    const refresh = screen.getByRole("button", { name: "刷新这段对话" });

    failRunRead = false;
    await userEvent.setup().click(refresh);
    expect(
      await screen.findByText("这段对话和检查进展已刷新，没有重新发起检查。"),
    ).toBeVisible();
    await waitFor(() => {
      expect(
        screen.queryByText(/已收到并应用终态事件，但暂时无法复读/),
      ).toBeNull();
    });
  });

  it.each([false, true])(
    "停止请求断开后只查进展，已确认结果不再说未知（读取失败：%s）",
    async (readUnavailable) => {
      const backend = installBackend([makeMessage("user", "之前的问题")]);
      backend.serviceIds.set(threadId, program.service_id);
      backend.runs.set(runId, makeRun());
      let cancelCalls = 0;
      server.use(
        http.post("/api/runs/:id/cancel", () => {
          cancelCalls += 1;
          backend.runs.set(runId, makeRun("cancelled"));
          return HttpResponse.error();
        }),
        http.get("/api/runs/:id", () =>
          cancelCalls > 0 && readUnavailable
            ? new HttpResponse(null, { status: 503 })
            : HttpResponse.json(backend.runs.get(runId)),
        ),
      );
      render(<ChatPage workspace services={[program]} />);
      await waitForSource();
      const user = userEvent.setup();
      await user.click(screen.getByRole("button", { name: "停止这次检查" }));
      const dialog = screen.getByRole("alertdialog", {
        name: "要停止这次检查吗？",
      });
      expect(dialog.querySelector(".chat-object-id")).not.toBeVisible();
      expect(cancelCalls).toBe(0);
      await user.click(screen.getByRole("button", { name: "确认停止" }));
      if (readUnavailable) {
        expect(
          await screen.findByText(
            "还不能确认是否停止；正在查看进展，不会重复请求。",
            { exact: true },
          ),
        ).toBeVisible();
        expect(
          await screen.findByText(
            "暂时没能读全这次检查的记录，可以稍后刷新；不会重复请求停止。",
            { exact: true },
          ),
        ).toBeVisible();
      } else {
        expect(
          await screen.findByText("已停止检查。没有重复请求停止。", {
            exact: true,
          }),
        ).toBeVisible();
        expect(screen.queryByText(/还不能确认是否停止/)).toBeNull();
      }
      expect(cancelCalls).toBe(1);
      expect(screen.getByText("之前的问题", { exact: true })).toBeVisible();
      expect(screen.getByLabelText("正在讨论的程序")).toHaveTextContent("gost");
    },
  );

  it.each([false, true])(
    "浏览器切换对话后，停止请求的旧回执不串页（补读：%s）",
    async (reread) => {
      const backend = installBackend([makeMessage("user", "之前的问题")]);
      backend.threadIds.push(secondThreadId);
      backend.messages.set(secondThreadId, []);
      backend.runs.set(runId, makeRun());
      let release = () => {};
      const pending = new Promise<void>((resolve) => {
        release = resolve;
      });
      let cancelCalls = 0;
      server.use(
        http.post("/api/runs/:id/cancel", async () => {
          cancelCalls += 1;
          if (!reread) await pending;
          backend.runs.set(runId, makeRun("cancelled"));
          return reread
            ? HttpResponse.error()
            : HttpResponse.json(makeRun("cancelled"));
        }),
        http.get("/api/runs/:id", async () => {
          if (reread && cancelCalls > 0) await pending;
          return HttpResponse.json(backend.runs.get(runId));
        }),
      );
      const originalUrl = window.location.href;
      const view = render(<ChatPage workspace />);
      try {
        await waitForSource();
        const user = userEvent.setup();
        await user.click(screen.getByRole("button", { name: "停止这次检查" }));
        await user.click(screen.getByRole("button", { name: "确认停止" }));
        await waitFor(() => expect(cancelCalls).toBe(1));
        if (reread) {
          await screen.findByText(
            "还不能确认是否停止；正在查看进展，不会重复请求。",
            { exact: true },
          );
        }
        window.history.replaceState({}, "", `?thread=${secondThreadId}`);
        view.rerender(<ChatPage workspace />);
        await waitFor(() =>
          expect(
            screen.getByRole("button", { name: /继续对话 2/ }),
          ).toHaveAttribute("aria-pressed", "true"),
        );
        release();
        await waitFor(() =>
          expect(
            screen.getByRole("button", { name: "开始新对话" }),
          ).toBeEnabled(),
        );
        expect(
          screen.queryByText("已停止检查。没有重复请求停止。", { exact: true }),
        ).toBeNull();
        expect(screen.queryByText(/还不能确认是否停止/)).toBeNull();
        expect(cancelCalls).toBe(1);
      } finally {
        release();
        window.history.replaceState({}, "", originalUrl);
      }
    },
  );

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

    await user.click(screen.getByRole("button", { name: "停止这次检查" }));
    const cancelDialog = screen.getByRole("alertdialog", {
      name: "要停止这次检查吗？",
    });
    expect(cancelDialog).toHaveTextContent(runId);
    expect(cancelCalls).toBe(0);
    await user.click(screen.getByRole("button", { name: "确认停止" }));
    expect(
      await screen.findByText("本次检查已结束。没有重复请求停止。", {
        exact: true,
      }),
    ).toBeVisible();
    expect(cancelCalls).toBe(1);
    expect(source.closed).toBe(true);
    expect(screen.queryByRole("button", { name: "停止这次检查" })).toBeNull();
    secondView.unmount();
  });
});
