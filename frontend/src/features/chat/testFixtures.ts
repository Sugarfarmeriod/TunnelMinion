import type {
  RunEvent,
  RunStatus,
  RunView,
  ThreadMessage,
  ThreadSummary,
} from "./contracts";

export const timestamp = "2026-08-08T10:00:00+08:00";
export const threadId = "thread_f8ba7a45920b4f2b8f16309c993680b1";
export const runId = "run_1220d96035cc487ab102491376c665e7";
export const toolRun2 = "toolrun_00000000000000000000000000000002";
export const toolRun3 = "toolrun_00000000000000000000000000000003";
export class FakeEventSource {
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

export function makeThread(
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

export function makeMessage(
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

export function makeRun(
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

export function makeEvent(
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

export function completedRun(answer: string): RunView {
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
