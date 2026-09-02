import { describe, expect, it } from "vitest";

import type { RunEvent, RunStatus, RunView } from "./contracts";
import { emptyRunEventState, runEventReducer } from "./eventReducer";

const threadId = "thread_f8ba7a45920b4f2b8f16309c993680b1";
const runId = "run_1220d96035cc487ab102491376c665e7";
const otherRunId = "run_e93279a30fbd4597b9e2b755cd36629c";
const nodeId = "node_a93279a30fbd4597b9e2b755cd36629c";
const timestamp = "2026-08-08T10:00:00+08:00";

function makeRun(status: RunStatus = "running"): RunView {
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
  };
}

function makeEvent(
  sequence: number,
  eventType: RunEvent["event_type"] = "tool",
  values: Partial<RunEvent> = {},
): RunEvent {
  return {
    sequence,
    event_type: eventType,
    created_at: timestamp,
    run_id: runId,
    target_node_id: nodeId,
    tool_name: "get_node_summary",
    tool_status: "success",
    elapsed_ms: 12,
    tool_run_id: `toolrun_${sequence.toString(16).padStart(32, "0")}`,
    stop_reason: null,
    message: null,
    ...values,
  };
}

describe("runEventReducer", () => {
  it("只应用连续序号，忽略重复与其他 run 的事件，并记录缺口", () => {
    let state = runEventReducer(emptyRunEventState, {
      type: "activate",
      run: makeRun(),
    });
    state = runEventReducer(state, { type: "opened" });
    state = runEventReducer(state, { type: "event", event: makeEvent(1) });

    const afterFirst = state;
    state = runEventReducer(state, {
      type: "event",
      event: makeEvent(1, "tool", { tool_status: "duplicate" }),
    });
    expect(state).toBe(afterFirst);

    state = runEventReducer(state, {
      type: "event",
      event: makeEvent(2, "tool", { run_id: otherRunId }),
    });
    expect(state).toBe(afterFirst);

    state = runEventReducer(state, { type: "event", event: makeEvent(3) });
    expect(state).toMatchObject({
      lastSequence: 1,
      phase: "recovering",
      gap: { expected: 2, received: 3 },
      recoveryReason: "gap",
    });
    expect(state.events).toEqual([makeEvent(1)]);
  });

  it("缺口恢复后从缺失序号继续，并以服务端终态关闭", () => {
    let state = runEventReducer(emptyRunEventState, {
      type: "activate",
      run: makeRun(),
    });
    state = runEventReducer(state, { type: "event", event: makeEvent(1) });
    state = runEventReducer(state, { type: "event", event: makeEvent(3) });
    state = runEventReducer(state, { type: "opened" });
    state = runEventReducer(state, {
      type: "event",
      event: makeEvent(2, "tool", { tool_status: "failed" }),
    });

    expect(state).toMatchObject({
      lastSequence: 2,
      phase: "open",
      gap: null,
    });

    state = runEventReducer(state, {
      type: "event",
      event: makeEvent(3, "finished", {
        stop_reason: "cancelled",
        tool_name: null,
        tool_status: null,
        tool_run_id: null,
      }),
    });
    expect(state).toMatchObject({
      lastSequence: 3,
      phase: "terminal",
      terminalStatus: "cancelled",
    });
  });

  it.each([
    ["completed", "completed"],
    ["cancelled", "cancelled"],
    ["failed", "failed"],
    ["interrupted", "interrupted"],
  ] as const)("复读到 %s 终态时关闭事件流", (status, expected) => {
    let state = runEventReducer(emptyRunEventState, {
      type: "activate",
      run: makeRun(),
    });
    state = runEventReducer(state, {
      type: "run-read",
      run: makeRun(status),
    });

    expect(state.phase).toBe("terminal");
    expect(state.terminalStatus).toBe(expected);
  });

  it("终态事件后的详情复读失败不会退回 running", () => {
    let state = runEventReducer(emptyRunEventState, {
      type: "activate",
      run: makeRun(),
    });
    state = runEventReducer(state, {
      type: "event",
      event: makeEvent(1, "finished", {
        stop_reason: "completed",
        tool_name: null,
        tool_status: null,
        tool_run_id: null,
      }),
    });
    state = runEventReducer(state, { type: "terminal-read-failed" });

    expect(state).toMatchObject({
      phase: "terminal",
      terminalStatus: "completed",
      terminalReadFailed: true,
    });
  });
});
