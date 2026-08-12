import type { RunEvent, RunStatus, RunView } from "./contracts";

export type StreamPhase =
  | "idle"
  | "connecting"
  | "open"
  | "recovering"
  | "terminal";

export interface SequenceGap {
  expected: number;
  received: number;
}

export interface RunEventState {
  runId: string | null;
  lastSequence: number;
  events: RunEvent[];
  phase: StreamPhase;
  gap: SequenceGap | null;
  terminalStatus: Exclude<RunStatus, "running"> | null;
  terminalReadFailed: boolean;
  recoveryReason:
    | "disconnect"
    | "idle-timeout"
    | "invalid-event"
    | "gap"
    | null;
}

export type RunEventAction =
  | { type: "activate"; run: RunView }
  | { type: "clear" }
  | { type: "connecting" }
  | { type: "opened" }
  | {
      type: "recovering";
      reason: Exclude<RunEventState["recoveryReason"], null>;
    }
  | { type: "event"; event: RunEvent }
  | { type: "run-read"; run: RunView }
  | { type: "terminal-read-failed" };

export const emptyRunEventState: RunEventState = {
  runId: null,
  lastSequence: 0,
  events: [],
  phase: "idle",
  gap: null,
  terminalStatus: null,
  terminalReadFailed: false,
  recoveryReason: null,
};

export function isTerminalRunStatus(
  status: RunStatus,
): status is Exclude<RunStatus, "running"> {
  return status !== "running";
}

function statusFromTerminalEvent(
  event: RunEvent,
): Exclude<RunStatus, "running"> | null {
  if (event.event_type === "failed") {
    return "failed";
  }
  if (event.event_type === "interrupted") {
    return "interrupted";
  }
  if (event.event_type === "finished") {
    return event.stop_reason === "cancelled" ? "cancelled" : "completed";
  }
  return null;
}

export function runEventReducer(
  state: RunEventState,
  action: RunEventAction,
): RunEventState {
  switch (action.type) {
    case "clear":
      return emptyRunEventState;
    case "activate": {
      const sameRun = state.runId === action.run.run_id;
      return {
        runId: action.run.run_id,
        lastSequence: sameRun ? state.lastSequence : 0,
        events: sameRun ? state.events : [],
        phase: "connecting",
        gap: sameRun ? state.gap : null,
        terminalStatus: isTerminalRunStatus(action.run.status)
          ? action.run.status
          : null,
        terminalReadFailed: sameRun ? state.terminalReadFailed : false,
        recoveryReason: null,
      };
    }
    case "connecting":
      return {
        ...state,
        phase: "connecting",
        recoveryReason: null,
      };
    case "opened":
      return {
        ...state,
        phase: "open",
        recoveryReason: null,
      };
    case "recovering":
      return {
        ...state,
        phase: "recovering",
        recoveryReason: action.reason,
      };
    case "run-read":
      if (state.runId !== action.run.run_id) {
        return state;
      }
      return isTerminalRunStatus(action.run.status)
        ? {
            ...state,
            phase: "terminal",
            terminalStatus: action.run.status,
            terminalReadFailed: false,
            recoveryReason: null,
          }
        : state;
    case "terminal-read-failed":
      if (state.terminalStatus === null) {
        return state;
      }
      return {
        ...state,
        phase: "terminal",
        terminalReadFailed: true,
        recoveryReason: null,
      };
    case "event": {
      if (state.runId !== action.event.run_id) {
        return state;
      }
      if (action.event.sequence <= state.lastSequence) {
        return state;
      }
      const expected = state.lastSequence + 1;
      if (action.event.sequence !== expected) {
        return {
          ...state,
          phase: "recovering",
          gap: { expected, received: action.event.sequence },
          recoveryReason: "gap",
        };
      }
      const terminalStatus = statusFromTerminalEvent(action.event);
      return {
        ...state,
        lastSequence: action.event.sequence,
        events: [...state.events, action.event],
        phase: terminalStatus === null ? state.phase : "terminal",
        gap: null,
        terminalStatus: terminalStatus ?? state.terminalStatus,
        terminalReadFailed: terminalStatus === null && state.terminalReadFailed,
        recoveryReason: null,
      };
    }
  }
}
