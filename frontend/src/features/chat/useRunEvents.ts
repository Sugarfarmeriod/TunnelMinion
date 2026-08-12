import { useCallback, useEffect, useRef, useState } from "react";

import { getRun } from "./api";
import type { RunView } from "./contracts";
import { runEventSchema } from "./contracts";
import {
  emptyRunEventState,
  isTerminalRunStatus,
  runEventReducer,
  type RunEventAction,
  type RunEventState,
} from "./eventReducer";

const eventNames = [
  "goal",
  "tool",
  "finished",
  "failed",
  "interrupted",
] as const;

interface RunEventCallbacks {
  onRunUpdate?: (run: RunView) => void;
  onRunSettled?: (run: RunView) => void;
}

interface RunEventOptions {
  idleTimeoutMs?: number;
  reconnectDelayMs?: number;
}

export function useRunEvents(
  run: RunView | null,
  callbacks: RunEventCallbacks = {},
  options: RunEventOptions = {},
): RunEventState {
  const { idleTimeoutMs = 30_000, reconnectDelayMs = 500 } = options;
  const [state, setState] = useState<RunEventState>(emptyRunEventState);
  const stateRef = useRef(state);
  const callbacksRef = useRef(callbacks);
  callbacksRef.current = callbacks;

  const apply = useCallback((action: RunEventAction) => {
    const next = runEventReducer(stateRef.current, action);
    stateRef.current = next;
    setState(next);
    return next;
  }, []);

  useEffect(() => {
    if (run === null) {
      apply({ type: "clear" });
      return;
    }
    const currentRun = run;

    const sameRun = stateRef.current.runId === currentRun.run_id;
    const alreadySettled =
      sameRun &&
      (stateRef.current.phase === "terminal" ||
        isTerminalRunStatus(currentRun.status));
    apply({ type: "activate", run: currentRun });
    if (alreadySettled) {
      apply({ type: "run-read", run: currentRun });
      return;
    }

    let disposed = false;
    let source: EventSource | null = null;
    let idleTimer: number | null = null;
    let reconnectTimer: number | null = null;
    let readController: AbortController | null = null;
    let recoveryInProgress = false;
    let terminalCatchupStarted = false;

    function clearIdleTimer() {
      if (idleTimer !== null) {
        window.clearTimeout(idleTimer);
        idleTimer = null;
      }
    }

    function closeSource() {
      clearIdleTimer();
      if (source !== null) {
        source.close();
        source = null;
      }
    }

    function scheduleIdleTimer() {
      clearIdleTimer();
      if (idleTimeoutMs <= 0) {
        return;
      }
      idleTimer = window.setTimeout(() => {
        void recover("idle-timeout");
      }, idleTimeoutMs);
    }

    function scheduleReconnect() {
      if (disposed) {
        return;
      }
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        recoveryInProgress = false;
        connect();
      }, reconnectDelayMs);
    }

    async function rereadRun(reconnectWhenRunning: boolean) {
      readController?.abort();
      readController = new AbortController();
      try {
        const latest = await getRun(currentRun.run_id, readController.signal);
        if (disposed) {
          return;
        }
        apply({ type: "run-read", run: latest });
        if (isTerminalRunStatus(latest.status)) {
          if (reconnectWhenRunning && !terminalCatchupStarted) {
            terminalCatchupStarted = true;
            apply({ type: "connecting" });
            scheduleReconnect();
            return;
          }
          finalizeTerminalRun(latest);
          return;
        }
        callbacksRef.current.onRunUpdate?.(latest);
      } catch (error) {
        if (disposed || isAbortError(error)) {
          return;
        }
        if (!reconnectWhenRunning && stateRef.current.terminalStatus !== null) {
          apply({ type: "terminal-read-failed" });
        }
      }

      if (reconnectWhenRunning) {
        scheduleReconnect();
      } else {
        recoveryInProgress = false;
      }
    }

    function finalizeTerminalRun(latest: RunView) {
      recoveryInProgress = false;
      callbacksRef.current.onRunUpdate?.(latest);
      callbacksRef.current.onRunSettled?.(latest);
    }

    async function recover(
      reason: "disconnect" | "idle-timeout" | "invalid-event" | "gap",
    ) {
      if (disposed || recoveryInProgress) {
        return;
      }
      recoveryInProgress = true;
      closeSource();
      apply({ type: "recovering", reason });
      await rereadRun(true);
    }

    function settleFromEvent() {
      if (disposed || recoveryInProgress) {
        return;
      }
      recoveryInProgress = true;
      closeSource();
      void rereadRun(false);
    }

    function receiveEvent(event: MessageEvent<string>) {
      const parsedJson = parseJson(event.data);
      const parsedEvent = runEventSchema.safeParse(parsedJson);
      if (!parsedEvent.success) {
        void recover("invalid-event");
        return;
      }

      const previous = stateRef.current;
      const next = apply({ type: "event", event: parsedEvent.data });
      if (next.gap !== null && next.gap !== previous.gap) {
        void recover("gap");
        return;
      }
      if (next.phase === "terminal") {
        settleFromEvent();
        return;
      }
      scheduleIdleTimer();
    }

    function connect() {
      if (disposed) {
        return;
      }
      closeSource();
      apply({ type: "connecting" });
      const after = stateRef.current.lastSequence;
      source = new EventSource(
        `/api/runs/${encodeURIComponent(currentRun.run_id)}/events?after=${after}`,
      );
      source.onopen = () => {
        if (disposed) {
          return;
        }
        apply({ type: "opened" });
        scheduleIdleTimer();
      };
      source.onerror = () => {
        void recover("disconnect");
      };
      for (const eventName of eventNames) {
        source.addEventListener(eventName, receiveEvent as EventListener);
      }
    }

    connect();

    return () => {
      disposed = true;
      closeSource();
      readController?.abort();
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
    };
  }, [apply, idleTimeoutMs, reconnectDelayMs, run?.run_id, run?.status]);

  return state;
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
