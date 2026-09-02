import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { ApiError } from "../../api/client";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";

import {
  allowedToolNames,
  cancelRun,
  createThread,
  deleteThread,
  getRun,
  getThread,
  listThreads,
  startRun,
  type AllowedToolName,
} from "./api";
import "./chat.css";
import type {
  RunEvent,
  RunStatus,
  RunView,
  ThreadDetail,
  ThreadMessage,
  ThreadSummary,
} from "./contracts";
import type { RunEventState } from "./eventReducer";
import { useRunEvents } from "./useRunEvents";
import { listOperations } from "../operations/operationsApi";
import type { OperationSummary } from "../operations/schemas";

const toolLabels: Record<AllowedToolName, string> = {
  get_node_summary: "节点摘要",
  get_wireguard_status: "WireGuard 状态",
  list_network_listeners: "网络监听",
  get_process_summary: "进程摘要",
  list_docker_services: "Docker 服务",
  probe_service_reachability: "服务可达性探测",
};

const runStatusLabels: Record<RunStatus, string> = {
  running: "正在运行",
  completed: "已完成",
  cancelled: "已取消",
  failed: "运行失败",
  interrupted: "服务重启时中断",
};

const streamPhaseLabels: Record<RunEventState["phase"], string> = {
  idle: "未连接事件流",
  connecting: "正在连接公开事件流",
  open: "公开事件流已连接",
  recovering: "正在复读服务端状态并恢复事件流",
  terminal: "公开事件流已关闭",
};

type WriteAction = "create" | "delete" | "start" | "cancel" | null;

function DeleteThreadConfirmationDialog({
  busy,
  fallbackFocus,
  onCancel,
  onConfirm,
  returnFocus,
  threadId,
}: {
  busy: boolean;
  fallbackFocus: HTMLElement | null;
  onCancel: () => void;
  onConfirm: () => void;
  returnFocus: HTMLElement | null;
  threadId: string | null;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLElement>({
    escapeDisabled: busy,
    initialFocusRef: cancelRef,
    onEscape: onCancel,
    returnFocus: [returnFocus, fallbackFocus],
  });

  return (
    <section
      aria-describedby="delete-thread-description"
      aria-labelledby="delete-thread-title"
      aria-modal="true"
      className="chat-confirmation"
      ref={dialogRef}
      role="alertdialog"
      tabIndex={-1}
      onKeyDown={handleKeyDown}
    >
      <h4 id="delete-thread-title">确认删除这个线程？</h4>
      <p id="delete-thread-description">
        这会删除该线程、短期消息和所属运行；独立的长期记忆不会被删除。
      </p>
      <p className="chat-object-id">线程 ID：{threadId}</p>
      <div className="chat-actions">
        <button
          disabled={busy}
          ref={cancelRef}
          type="button"
          onClick={onCancel}
        >
          保留线程
        </button>
        <button
          className="chat-button--danger"
          disabled={busy}
          type="button"
          onClick={onConfirm}
        >
          {busy ? "正在删除……" : "确认删除"}
        </button>
      </div>
    </section>
  );
}

export interface ChatPageProps {
  streamIdleTimeoutMs?: number;
  streamReconnectDelayMs?: number;
}

export function ChatPage({
  streamIdleTimeoutMs,
  streamReconnectDelayMs,
}: ChatPageProps = {}) {
  const [threads, setThreads] = useState<ThreadSummary[]>([]);
  const [selectedThreadId, setSelectedThreadId] = useState<string | null>(null);
  const [threadDetail, setThreadDetail] = useState<ThreadDetail | null>(null);
  const [activeRun, setActiveRun] = useState<RunView | null>(null);
  const [loadingThreads, setLoadingThreads] = useState(true);
  const [loadingThread, setLoadingThread] = useState(false);
  const [pageError, setPageError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [writeAction, setWriteAction] = useState<WriteAction>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [confirmingCancel, setConfirmingCancel] = useState(false);
  const [question, setQuestion] = useState("");
  const [toolName, setToolName] = useState<AllowedToolName>("get_node_summary");
  const selectedThreadRef = useRef<string | null>(null);
  const actionControllers = useRef(new Set<AbortController>());
  const deleteButtonRef = useRef<HTMLButtonElement>(null);
  const threadsHeadingRef = useRef<HTMLHeadingElement>(null);

  const selectThread = useCallback((threadId: string | null) => {
    selectedThreadRef.current = threadId;
    setSelectedThreadId(threadId);
    setThreadDetail(null);
    setActiveRun(null);
    setConfirmingDelete(false);
    setConfirmingCancel(false);
    setPageError(null);
  }, []);

  const refreshThreads = useCallback(
    async (signal?: AbortSignal, preferredThreadId?: string) => {
      const latest = await listThreads(signal);
      if (signal?.aborted) {
        return latest;
      }
      setThreads(latest);
      setSelectedThreadId((current) => {
        const preferred = latest.some(
          (item) => item.thread_id === preferredThreadId,
        )
          ? preferredThreadId
          : undefined;
        const retained = latest.some((item) => item.thread_id === current)
          ? current
          : null;
        const next = preferred ?? retained ?? latest[0]?.thread_id ?? null;
        selectedThreadRef.current = next;
        return next;
      });
      return latest;
    },
    [],
  );

  const refreshThread = useCallback(
    async (threadId: string, signal?: AbortSignal) => {
      const detail = await getThread(threadId, signal);
      if (signal?.aborted || selectedThreadRef.current !== threadId) {
        return;
      }
      setThreadDetail(detail);
      const latestMessage = detail.messages.at(-1);
      if (latestMessage === undefined) {
        setActiveRun(null);
        return;
      }
      try {
        const latestRun = await getRun(latestMessage.run_id, signal);
        if (!signal?.aborted && selectedThreadRef.current === threadId) {
          setActiveRun(latestRun);
        }
      } catch (error) {
        if (!isAbortError(error) && selectedThreadRef.current === threadId) {
          setActiveRun((current) =>
            current?.run_id === latestMessage.run_id ? current : null,
          );
        }
      }
    },
    [],
  );

  useEffect(() => {
    const controller = new AbortController();
    setLoadingThreads(true);
    void refreshThreads(controller.signal)
      .catch((error: unknown) => {
        if (!isAbortError(error)) {
          setPageError("无法读取聊天线程，请确认 TunnelMinion 仍在运行。");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoadingThreads(false);
        }
      });
    return () => controller.abort();
  }, [refreshThreads]);

  useEffect(() => {
    if (selectedThreadId === null) {
      setThreadDetail(null);
      setActiveRun(null);
      return;
    }
    selectedThreadRef.current = selectedThreadId;
    const controller = new AbortController();
    setLoadingThread(true);
    void refreshThread(selectedThreadId, controller.signal)
      .catch((error: unknown) => {
        if (!isAbortError(error)) {
          setPageError("无法读取所选线程，请刷新线程列表后重试。");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoadingThread(false);
        }
      });
    return () => controller.abort();
  }, [refreshThread, selectedThreadId]);

  useEffect(
    () => () => {
      for (const controller of actionControllers.current) {
        controller.abort();
      }
      actionControllers.current.clear();
    },
    [],
  );

  const onRunUpdate = useCallback((run: RunView) => {
    if (selectedThreadRef.current === run.thread_id) {
      setActiveRun(run);
    }
  }, []);

  const onRunSettled = useCallback(
    (run: RunView) => {
      if (selectedThreadRef.current !== run.thread_id) {
        return;
      }
      setActiveRun(run);
      const controller = registerController(actionControllers.current);
      void Promise.all([
        refreshThread(run.thread_id, controller.signal),
        refreshThreads(controller.signal, run.thread_id),
      ]).finally(() => actionControllers.current.delete(controller));
    },
    [refreshThread, refreshThreads],
  );

  const eventState = useRunEvents(
    activeRun,
    { onRunUpdate, onRunSettled },
    {
      idleTimeoutMs: streamIdleTimeoutMs,
      reconnectDelayMs: streamReconnectDelayMs,
    },
  );
  const effectiveRunStatus =
    eventState.terminalStatus ?? activeRun?.status ?? null;
  const terminalReplayPending =
    eventState.terminalStatus !== null && eventState.phase !== "terminal";
  const composerLocked =
    effectiveRunStatus === "running" || terminalReplayPending;

  async function handleCreateThread() {
    if (writeAction !== null) {
      return;
    }
    setWriteAction("create");
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      const created = await createThread(controller.signal);
      await refreshThreads(controller.signal, created.thread_id);
      setNotice("新线程已创建，可以开始提问。");
    } catch (error) {
      if (isUnknownWriteResult(error)) {
        setNotice("新建线程的结果未知；已重新读取线程列表，不会自动再次新建。");
        await safelyRefreshThreads(refreshThreads, controller.signal);
      } else if (!isAbortError(error)) {
        setPageError("无法新建线程，请确认服务状态后再手动重试。");
      }
    } finally {
      actionControllers.current.delete(controller);
      if (!controller.signal.aborted) {
        setWriteAction(null);
      }
    }
  }

  async function handleDeleteThread() {
    const threadId = selectedThreadRef.current;
    if (threadId === null || writeAction !== null) {
      return;
    }
    setWriteAction("delete");
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      await deleteThread(threadId, controller.signal);
      selectThread(null);
      await refreshThreads(controller.signal);
      setNotice("线程及其短期消息已删除，独立长期记忆未受影响。");
    } catch (error) {
      if (isUnknownWriteResult(error)) {
        setNotice("删除结果未知；已重新读取线程列表，不会自动再次删除。");
        await safelyRefreshThreads(refreshThreads, controller.signal);
      } else if (!isAbortError(error)) {
        setPageError("删除失败；请重新读取线程状态后再决定是否重试。");
      }
    } finally {
      actionControllers.current.delete(controller);
      setConfirmingDelete(false);
      if (!controller.signal.aborted) {
        setWriteAction(null);
      }
    }
  }

  async function handleStartRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const threadId = selectedThreadRef.current;
    const normalizedQuestion = question.trim();
    if (threadId === null || writeAction !== null || composerLocked) {
      return;
    }
    if (normalizedQuestion.length === 0) {
      setPageError("请输入问题后再发送。");
      return;
    }
    if (normalizedQuestion.length > 20_000) {
      setPageError("问题最多 20,000 个字符。");
      return;
    }

    setWriteAction("start");
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      const started = await startRun(
        threadId,
        normalizedQuestion,
        toolName,
        controller.signal,
      );
      if (selectedThreadRef.current === threadId) {
        setActiveRun(started);
        setQuestion("");
      }
      await refreshThread(threadId, controller.signal);
      setNotice("运行已发起，下面只展示服务端公开的状态和工具证据。");
    } catch (error) {
      if (isUnknownWriteResult(error)) {
        setNotice(
          error instanceof ApiError && error.status === 503
            ? "模型服务返回不可用；写入结果仍按未知处理，正在复读当前线程，不会自动重发。"
            : "发送结果未知；正在复读当前线程，不会自动重发问题或工具调用。",
        );
        await safelyRefreshThread(refreshThread, threadId, controller.signal);
      } else if (!isAbortError(error)) {
        setPageError("无法发起运行；请检查输入和服务状态后再手动重试。");
      }
    } finally {
      actionControllers.current.delete(controller);
      if (!controller.signal.aborted) {
        setWriteAction(null);
      }
    }
  }

  async function handleRefreshSelectedThread() {
    const threadId = selectedThreadRef.current;
    if (threadId === null || writeAction !== null) {
      return;
    }
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      await Promise.all([
        refreshThread(threadId, controller.signal),
        refreshThreads(controller.signal, threadId),
      ]);
      setNotice("已通过只读请求重新读取线程与运行状态。");
    } catch (error) {
      if (!isAbortError(error)) {
        setPageError("仍无法读取线程状态；不会因此重发任何写请求。");
      }
    } finally {
      actionControllers.current.delete(controller);
    }
  }

  async function handleCancelRun() {
    if (
      activeRun === null ||
      activeRun.status !== "running" ||
      writeAction !== null
    ) {
      return;
    }
    const runId = activeRun.run_id;
    setWriteAction("cancel");
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      const latest = await cancelRun(runId, controller.signal);
      onRunUpdate(latest);
      setNotice(
        latest.status === "running"
          ? "取消请求已送达，正在等待服务端终态。"
          : `运行状态：${runStatusLabels[latest.status]}；不会再次发送取消请求。`,
      );
      if (latest.status !== "running") {
        await refreshThread(latest.thread_id, controller.signal);
      }
    } catch (error) {
      if (isUnknownWriteResult(error)) {
        setNotice("取消结果未知；正在复读同一运行，不会自动再次发送取消请求。");
        try {
          const latest = await getRun(runId, controller.signal);
          onRunUpdate(latest);
          if (latest.status !== "running") {
            await refreshThread(latest.thread_id, controller.signal);
          }
        } catch (readError) {
          if (!isAbortError(readError)) {
            setPageError("暂时也无法读取运行状态，请稍后手动刷新线程。");
          }
        }
      } else if (!isAbortError(error)) {
        setPageError("无法请求取消；请重新读取运行状态后再决定是否重试。");
      }
    } finally {
      actionControllers.current.delete(controller);
      setConfirmingCancel(false);
      if (!controller.signal.aborted) {
        setWriteAction(null);
      }
    }
  }

  function closeDeleteConfirmation() {
    setConfirmingDelete(false);
  }

  return (
    <section aria-labelledby="chat-title" className="chat-page surface">
      <header className="chat-page__header">
        <div>
          <p className="eyebrow">公开运行事件</p>
          <h2 id="chat-title">聊天</h2>
          <p>
            对话只展示公开回答与允许的只读工具轨迹，不显示隐藏推理或原始工具数据。
          </p>
        </div>
      </header>

      {pageError === null ? null : (
        <div className="chat-alert chat-alert--error" role="alert">
          {pageError}
        </div>
      )}
      <div aria-live="polite" className="chat-notice" role="status">
        {notice}
      </div>

      <div className="chat-layout">
        <aside aria-labelledby="chat-threads-title" className="chat-threads">
          <div className="chat-threads__heading">
            <h3 id="chat-threads-title" ref={threadsHeadingRef}>
              线程
            </h3>
            <button
              disabled={writeAction !== null}
              type="button"
              onClick={() => void handleCreateThread()}
            >
              {writeAction === "create" ? "正在新建……" : "新建线程"}
            </button>
          </div>

          {loadingThreads ? (
            <p>正在读取线程……</p>
          ) : threads.length === 0 ? (
            <p className="chat-empty">还没有线程。新建一个线程后即可提问。</p>
          ) : (
            <ol className="chat-thread-list">
              {threads.map((thread, index) => (
                <li key={thread.thread_id}>
                  <button
                    aria-pressed={thread.thread_id === selectedThreadId}
                    className="chat-thread-list__button"
                    type="button"
                    onClick={() => selectThread(thread.thread_id)}
                  >
                    <strong>继续对话 {index + 1}</strong>
                    <span>{thread.message_count} 条消息</span>
                    <span>{formatTimestamp(thread.updated_at)}</span>
                  </button>
                </li>
              ))}
            </ol>
          )}

          <button
            ref={deleteButtonRef}
            className="chat-button chat-button--danger"
            disabled={selectedThreadId === null || writeAction !== null}
            type="button"
            onClick={() => setConfirmingDelete(true)}
          >
            删除所选线程
          </button>

          {confirmingDelete ? (
            <DeleteThreadConfirmationDialog
              busy={writeAction !== null}
              fallbackFocus={threadsHeadingRef.current}
              onCancel={closeDeleteConfirmation}
              onConfirm={() => void handleDeleteThread()}
              returnFocus={deleteButtonRef.current}
              threadId={selectedThreadId}
            />
          ) : null}
        </aside>

        <div className="chat-conversation">
          {selectedThreadId === null ? (
            <div className="chat-empty chat-empty--large">
              <h3>选择或新建线程</h3>
              <p>线程记录与独立长期记忆是不同的数据。</p>
            </div>
          ) : loadingThread ? (
            <p aria-live="polite">正在读取线程消息……</p>
          ) : (
            <>
              <MessageHistory detail={threadDetail} />
              <RunPanel
                activeRun={activeRun}
                effectiveStatus={effectiveRunStatus}
                eventState={eventState}
                cancelling={writeAction === "cancel"}
                confirmingCancel={confirmingCancel}
                onRequestCancel={() => setConfirmingCancel(true)}
                onDismissCancel={() => setConfirmingCancel(false)}
                onConfirmCancel={() => void handleCancelRun()}
                onRefresh={() => void handleRefreshSelectedThread()}
              />
              <form className="chat-composer" onSubmit={handleStartRun}>
                <h3>继续当前线程</h3>
                <label htmlFor="chat-question">问题</label>
                <textarea
                  id="chat-question"
                  maxLength={20_000}
                  rows={5}
                  value={question}
                  disabled={writeAction !== null || composerLocked}
                  placeholder="例如：本机 WireGuard 和模型状态如何？"
                  onChange={(event) => setQuestion(event.currentTarget.value)}
                />
                <span className="chat-composer__count">
                  {question.length.toLocaleString("zh-CN")} / 20,000 字符
                </span>
                <label htmlFor="chat-tool">本次允许的只读工具</label>
                <select
                  id="chat-tool"
                  value={toolName}
                  disabled={writeAction !== null || composerLocked}
                  onChange={(event) =>
                    setToolName(event.currentTarget.value as AllowedToolName)
                  }
                >
                  {allowedToolNames.map((name) => (
                    <option key={name} value={name}>
                      {toolLabels[name]}（{name}）
                    </option>
                  ))}
                </select>
                <button
                  className="chat-button chat-button--primary"
                  disabled={
                    writeAction !== null ||
                    composerLocked ||
                    question.trim().length === 0
                  }
                  type="submit"
                >
                  {writeAction === "start" ? "正在发送……" : "发送并开始运行"}
                </button>
                <p className="chat-composer__safety">
                  网络结果未知时只复读线程与运行状态，不会自动重发问题、工具调用或取消请求。
                </p>
              </form>
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function MessageHistory({ detail }: { detail: ThreadDetail | null }) {
  return (
    <section aria-labelledby="chat-messages-title" className="chat-messages">
      <h3 id="chat-messages-title">消息</h3>
      {detail === null || detail.messages.length === 0 ? (
        <p className="chat-empty">这个线程还没有消息。</p>
      ) : (
        <ol>
          {detail.messages.map((message, index) => (
            <MessageItem
              key={`${message.run_id}-${message.role}-${index}`}
              message={message}
            />
          ))}
        </ol>
      )}
    </section>
  );
}

function MessageItem({ message }: { message: ThreadMessage }) {
  return (
    <li>
      <article className={`chat-message chat-message--${message.role}`}>
        <header>
          <strong>{message.role === "user" ? "你" : "TunnelMinion"}</strong>
          <time dateTime={message.created_at}>
            {formatTimestamp(message.created_at)}
          </time>
        </header>
        <p className="chat-untrusted-text">{message.content}</p>
      </article>
    </li>
  );
}

function CancelRunConfirmationDialog({
  busy,
  fallbackFocus,
  onCancel,
  onConfirm,
  returnFocus,
  runId,
}: {
  busy: boolean;
  fallbackFocus: HTMLElement | null;
  onCancel: () => void;
  onConfirm: () => void;
  returnFocus: HTMLElement | null;
  runId: string;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLElement>({
    escapeDisabled: busy,
    initialFocusRef: cancelRef,
    onEscape: onCancel,
    returnFocus: [returnFocus, fallbackFocus],
  });

  return (
    <section
      aria-describedby="cancel-run-description"
      aria-labelledby="cancel-run-title"
      aria-modal="true"
      className="chat-confirmation"
      ref={dialogRef}
      role="alertdialog"
      tabIndex={-1}
      onKeyDown={handleKeyDown}
    >
      <h4 id="cancel-run-title">确认取消这次运行？</h4>
      <p id="cancel-run-description">
        只会请求取消下面这一项运行；服务端终态仍可能是已完成。
      </p>
      <p className="chat-object-id">运行 ID：{runId}</p>
      <div className="chat-actions">
        <button
          disabled={busy}
          ref={cancelRef}
          type="button"
          onClick={onCancel}
        >
          返回运行
        </button>
        <button
          className="chat-button--danger"
          disabled={busy}
          type="button"
          onClick={onConfirm}
        >
          {busy ? "正在请求取消……" : "确认取消此运行"}
        </button>
      </div>
    </section>
  );
}

interface RunPanelProps {
  activeRun: RunView | null;
  effectiveStatus: RunStatus | null;
  eventState: RunEventState;
  cancelling: boolean;
  confirmingCancel: boolean;
  onRequestCancel: () => void;
  onDismissCancel: () => void;
  onConfirmCancel: () => void;
  onRefresh: () => void;
}

function RelatedOperations({
  toolRunIds,
}: {
  toolRunIds: string[] | undefined;
}) {
  const [operations, setOperations] = useState<OperationSummary[]>([]);

  useEffect(() => {
    if (toolRunIds === undefined || toolRunIds.length === 0) {
      setOperations([]);
      return;
    }
    let current = true;
    const ids = new Set(toolRunIds);
    void listOperations()
      .then((items) => {
        if (current) {
          setOperations(
            items.filter((item) => item.tool_run_ids.some((id) => ids.has(id))),
          );
        }
      })
      .catch(() => {
        if (current) {
          setOperations([]);
        }
      });
    return () => {
      current = false;
    };
  }, [toolRunIds]);

  if (operations.length === 0) {
    return null;
  }
  return (
    <div className="chat-evidence">
      <h4>相关操作</h4>
      <ul>
        {operations.map((operation) => (
          <li key={operation.operation_id}>
            <a
              href={`/app/operations/${encodeURIComponent(operation.operation_id)}`}
            >
              {operation.tool_name} · {operation.status}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

function RunPanel({
  activeRun,
  effectiveStatus,
  eventState,
  cancelling,
  confirmingCancel,
  onRequestCancel,
  onDismissCancel,
  onConfirmCancel,
  onRefresh,
}: RunPanelProps) {
  const requestCancelButtonRef = useRef<HTMLButtonElement>(null);
  const runHeadingRef = useRef<HTMLHeadingElement>(null);

  if (activeRun === null || effectiveStatus === null) {
    return null;
  }
  const toolEvents = eventState.events.filter(
    (event): event is RunEvent => event.event_type === "tool",
  );
  const terminalEvent = [...eventState.events]
    .reverse()
    .find(
      (event: RunEvent) =>
        event.event_type === "finished" ||
        event.event_type === "failed" ||
        event.event_type === "interrupted",
    );
  const evidence = activeRun.result?.evidence_answer.evidence ?? [];

  return (
    <section aria-labelledby="chat-run-title" className="chat-run">
      <div className="chat-run__heading">
        <div>
          <h3 id="chat-run-title" ref={runHeadingRef}>
            当前运行
          </h3>
          <p className="chat-run__id">运行 ID：{activeRun.run_id}</p>
        </div>
        <span className={`chat-run-status chat-run-status--${effectiveStatus}`}>
          {runStatusLabels[effectiveStatus]}
        </span>
      </div>
      <p aria-live="polite" className="chat-stream-status">
        {streamPhaseLabels[eventState.phase]}
        {eventState.lastSequence > 0
          ? `；最后确认事件序号 ${eventState.lastSequence}`
          : ""}
      </p>
      {eventState.gap === null ? null : (
        <p className="chat-alert chat-alert--warning" role="alert">
          检测到事件缺口：期望序号 {eventState.gap.expected}，收到序号{" "}
          {eventState.gap.received}
          。缺口事件未应用，正在从最后确认序号恢复。
        </p>
      )}
      {effectiveStatus === "running" ? (
        <button
          ref={requestCancelButtonRef}
          className="chat-button chat-button--secondary"
          disabled={cancelling}
          type="button"
          onClick={onRequestCancel}
        >
          取消这次运行
        </button>
      ) : null}
      {effectiveStatus === "running" && confirmingCancel ? (
        <CancelRunConfirmationDialog
          busy={cancelling}
          fallbackFocus={runHeadingRef.current}
          onCancel={onDismissCancel}
          onConfirm={onConfirmCancel}
          returnFocus={requestCancelButtonRef.current}
          runId={activeRun.run_id}
        />
      ) : null}

      {eventState.terminalReadFailed ? (
        <p className="chat-alert chat-alert--warning" role="alert">
          已收到并应用终态事件，但暂时无法复读最终 run
          详情。页面不会重放写请求；可使用下面的只读刷新。
        </p>
      ) : null}
      {effectiveStatus === "running" ? null : (
        <button
          className="chat-button chat-button--secondary"
          type="button"
          onClick={onRefresh}
        >
          重新读取线程
        </button>
      )}

      <h4>公开工具轨迹</h4>
      {toolEvents.length === 0 ? (
        <p className="chat-empty">还没有公开工具事件。</p>
      ) : (
        <ol className="chat-tool-events">
          {toolEvents.map((event) => (
            <li key={event.sequence}>
              <dl>
                <div>
                  <dt>序号</dt>
                  <dd>{event.sequence}</dd>
                </div>
                <div>
                  <dt>目标节点</dt>
                  <dd className="chat-untrusted-text">
                    {event.target_node_id ?? "服务端未提供"}
                  </dd>
                </div>
                <div>
                  <dt>工具</dt>
                  <dd className="chat-untrusted-text">
                    {event.tool_name ?? "服务端未提供"}
                  </dd>
                </div>
                <div>
                  <dt>状态</dt>
                  <dd className="chat-untrusted-text">
                    {event.tool_status ?? "未知"}
                  </dd>
                </div>
                <div>
                  <dt>耗时</dt>
                  <dd>
                    {event.elapsed_ms === null
                      ? "未知"
                      : `${Math.round(event.elapsed_ms)} ms`}
                  </dd>
                </div>
                <div>
                  <dt>工具运行 ID / 证据引用</dt>
                  <dd className="chat-untrusted-text">
                    {event.tool_run_id ?? "未提供"}
                  </dd>
                </div>
              </dl>
            </li>
          ))}
        </ol>
      )}

      {evidence.length === 0 ? null : (
        <div className="chat-evidence">
          <h4>最终回答引用的证据</h4>
          <ul>
            {evidence.map((item) => (
              <li key={item.tool_run_id} className="chat-untrusted-text">
                {item.tool_name} · {item.status} · {item.tool_run_id}
              </li>
            ))}
          </ul>
        </div>
      )}

      <RelatedOperations toolRunIds={activeRun.result?.tool_run_ids} />

      {terminalEvent?.message === null ||
      terminalEvent?.message === undefined ? null : (
        <p className="chat-terminal-message chat-untrusted-text">
          {terminalEvent.message}
        </p>
      )}
    </section>
  );
}

function registerController(controllers: Set<AbortController>) {
  const controller = new AbortController();
  controllers.add(controller);
  return controller;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function isUnknownWriteResult(error: unknown): boolean {
  if (isAbortError(error)) {
    return false;
  }
  if (!(error instanceof ApiError)) {
    return true;
  }
  return error.status === 408 || error.status === 429 || error.status >= 500;
}

async function safelyRefreshThreads(
  refresh: (signal?: AbortSignal) => Promise<ThreadSummary[]>,
  signal: AbortSignal,
) {
  try {
    await refresh(signal);
  } catch (error) {
    if (!isAbortError(error)) {
      return;
    }
  }
}

async function safelyRefreshThread(
  refresh: (threadId: string, signal?: AbortSignal) => Promise<void>,
  threadId: string,
  signal: AbortSignal,
) {
  try {
    await refresh(threadId, signal);
  } catch (error) {
    if (!isAbortError(error)) {
      return;
    }
  }
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}
