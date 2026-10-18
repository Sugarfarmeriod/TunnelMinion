import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { ApiError, requestJson } from "../../api/client";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { isReadOnlyPreview } from "../../shared/previewMode";

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
import type { OperationDetail, OperationSummary } from "../operations/schemas";
import {
  incidentDetailSchema,
  type ResourceOverview,
} from "../../api/schemas/overview";
import { runSchema } from "./contracts";
import { operationStatusLabel } from "../operations/operationPresentation";
import { serviceDisplayName } from "../overview/overviewActions";
import { Link } from "react-router-dom";

const toolLabels: Record<AllowedToolName, string> = {
  get_node_summary: "节点摘要",
  get_wireguard_status: "WireGuard 状态",
  list_network_listeners: "网络监听",
  get_process_summary: "进程摘要",
  list_docker_services: "Docker 服务",
  probe_service_reachability: "服务可达性探测",
};

const runStatusLabels: Record<RunStatus, string> = {
  running: "正在检查",
  completed: "本次检查已结束",
  cancelled: "已停止检查",
  failed: "这次没查完",
  interrupted: "检查被打断",
};

const failureMessages = new Map([
  ["model_authentication_failed", "模型连接没有通过验证，这次检查没能完成。"],
  ["model_not_found", "没有找到设置中的模型，这次检查没能完成。"],
  ["model_timeout", "等模型回答等得太久，这次检查先停下了。"],
  ["model_network_unreachable", "这次联系模型时遇到问题，还没查完。"],
  ["model_invalid_response", "模型这次没有给出可用的回答，检查没能完成。"],
  ["model_capability_incompatible", "当前模型还不能完成这类检查。"],
  ["tool_failed", "读取程序情况时遇到问题，这次还没查完。"],
  ["context_invalid", "检查记录暂时没能整理好，这次检查没有完成。"],
  ["summary_failed", "检查记录暂时没能整理好，这次检查没有完成。"],
  ["governance_denied", "这次检查没有获准继续。已有记录仍可查看。"],
]);

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
  workspace?: boolean;
  visible?: boolean;
  locationSearch?: string;
  serviceContext?: ResourceOverview["services"]["items"][number];
  services?: ResourceOverview["services"]["items"];
  nodes?: ResourceOverview["nodes"]["items"];
  computerName?: string;
  onThreadSelect?: (threadId: string | null) => void;
  onThreadCreated?: (threadId: string) => void;
  incidentId?: string;
  incidentThreadId?: string | null;
  operationContext?: OperationDetail;
  contextBlocked?: boolean;
  modelStatus?: ResourceOverview["model"]["status"];
  children?: ReactNode;
}

export function ChatPage({
  streamIdleTimeoutMs,
  streamReconnectDelayMs,
  workspace = false,
  visible = true,
  locationSearch = window.location.search,
  serviceContext,
  services,
  nodes,
  computerName,
  onThreadSelect,
  onThreadCreated,
  incidentId,
  incidentThreadId,
  operationContext,
  contextBlocked = false,
  modelStatus,
  children,
}: ChatPageProps = {}) {
  const readOnlyPreview = isReadOnlyPreview();
  const requestedThreadId = incidentId
    ? (incidentThreadId ?? undefined)
    : (new URLSearchParams(locationSearch).get("thread") ?? undefined);
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
  const [toolName, setToolName] = useState<AllowedToolName | "auto">(
    workspace ? "auto" : "get_node_summary",
  );
  const selectedThreadRef = useRef<string | null>(null);
  const actionControllers = useRef(new Set<AbortController>());
  const deleteButtonRef = useRef<HTMLButtonElement>(null);
  const threadsHeadingRef = useRef<HTMLHeadingElement>(null);
  const wasHidden = useRef(false);
  useEffect(() => {
    if (!visible) {
      wasHidden.current = true;
      setConfirmingDelete(false);
      setConfirmingCancel(false);
    } else if (wasHidden.current) {
      wasHidden.current = false;
      document.getElementById("chat-question")?.focus();
    }
  }, [visible]);

  const selectThread = useCallback((threadId: string | null) => {
    selectedThreadRef.current = threadId;
    setSelectedThreadId(threadId);
    setThreadDetail(null);
    setActiveRun(null);
    setConfirmingDelete(false);
    setConfirmingCancel(false);
    setPageError(null);
    setNotice(null);
  }, []);

  const refreshThreads = useCallback(
    async (signal?: AbortSignal, preferredThreadId?: string) => {
      const latest = (await listThreads(signal)).sort(
        (left, right) =>
          Date.parse(right.updated_at) - Date.parse(left.updated_at),
      );
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
    if (requestedThreadId && requestedThreadId !== selectedThreadRef.current)
      setNotice(null);
    void refreshThreads(controller.signal, requestedThreadId)
      .then(() => {
        if (!controller.signal.aborted && incidentId && !incidentThreadId)
          selectThread(null);
      })
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
  }, [
    refreshThreads,
    requestedThreadId,
    incidentId,
    incidentThreadId,
    selectThread,
  ]);

  useEffect(() => {
    if (incidentId) {
      setQuestion("");
      selectThread(incidentThreadId ?? null);
    }
  }, [incidentId, selectThread]);

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
    readOnlyPreview ||
    effectiveRunStatus === "running" ||
    terminalReplayPending;
  const programConversation =
    workspace && !incidentId && !operationContext && !contextBlocked;
  const currentDetail =
    threadDetail?.thread.thread_id === selectedThreadId ? threadDetail : null;
  const savedServiceId =
    currentDetail?.service_id === undefined &&
    activeRun?.thread_id === selectedThreadId &&
    activeRun?.run_id === currentDetail?.messages.at(-1)?.run_id &&
    activeRun?.result?.answer_checked === true
      ? activeRun.result.checked_service_id
      : currentDetail?.service_id;
  const matches = services?.filter(
    (service) => service.service_id === savedServiceId,
  );
  const restoredService =
    matches?.length === 1 && ["live", "fresh"].includes(matches[0]!.freshness)
      ? matches[0]
      : undefined;
  const selectedService = programConversation
    ? (serviceContext ?? restoredService)
    : undefined;
  const matchingComputers = nodes?.filter(
    (node) => node.node_id === selectedService?.node_id,
  );
  const selectedComputerName = serviceContext
    ? computerName
    : matchingComputers?.length === 1 &&
        ["live", "fresh"].includes(matchingComputers[0]!.freshness)
      ? matchingComputers[0]!.display_name
      : undefined;
  const programContextBlocked =
    programConversation &&
    !serviceContext &&
    selectedThreadId !== null &&
    (!currentDetail ||
      (Boolean(savedServiceId) && !restoredService) ||
      (currentDetail.service_id === undefined &&
        currentDetail.messages.length > 0 &&
        !savedServiceId));

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
      if (!controller.signal.aborted) onThreadCreated?.(created.thread_id);
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
      const remaining = await refreshThreads(controller.signal);
      if (!controller.signal.aborted)
        onThreadSelect?.(remaining[0]?.thread_id ?? null);
      setNotice("线程及其短期消息已删除，独立长期记忆未受影响。");
    } catch (error) {
      if (isUnknownWriteResult(error)) {
        setNotice("删除结果未知；已重新读取线程列表，不会自动再次删除。");
        await safelyRefreshThreads(refreshThreads, controller.signal);
        if (!controller.signal.aborted) onThreadSelect?.(null);
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
    if (
      (threadId === null && !incidentId) ||
      writeAction !== null ||
      composerLocked ||
      contextBlocked ||
      programContextBlocked
    ) {
      return;
    }
    if (normalizedQuestion.length === 0) {
      setPageError("请输入问题后再发送。");
      return;
    }
    if (normalizedQuestion.length > (incidentId ? 2000 : 20_000)) {
      setPageError(
        incidentId
          ? "针对调查的问题最多 2,000 个字符。"
          : "问题最多 20,000 个字符。",
      );
      return;
    }

    setWriteAction("start");
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      const started = incidentId
        ? await requestJson(
            `/api/incidents/${encodeURIComponent(incidentId)}/follow-up`,
            runSchema,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ question: normalizedQuestion }),
              signal: controller.signal,
            },
          )
        : await startRun(
            threadId ?? "",
            operationContext
              ? `关于正在查看的临时访问请求（服务标识“${operationContext.service_process_or_container || operationContext.service_id}”；状态“${operationStatusLabel(operationContext.state, operationContext.role)}”；申请时长 ${operationContext.duration_seconds} 秒；${operationContext.submission_result_unknown || operationContext.execution_result_unknown ? "上次请求结果仍不明确，不得建议重复提交" : "批准或执行必须由用户在请求界面确认"}）：\n${normalizedQuestion}`
              : normalizedQuestion,
            toolName === "auto" ? allowedToolNames : toolName,
            controller.signal,
            selectedService?.service_id,
          );
      if (incidentId) {
        selectThread(started.thread_id);
        setActiveRun(started);
        setQuestion("");
        await refreshThreads(controller.signal, started.thread_id);
      } else if (selectedThreadRef.current === threadId) {
        setActiveRun(started);
        setQuestion("");
      }
      await refreshThread(started.thread_id, controller.signal);
    } catch (error) {
      if (isUnknownWriteResult(error)) {
        setNotice(
          error instanceof ApiError && error.status === 503
            ? "模型服务返回不可用；写入结果仍按未知处理，正在复读当前线程，不会自动重发。"
            : "发送结果未知；正在复读当前线程，不会自动重发问题或工具调用。",
        );
        if (incidentId) {
          try {
            const latest = await requestJson(
              `/api/incidents/${encodeURIComponent(incidentId)}`,
              incidentDetailSchema,
              { signal: controller.signal },
            );
            if (latest.thread_id) {
              selectThread(latest.thread_id);
              await refreshThreads(controller.signal, latest.thread_id);
              await safelyRefreshThread(
                refreshThread,
                latest.thread_id,
                controller.signal,
              );
            }
          } catch {
            setPageError(
              "还不能确认这次追问的结果，请重新读取调查；问题没有再次发送。",
            );
          }
        } else if (threadId !== null) {
          await safelyRefreshThread(refreshThread, threadId, controller.signal);
        }
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
      setNotice("这段对话和检查进展已刷新，没有重新发起检查。");
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
    const threadId = activeRun.thread_id;
    setWriteAction("cancel");
    setNotice(null);
    setPageError(null);
    const controller = registerController(actionControllers.current);
    try {
      const latest = await cancelRun(runId, controller.signal);
      if (selectedThreadRef.current !== threadId) return;
      onRunUpdate(latest);
      setNotice(
        latest.status === "running"
          ? "已请求停止，正在等当前步骤结束。"
          : `${runStatusLabels[latest.status]}。没有重复请求停止。`,
      );
      if (latest.status !== "running") {
        await refreshThread(latest.thread_id, controller.signal);
      }
    } catch (error) {
      if (selectedThreadRef.current !== threadId) return;
      if (isUnknownWriteResult(error)) {
        setNotice("还不能确认是否停止；正在查看进展，不会重复请求。");
        try {
          const latest = await getRun(runId, controller.signal);
          if (selectedThreadRef.current !== threadId) return;
          onRunUpdate(latest);
          if (latest.status !== "running") {
            setNotice(`${runStatusLabels[latest.status]}。没有重复请求停止。`);
            await refreshThread(latest.thread_id, controller.signal);
          }
        } catch (readError) {
          if (
            !isAbortError(readError) &&
            selectedThreadRef.current === threadId
          ) {
            setPageError(
              "暂时没能读全这次检查的记录，可以稍后刷新；不会重复请求停止。",
            );
          }
        }
      } else if (!isAbortError(error)) {
        setPageError("暂时没能请求停止；请先查看检查进展，再决定是否重试。");
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
  const ThreadContainer = workspace ? "details" : "aside";

  return (
    <section aria-labelledby="chat-title" className="chat-page surface">
      {children}
      <header className="chat-page__header">
        <div>
          <p className="eyebrow">公开运行事件</p>
          <h2 id="chat-title" tabIndex={workspace ? -1 : undefined}>
            {workspace ? "一起处理" : "聊天"}
          </h2>
          {!workspace ? (
            <p>
              对话只展示公开回答与允许的只读工具轨迹，不显示隐藏推理或原始工具数据。
            </p>
          ) : null}
        </div>
        {workspace && !incidentId ? (
          <button
            className="chat-button--primary"
            disabled={readOnlyPreview || writeAction !== null}
            type="button"
            onClick={() => void handleCreateThread()}
          >
            {writeAction === "create" ? "正在开始……" : "开始新对话"}
          </button>
        ) : null}
      </header>
      {workspace && !readOnlyPreview && modelStatus === "unconfigured" ? (
        <p className="chat-alert chat-alert--warning" role="status">
          还没连接模型，目前只能看程序和处理已有请求，不会自动调查。
          <Link to="/app/settings">连接模型</Link>
        </p>
      ) : workspace && !readOnlyPreview && modelStatus === "unavailable" ? (
        <p className="chat-alert chat-alert--warning" role="status">
          暂时联系不上模型；程序和已有请求仍可查看。
          <Link to="/app/settings">检查模型连接</Link>
        </p>
      ) : null}

      {pageError === null ? null : (
        <div className="chat-alert chat-alert--error" role="alert">
          {pageError}
        </div>
      )}
      <div aria-live="polite" className="chat-notice" role="status">
        {notice}
      </div>

      <div className="chat-layout">
        <ThreadContainer
          aria-labelledby="chat-threads-title"
          className="chat-threads"
        >
          {workspace ? <summary>以往对话</summary> : null}
          <div className="chat-threads__heading">
            <h3 id="chat-threads-title" ref={threadsHeadingRef}>
              线程
            </h3>
            {!workspace ? (
              <button
                disabled={readOnlyPreview || writeAction !== null}
                type="button"
                onClick={() => void handleCreateThread()}
              >
                {writeAction === "create" ? "正在新建……" : "新建线程"}
              </button>
            ) : null}
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
                    onClick={() => {
                      if (thread.thread_id === selectedThreadRef.current)
                        void handleRefreshSelectedThread();
                      else selectThread(thread.thread_id);
                      onThreadSelect?.(thread.thread_id);
                    }}
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
            disabled={
              readOnlyPreview ||
              selectedThreadId === null ||
              writeAction !== null
            }
            type="button"
            onClick={() => setConfirmingDelete(true)}
          >
            删除所选线程
          </button>

          {visible && confirmingDelete ? (
            <DeleteThreadConfirmationDialog
              busy={writeAction !== null}
              fallbackFocus={threadsHeadingRef.current}
              onCancel={closeDeleteConfirmation}
              onConfirm={() => void handleDeleteThread()}
              returnFocus={deleteButtonRef.current}
              threadId={selectedThreadId}
            />
          ) : null}
        </ThreadContainer>

        <div className="chat-conversation">
          {selectedService ? (
            <div className="workspace-context" aria-label="正在讨论的程序">
              <strong>
                {selectedComputerName || "所属电脑名称未知"} ·{" "}
                {serviceDisplayName(selectedService) || "程序名称待确认"}
              </strong>
              <details>
                <summary>查看连接信息</summary>
                <p>
                  连接入口{" "}
                  {selectedService.protocol?.toUpperCase() ?? "协议未知"}{" "}
                  {selectedService.port ?? "未知"}
                  。下面的问题会带上这条连接记录；它不代表已经验证能使用。
                </p>
              </details>
            </div>
          ) : null}
          {programContextBlocked && !loadingThread ? (
            <p className="chat-alert chat-alert--warning" role="status">
              {savedServiceId
                ? "暂时找不到这段对话原来检查的程序，请刷新程序清单，或重新选择后再问。"
                : "还不能确认这段对话检查的是哪个程序，请刷新对话，或重新选择程序后再问。"}
            </p>
          ) : null}
          {incidentId ? (
            <p className="workspace-context">
              下面的问题会沿用上面这次调查，不需要重新解释发生了什么。
            </p>
          ) : operationContext ? (
            <p className="workspace-context">
              下面的问题会带上这条请求的状态；聊天不能替你批准或执行。
            </p>
          ) : null}
          {contextBlocked ? (
            <p role="status">
              还没读到这项任务的完整记录，暂时不能针对它提问。
            </p>
          ) : selectedThreadId === null && !incidentId ? (
            <div className="chat-empty chat-empty--large">
              <h3>
                {workspace
                  ? "想了解哪个程序，或哪里用不了？"
                  : "选择或新建线程"}
              </h3>
              <p>
                {workspace
                  ? "点“开始新对话”，然后直接说你的问题，不需要选择技术工具。"
                  : "线程记录与独立长期记忆是不同的数据。"}
              </p>
            </div>
          ) : loadingThread && selectedThreadId !== null ? (
            <p aria-live="polite">正在读取线程消息……</p>
          ) : (
            <>
              {!workspace || (threadDetail?.messages.length ?? 0) > 0 ? (
                <MessageHistory compact={workspace} detail={threadDetail} />
              ) : null}
              <RunPanel
                compact={workspace}
                activeRun={activeRun}
                effectiveStatus={effectiveRunStatus}
                eventState={eventState}
                cancelling={writeAction === "cancel"}
                confirmingCancel={visible && confirmingCancel}
                continuationBlocked={programContextBlocked}
                onRequestCancel={() => setConfirmingCancel(true)}
                onDismissCancel={() => setConfirmingCancel(false)}
                onConfirmCancel={() => void handleCancelRun()}
                onRefresh={() => void handleRefreshSelectedThread()}
              />
              <form className="chat-composer" onSubmit={handleStartRun}>
                {!workspace ? <h3>继续当前线程</h3> : null}
                <label htmlFor="chat-question">问题</label>
                <textarea
                  id="chat-question"
                  maxLength={incidentId ? 2000 : 20_000}
                  rows={workspace ? 3 : 5}
                  value={question}
                  disabled={writeAction !== null || composerLocked}
                  placeholder={
                    workspace
                      ? "例如：这个程序为什么在另一台电脑上打不开？"
                      : "例如：本机 WireGuard 和模型状态如何？"
                  }
                  onChange={(event) => setQuestion(event.currentTarget.value)}
                />
                {!workspace ||
                question.length > (incidentId ? 1800 : 18_000) ? (
                  <span className="chat-composer__count">
                    {question.length.toLocaleString("zh-CN")} /{" "}
                    {incidentId ? "2,000" : "20,000"} 字符
                  </span>
                ) : null}
                {!incidentId ? (
                  <details open={!workspace}>
                    <summary>调查工具（通常不用改）</summary>
                    <label htmlFor="chat-tool">本次允许的只读工具</label>
                    <select
                      id="chat-tool"
                      value={toolName}
                      disabled={writeAction !== null || composerLocked}
                      onChange={(event) =>
                        setToolName(
                          event.currentTarget.value as AllowedToolName | "auto",
                        )
                      }
                    >
                      {workspace ? (
                        <option value="auto">自动选择（只读）</option>
                      ) : null}
                      {allowedToolNames.map((name) => (
                        <option key={name} value={name}>
                          {toolLabels[name]}（{name}）
                        </option>
                      ))}
                    </select>
                  </details>
                ) : null}
                <button
                  className="chat-button chat-button--primary"
                  disabled={
                    writeAction !== null ||
                    composerLocked ||
                    programContextBlocked ||
                    question.trim().length === 0
                  }
                  type="submit"
                >
                  {writeAction === "start"
                    ? "正在发送……"
                    : workspace
                      ? "发送问题"
                      : "发送并开始运行"}
                </button>
                <p className="chat-composer__safety">
                  {readOnlyPreview
                    ? "当前只展示记录。发送问题和操作已停用，不会使用模型额度。"
                    : workspace
                      ? "提问会使用模型额度。任何批准或执行仍要你确认。"
                      : "网络结果未知时只复读线程与运行状态，不会自动重发问题、工具调用或取消请求。"}
                </p>
              </form>
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function MessageHistory({
  compact,
  detail,
}: {
  compact: boolean;
  detail: ThreadDetail | null;
}) {
  return (
    <section
      aria-label={compact ? "对话记录" : undefined}
      aria-labelledby={compact ? undefined : "chat-messages-title"}
      className="chat-messages"
    >
      {!compact ? <h3 id="chat-messages-title">消息</h3> : null}
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
  const unchecked =
    message.role === "assistant" && message.answer_checked !== true;
  const marker = "\n\n证据索引（程序生成）：\n";
  const index =
    message.role === "assistant" ? message.content.lastIndexOf(marker) : -1;
  return (
    <li>
      <article className={`chat-message chat-message--${message.role}`}>
        <header>
          <strong>{message.role === "user" ? "你" : "TunnelMinion"}</strong>
          <time dateTime={message.created_at}>
            {formatTimestamp(message.created_at)}
          </time>
        </header>
        {unchecked ? (
          <>
            <p>这条旧说明还没有经过事实核对，请不要据此更改设置。</p>
            <details>
              <summary>查看原始说明（未核对）</summary>
              <p className="chat-untrusted-text">{message.content}</p>
            </details>
          </>
        ) : (
          <p className="chat-untrusted-text">
            {index < 0 ? message.content : message.content.slice(0, index)}
          </p>
        )}
        {unchecked || index < 0 ? null : (
          <details>
            <summary>查看证据编号</summary>
            <p className="chat-untrusted-text">
              {message.content.slice(index + marker.length)}
            </p>
          </details>
        )}
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
      <h4 id="cancel-run-title">要停止这次检查吗？</h4>
      <p id="cancel-run-description">
        会请求停止当前检查；正在进行的步骤可能先结束，也可能刚好已经查完。已有记录会保留。
      </p>
      <details>
        <summary>技术信息</summary>
        <p className="chat-object-id">运行 ID：{runId}</p>
      </details>
      <div className="chat-actions">
        <button
          disabled={busy}
          ref={cancelRef}
          type="button"
          onClick={onCancel}
        >
          暂不停止
        </button>
        <button
          className="chat-button--danger"
          disabled={busy}
          type="button"
          onClick={onConfirm}
        >
          {busy ? "正在请求停止……" : "确认停止"}
        </button>
      </div>
    </section>
  );
}

interface RunPanelProps {
  compact?: boolean;
  activeRun: RunView | null;
  effectiveStatus: RunStatus | null;
  eventState: RunEventState;
  cancelling: boolean;
  confirmingCancel: boolean;
  continuationBlocked: boolean;
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
  compact = false,
  activeRun,
  effectiveStatus,
  eventState,
  cancelling,
  confirmingCancel,
  continuationBlocked,
  onRequestCancel,
  onDismissCancel,
  onConfirmCancel,
  onRefresh,
}: RunPanelProps) {
  const requestCancelButtonRef = useRef<HTMLButtonElement>(null);
  const runHeadingRef = useRef<HTMLHeadingElement>(null);
  const readOnlyPreview = isReadOnlyPreview();

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
  const stopReason =
    activeRun.result?.stop_reason ?? terminalEvent?.stop_reason;
  const stoppedEarly =
    effectiveStatus === "completed" && stopReason && stopReason !== "completed";
  const statusLabel = stoppedEarly
    ? stopReason === "timeout"
      ? "暂时没查完"
      : stopReason === "cancelled"
        ? "已停止检查"
        : "已达到调查上限"
    : runStatusLabels[effectiveStatus];
  const terminalMessage =
    terminalEvent?.event_type !== "finished"
      ? terminalEvent?.message
      : activeRun.result
        ? activeRun.result.answer_checked === true
          ? activeRun.result.answer
          : "这条旧说明还没有经过事实核对，请不要据此更改设置。"
        : eventState.terminalReadFailed
          ? "检查已结束，暂时未取得核对结果。"
          : "检查已结束，正在读取核对结果。";
  const reason = activeRun.failure?.reason ?? activeRun.error_code ?? "";
  const needsModelSettings =
    effectiveStatus === "failed" &&
    [
      "model_authentication_failed",
      "model_not_found",
      "model_network_unreachable",
      "model_capability_incompatible",
    ].includes(reason);
  let feedback: string | null = null;
  if (compact) {
    if (effectiveStatus === "failed") {
      feedback =
        failureMessages.get(reason) ??
        "这次检查没有完成，还不能据此判断程序是否有问题。";
    } else if (
      effectiveStatus === "cancelled" ||
      (stoppedEarly && stopReason === "cancelled")
    ) {
      feedback = "这次检查已停止，没有自动重新开始。";
    } else if (effectiveStatus === "interrupted") {
      feedback =
        "TunnelMinion重新启动时，这次检查还没结束。已有记录保留，没有自动重做。";
    } else if (stoppedEarly) {
      feedback =
        stopReason === "timeout"
          ? "这次检查用时已到上限，先停在这里。"
          : "这次检查已到用量上限，先停在这里。";
    } else if (
      effectiveStatus === "completed" &&
      !activeRun.result &&
      eventState.phase === "terminal"
    ) {
      feedback = "检查已结束，但没有读到可核对的结果。";
    }
  }
  const technicalMessage =
    effectiveStatus === "failed" || effectiveStatus === "interrupted"
      ? (terminalEvent?.message ?? activeRun.error_message)
      : null;

  return (
    <section aria-labelledby="chat-run-title" className="chat-run">
      <div className="chat-run__heading">
        <div>
          <h3 id="chat-run-title" ref={runHeadingRef} tabIndex={-1}>
            {compact ? "调查进展" : "当前运行"}
          </h3>
        </div>
        <span
          className={`chat-run-status chat-run-status--${stoppedEarly ? "bounded" : effectiveStatus}`}
        >
          {statusLabel}
        </span>
      </div>
      {feedback ? (
        <>
          <p className="chat-terminal-message" role="status">
            {feedback}
          </p>
          <p>
            {readOnlyPreview ? (
              "这是已有的检查记录，预览模式不会继续提问或重新检查。"
            ) : continuationBlocked ? (
              "先从程序列表重新选择程序，再继续问。"
            ) : (
              <>
                {needsModelSettings ? (
                  <>
                    先<Link to="/app/settings">检查模型连接</Link>，再
                  </>
                ) : null}
                <a
                  href="#chat-question"
                  onClick={(event) => {
                    event.preventDefault();
                    document.getElementById("chat-question")?.focus();
                  }}
                >
                  继续提问
                </a>
                。
              </>
            )}
            <br />
            刷新只更新已有记录，不会重新检查。
          </p>
        </>
      ) : null}
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
          disabled={readOnlyPreview || cancelling}
          type="button"
          onClick={onRequestCancel}
        >
          停止这次检查
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

      {eventState.terminalReadFailed && !feedback ? (
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
          刷新这段对话
        </button>
      )}

      <details open={!compact}>
        <summary>查看用了哪些工具与证据</summary>
        {feedback && technicalMessage ? (
          <>
            <h4>技术说明（不是程序结论）</h4>
            <p className="chat-untrusted-text">{technicalMessage}</p>
          </>
        ) : null}
        <p className="chat-run__id">运行 ID：{activeRun.run_id}</p>
        <p aria-live="polite" className="chat-stream-status">
          {streamPhaseLabels[eventState.phase]}
          {eventState.lastSequence > 0
            ? `；最后确认事件序号 ${eventState.lastSequence}`
            : ""}
        </p>
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
        {activeRun.result?.answer_checked === true &&
        activeRun.result.stop_reason === "completed" &&
        activeRun.result.evidence_answer.inferences.length > 0 ? (
          <details>
            <summary>查看模型原始说明（未核对）</summary>
            {activeRun.result.evidence_answer.inferences.map((text, index) => (
              <p className="chat-untrusted-text" key={index}>
                {text}
              </p>
            ))}
          </details>
        ) : null}
      </details>
      <RelatedOperations toolRunIds={activeRun.result?.tool_run_ids} />

      {feedback ||
      terminalMessage === null ||
      terminalMessage === undefined ||
      (compact && terminalMessage === activeRun.result?.answer) ? null : (
        <p className="chat-terminal-message chat-untrusted-text">
          {terminalMessage}
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
