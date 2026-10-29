import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../../api/client";
import type { ResourceOverview } from "../../api/schemas/overview";
import { isReadOnlyPreview } from "../../shared/previewMode";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { peersQueryKey, type ServiceEntry } from "../service-map/api";
import type { Repair } from "../repairs/api";
import {
  allowedToolNames,
  cancelRun,
  createThread,
  getRun,
  getThread,
  listThreads,
  startRun,
} from "./api";
import type { ConversationAbout, RunView, ThreadContext } from "./contracts";
import { emptyRunEventState, type RunEventState } from "./eventReducer";
import { ChatComposer } from "./ChatComposer";
import { MessageHistory } from "./MessageHistory";
import { RunPanel } from "./RunPanel";
import { useRunEvents } from "./useRunEvents";
import "./chat.css";

export interface ChatRequest {
  key: number;
  threadId?: string;
  about?: ConversationAbout;
  service?: ServiceEntry;
  /** 直接发出的问题，用于用户已经点选了具体问题的入口 */
  question?: string;
  /** 不自动发出、摆在输入框上方供点选的预设问题 */
  suggestions?: string[];
}

function RunSubscription({
  run,
  onUpdate,
  onSettled,
  onEvents,
}: {
  run: RunView;
  onUpdate: (run: RunView) => void;
  onSettled: (run: RunView) => void;
  onEvents: (runId: string, events: RunEventState) => void;
}) {
  const events = useRunEvents(run, {
    onRunUpdate: onUpdate,
    onRunSettled: onSettled,
  });
  useEffect(() => onEvents(run.run_id, events), [run.run_id, events, onEvents]);
  return null;
}

// 与 service-map.css 中地图让出右侧位置的断点一致
const SIDE_BY_SIDE_WIDTH = 1100;

function useSideBySide() {
  const [wide, setWide] = useState(
    () => window.innerWidth >= SIDE_BY_SIDE_WIDTH,
  );
  useEffect(() => {
    const update = () => setWide(window.innerWidth >= SIDE_BY_SIDE_WIDTH);
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);
  return wide;
}

interface DrawerDialogProps {
  children: ReactNode;
  inputRef: RefObject<HTMLTextAreaElement | null>;
  toggleRef: RefObject<HTMLButtonElement | null>;
  onClose: () => void;
}

/** 宽屏时地图让出右侧，抽屉与地图并排，不拦地图上的点击；窄屏时抽屉盖住地图，锁定焦点。 */
function DrawerDialog(props: DrawerDialogProps) {
  return useSideBySide() ? (
    <SideDrawer {...props} />
  ) : (
    <ModalDrawer {...props} />
  );
}

function SideDrawer({
  children,
  inputRef,
  toggleRef,
  onClose,
}: DrawerDialogProps) {
  useEffect(() => {
    const opener =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const toggle = toggleRef.current;
    inputRef.current?.focus();
    return () => {
      // 关闭后焦点回到打开对话的按钮；它已不在页面上时回到顶栏的对话按钮
      const target = [opener, toggle].find(
        (element) =>
          element !== null && element.isConnected && element !== document.body,
      );
      target?.focus();
    };
  }, [inputRef, toggleRef]);
  return (
    <aside
      className="conversation-drawer"
      role="dialog"
      aria-modal="false"
      aria-labelledby="drawer-title"
      tabIndex={-1}
      onKeyDown={(event) => {
        if (event.key !== "Escape") return;
        event.stopPropagation();
        event.preventDefault();
        onClose();
      }}
    >
      {children}
    </aside>
  );
}

function ModalDrawer({
  children,
  inputRef,
  toggleRef,
  onClose,
}: DrawerDialogProps) {
  const opener = useRef(
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null,
  );
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLElement>({
    initialFocusRef: inputRef,
    toggleRef,
    returnFocus: [opener.current, toggleRef.current],
    onEscape: onClose,
  });
  return (
    <aside
      ref={dialogRef}
      className="conversation-drawer"
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
      tabIndex={-1}
      onKeyDown={handleKeyDown}
    >
      {children}
    </aside>
  );
}

export function ConversationDrawer({
  open,
  onClose,
  toggleRef,
  request,
  onUnread,
  nodeId,
  services,
  nodes,
  modelStatus,
  peerServices,
  pendingRepairs = [],
  onRepair,
  onDelegationsChange,
}: {
  open: boolean;
  onClose: () => void;
  toggleRef: RefObject<HTMLButtonElement | null>;
  request: ChatRequest | null;
  onUnread: (threadId: string) => void;
  nodeId?: string;
  services: ServiceEntry[];
  nodes: { node_id: string; display_name: string }[];
  peerServices?: { node_id: string; services: ServiceEntry[] };
  modelStatus?: ResourceOverview["model"]["status"];
  pendingRepairs?: Repair[];
  onRepair?: (id: string) => void;
  onDelegationsChange?: (delegations: RunEventState["delegations"]) => void;
}) {
  const client = useQueryClient();
  const preview = isReadOnlyPreview();
  const [tab, setTab] = useState<"current" | "history">("current");
  const [selected, setSelected] = useState<string | null>(null);
  const [about, setAbout] = useState<ConversationAbout | undefined>();
  const [question, setQuestion] = useState("");
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [page, setPage] = useState(0);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [runs, setRuns] = useState<Record<string, RunView>>({});
  const [watching, setWatching] = useState<Record<string, RunView>>({});
  const [eventStates, setEventStates] = useState<Record<string, RunEventState>>(
    {},
  );
  const [confirmingCancel, setConfirmingCancel] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [below, setBelow] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const handled = useRef<number | null>(null);
  const pendingSend = useRef(false);
  const settled = useRef(new Set<string>());
  const current = useRef({ open, selected, onUnread });
  current.current = { open, selected, onUnread };

  const threads = useQuery({
    queryKey: ["chat-threads"],
    queryFn: ({ signal }) => listThreads(signal),
    enabled: open,
  });
  const detail = useQuery({
    queryKey: ["chat-thread", selected],
    queryFn: ({ signal }) => getThread(selected!, signal),
    enabled: selected !== null,
  });
  const latestRunId = detail.data?.messages.at(-1)?.run_id;
  const runQuery = useQuery({
    queryKey: ["chat-run", latestRunId],
    queryFn: ({ signal }) => getRun(latestRunId!, signal),
    enabled: latestRunId !== undefined,
  });

  const updateRun = useCallback(
    (run: RunView) => setRuns((items) => ({ ...items, [run.run_id]: run })),
    [],
  );
  const observeRun = useCallback(
    (run: RunView) => {
      updateRun(run);
      if (run.status === "running" && !settled.current.has(run.run_id)) {
        setWatching((items) =>
          items[run.run_id] ? items : { ...items, [run.run_id]: run },
        );
      }
    },
    [updateRun],
  );
  useEffect(() => {
    if (runQuery.data) observeRun(runQuery.data);
  }, [runQuery.data, observeRun]);

  const refresh = useCallback(
    (threadId: string) =>
      Promise.all([
        client.invalidateQueries({ queryKey: ["chat-thread", threadId] }),
        client.invalidateQueries({ queryKey: ["chat-threads"] }),
      ]),
    [client],
  );

  const onSettled = useCallback(
    (run: RunView) => {
      updateRun(run);
      if (!settled.current.has(run.run_id)) {
        settled.current.add(run.run_id);
        if (
          run.status === "completed" &&
          run.result &&
          (!current.current.open || current.current.selected !== run.thread_id)
        ) {
          current.current.onUnread(run.thread_id);
        }
      }
      setWatching((items) => {
        const next = { ...items };
        delete next[run.run_id];
        return next;
      });
      void refresh(run.thread_id).catch(() =>
        setNotice("回答已到，消息暂时没读全，请刷新这段对话。"),
      );
      void client.invalidateQueries({ queryKey: peersQueryKey });
    },
    [refresh, updateRun, client],
  );
  const onEvents = useCallback(
    (runId: string, events: RunEventState) =>
      setEventStates((items) => ({ ...items, [runId]: events })),
    [],
  );

  async function send(
    value: string,
    threadId: string | null,
    context?: ConversationAbout,
  ) {
    if (preview || pendingSend.current || !value.trim()) return;
    pendingSend.current = true;
    setSending(true);
    setError(null);
    setNotice(null);
    let identifier = threadId;
    try {
      if (!identifier) {
        identifier = (await createThread()).thread_id;
        setSelected(identifier);
      }
      const run = await startRun(
        identifier,
        value,
        allowedToolNames,
        undefined,
        threadId ? (detail.data?.service_id ?? undefined) : undefined,
        context,
      );
      observeRun(run);
      setQuestion("");
      setSuggestions([]);
      await refresh(identifier);
    } catch (failure) {
      const unknown =
        !(failure instanceof ApiError) ||
        failure.status === 408 ||
        failure.status === 429 ||
        failure.status >= 500;
      if (unknown) {
        setNotice("发送结果还不能确认，请刷新对话后查看；问题不会自动重发。");
        if (identifier) {
          try {
            const saved = await getThread(identifier);
            client.setQueryData(["chat-thread", identifier], saved);
            const runId = saved.messages.at(-1)?.run_id;
            if (runId) observeRun(await getRun(runId));
          } catch {
            setError("暂时无法读取对话，请稍后重试读取。");
          }
        }
      } else {
        setError(
          failure.status === 422
            ? "提问对象已不在当前清单中，请刷新地图后重试。"
            : "这次没能发送问题，请检查服务状态后重试。",
        );
      }
    } finally {
      pendingSend.current = false;
      setSending(false);
    }
  }

  useEffect(() => {
    if (!request || request.key === handled.current) return;
    handled.current = request.key;
    setTab("current");
    setSelected(request.threadId ?? null);
    setAbout(request.about);
    setQuestion("");
    setSuggestions(request.suggestions ?? []);
    setError(null);
    setNotice(null);
    setConfirmingCancel(false);
    if (request.question) void send(request.question, null, request.about);
    // 并排时抽屉已经开着，新的提问对象要把焦点带回输入框
    else inputRef.current?.focus();
  }, [request]);

  useEffect(() => {
    if (
      open &&
      tab === "current" &&
      !sending &&
      !detail.isFetching &&
      !runQuery.isFetching
    )
      inputRef.current?.focus();
  }, [open, tab, selected, sending, detail.isFetching, runQuery.isFetching]);
  useEffect(() => {
    if (!open) setConfirmingCancel(false);
  }, [open]);

  const activeRun =
    Object.values(runs)
      .filter((run) => run.thread_id === selected)
      .at(-1) ?? null;
  const events = activeRun
    ? (eventStates[activeRun.run_id] ?? emptyRunEventState)
    : emptyRunEventState;
  useEffect(() => {
    onDelegationsChange?.(events.delegations);
  }, [events.delegations, onDelegationsChange]);
  const status = events.terminalStatus ?? activeRun?.status ?? null;
  const locked =
    preview ||
    sending ||
    detail.isFetching ||
    runQuery.isFetching ||
    status === "running" ||
    (events.terminalStatus !== null && events.phase !== "terminal");
  const savedContext = detail.data?.context ?? detail.data?.thread.context;
  const context = savedContext ?? about;
  function computerName(id?: string) {
    return id === undefined || id === nodeId
      ? "这台电脑"
      : (nodes.find((node) => node.node_id === id)?.display_name ??
          "电脑名称未知");
  }
  function contextLabel(value: ConversationAbout | ThreadContext | undefined) {
    if (!value) return undefined;
    const service =
      (value.node_id === nodeId
        ? services
        : value.node_id === peerServices?.node_id
          ? peerServices.services
          : []
      ).find((item) => item.key === value.service_key) ??
      (request?.about?.node_id === value.node_id &&
      request.about.service_key === value.service_key
        ? request.service
        : undefined);
    const name = "service_name" in value ? value.service_name : service?.name;
    return (
      computerName(value.node_id) +
      (name
        ? ` · ${name}${service ? `（${{ docker: "Docker", python: "Python", program: "程序" }[service.kind]}）` : ""}`
        : "")
    );
  }
  const history = [...(threads.data ?? [])].sort(
    (a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at),
  );
  const pages = Math.max(1, Math.ceil(history.length / 20));
  const currentPage = Math.min(page, pages - 1);

  useEffect(() => {
    const scroll = scrollRef.current;
    if (!scroll) return;
    function measure() {
      if (scroll)
        setBelow(
          scroll.scrollHeight - scroll.scrollTop > scroll.clientHeight + 2,
        );
    }
    measure();
    scroll.addEventListener("scroll", measure);
    const observer = new ResizeObserver(measure);
    observer.observe(scroll);
    return () => {
      scroll.removeEventListener("scroll", measure);
      observer.disconnect();
    };
  }, [open, tab, currentPage, detail.data, events, error]);

  async function stopRun() {
    if (!activeRun || preview || cancelling) return;
    setCancelling(true);
    try {
      observeRun(await cancelRun(activeRun.run_id));
    } catch {
      setNotice("还不能确认是否停止，请刷新进展后查看。不会重复请求停止。");
    } finally {
      setCancelling(false);
      setConfirmingCancel(false);
    }
  }

  return (
    <>
      {Object.values(watching).map((run) => (
        <RunSubscription
          key={run.run_id}
          run={run}
          onUpdate={updateRun}
          onSettled={onSettled}
          onEvents={onEvents}
        />
      ))}
      {open ? (
        <DrawerDialog
          inputRef={inputRef}
          toggleRef={toggleRef}
          onClose={onClose}
        >
          <header className="drawer-heading">
            <h2 id="drawer-title">对话</h2>
            <button
              type="button"
              className="map-button"
              disabled={sending}
              onClick={() => {
                setSelected(null);
                setAbout(undefined);
                setQuestion("");
                setTab("current");
                setError(null);
                setNotice(null);
              }}
            >
              新对话
            </button>
            <button
              type="button"
              className="map-close"
              aria-label="关闭对话"
              onClick={onClose}
            >
              ×
            </button>
          </header>
          <div className="drawer-tabs" role="tablist" aria-label="对话视图">
            <button
              id="current-chat-tab"
              type="button"
              role="tab"
              aria-selected={tab === "current"}
              aria-controls="current-chat-panel"
              onClick={() => setTab("current")}
            >
              当前对话
            </button>
            <button
              id="history-chat-tab"
              type="button"
              role="tab"
              aria-selected={tab === "history"}
              aria-controls="history-chat-panel"
              onClick={() => setTab("history")}
            >
              以往对话
            </button>
          </div>
          <div className="drawer-body map-scroll" ref={scrollRef}>
            {tab === "history" ? (
              <section
                id="history-chat-panel"
                role="tabpanel"
                aria-labelledby="history-chat-tab"
              >
                {threads.isPending ? (
                  <p role="status">正在读取以往对话……</p>
                ) : null}
                {threads.isError ? (
                  <p role="alert">
                    以往对话暂时无法读取。
                    <button
                      type="button"
                      onClick={() => void threads.refetch()}
                    >
                      重试
                    </button>
                  </p>
                ) : null}
                {history.length === 0 && threads.isSuccess ? (
                  <p>还没有以往对话。</p>
                ) : null}
                <ol className="drawer-history">
                  {history
                    .slice(currentPage * 20, (currentPage + 1) * 20)
                    .map((thread) => (
                      <li key={thread.thread_id}>
                        <button
                          type="button"
                          onClick={() => {
                            setSelected(thread.thread_id);
                            setAbout(undefined);
                            setQuestion("");
                            setTab("current");
                            setError(null);
                            setNotice(null);
                          }}
                        >
                          <strong>{thread.title ?? "未命名对话"}</strong>
                          <small>
                            <time dateTime={thread.updated_at}>
                              {new Date(thread.updated_at).toLocaleString(
                                "zh-CN",
                              )}
                            </time>{" "}
                            · {computerName(thread.context?.node_id)}
                          </small>
                        </button>
                      </li>
                    ))}
                </ol>
                <nav className="map-pager" aria-label="以往对话分页">
                  <button
                    type="button"
                    className="map-button"
                    aria-label="上一页对话"
                    disabled={currentPage === 0}
                    onClick={() => setPage(currentPage - 1)}
                  >
                    ◀
                  </button>
                  <span>
                    第 {currentPage + 1} / {pages} 页
                  </span>
                  <button
                    type="button"
                    className="map-button"
                    aria-label="下一页对话"
                    disabled={currentPage === pages - 1}
                    onClick={() => setPage(currentPage + 1)}
                  >
                    ▶
                  </button>
                </nav>
              </section>
            ) : (
              <section
                id="current-chat-panel"
                role="tabpanel"
                aria-labelledby="current-chat-tab"
              >
                {!preview && modelStatus === "unconfigured" ? (
                  <p role="status">
                    还没连接模型。<Link to="/app/settings">连接模型</Link>
                  </p>
                ) : null}
                {!preview && modelStatus === "unavailable" ? (
                  <p role="status">
                    暂时联系不上模型。
                    <Link to="/app/settings">检查模型连接</Link>
                  </p>
                ) : null}
                {detail.isError ? (
                  <p role="alert">
                    暂时无法读取这段对话。
                    <button type="button" onClick={() => void detail.refetch()}>
                      重新读取对话
                    </button>
                  </p>
                ) : null}
                {selected === null ? (
                  <p className="chat-empty">
                    想了解哪个服务，或哪里用不了？直接说你的问题。
                  </p>
                ) : detail.isPending ? (
                  <p role="status">正在读取对话……</p>
                ) : (
                  <MessageHistory
                    compact
                    detail={detail.data ?? null}
                    contextLabel={contextLabel(savedContext ?? undefined)}
                    pendingRepairs={pendingRepairs.filter(
                      (repair) => repair.origin.thread_id === selected,
                    )}
                    onRepair={onRepair}
                  />
                )}
                <RunPanel
                  compact
                  activeRun={activeRun}
                  effectiveStatus={status}
                  eventState={events}
                  peerName={(id) =>
                    nodes.find((node) => node.node_id === id)?.display_name
                  }
                  cancelling={cancelling}
                  confirmingCancel={confirmingCancel}
                  continuationBlocked={false}
                  onRequestCancel={() => setConfirmingCancel(true)}
                  onDismissCancel={() => setConfirmingCancel(false)}
                  onConfirmCancel={() => void stopRun()}
                  onRefresh={() => {
                    if (selected)
                      void refresh(selected).then(() => runQuery.refetch());
                  }}
                />
              </section>
            )}
          </div>
          {/* 常驻占位，滚到底时只隐藏，避免内容跳动 */}
          <div
            className={below ? "map-scroll-hint" : "map-scroll-hint is-idle"}
            aria-hidden="true"
          >
            ▼ 下面还有
          </div>
          {error ? (
            <p className="map-error" role="alert">
              {error}
            </p>
          ) : null}
          {notice ? (
            <p className="chat-notice" role="status">
              {notice}
            </p>
          ) : null}
          {tab === "current" ? (
            <footer className="drawer-footer">
              {preview ? (
                <p role="status">预览模式只能查看已有对话，不能发送问题。</p>
              ) : null}
              {suggestions.length && !locked ? (
                <div className="chat-suggestions" aria-label="可以这样问">
                  {suggestions.map((item) => (
                    <button
                      key={item}
                      type="button"
                      className="map-button"
                      disabled={sending || detail.isError}
                      onClick={() =>
                        void send(item, selected, context ?? undefined)
                      }
                    >
                      {item}
                    </button>
                  ))}
                </div>
              ) : null}
              <ChatComposer
                inputRef={inputRef}
                question={question}
                onChange={setQuestion}
                contextLabel={contextLabel(context ?? undefined)}
                disabled={locked || detail.isError}
                sending={sending}
                onSubmit={(event) => {
                  event.preventDefault();
                  if (!locked)
                    void send(question, selected, context ?? undefined);
                }}
              />
            </footer>
          ) : null}
        </DrawerDialog>
      ) : null}
    </>
  );
}
