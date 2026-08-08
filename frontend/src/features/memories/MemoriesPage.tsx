import { useQuery } from "@tanstack/react-query";
import type { FormEvent, KeyboardEvent, ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import { ApiError } from "../../api/client";

import {
  clearMemoryScope,
  deleteMemory,
  getMemories,
  nodeIdSchema,
  reviseMemory,
} from "./api";
import type { LongTermMemory, MemoryScope, ReviseMemoryInput } from "./api";
import "./memories.css";

const kindLabels: Record<LongTermMemory["kind"], string> = {
  "node-alias": "节点别名",
  preference: "偏好",
  "security-constraint": "安全约束",
  "stable-service-fact": "稳定服务事实",
};

interface Notice {
  kind: "success" | "warning" | "error";
  message: string;
}

interface EditState {
  memory: LongTermMemory;
  content: string;
  source: string;
  returnFocus: HTMLElement | null;
}

type Confirmation =
  | {
      kind: "revise";
      memory: LongTermMemory;
      input: ReviseMemoryInput;
      returnFocus: HTMLElement | null;
    }
  | {
      kind: "delete";
      memory: LongTermMemory;
      returnFocus: HTMLElement | null;
    }
  | {
      kind: "clear";
      scope: MemoryScope;
      returnFocus: HTMLElement | null;
    };

function formatTimestamp(value: string | null): string {
  if (value === null) {
    return "没有期限";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function scopeLabel(scope: MemoryScope): string {
  return `用户“${scope.user}” / 网络“${scope.network}” / 节点“${scope.nodeId}”`;
}

function returnedScopeLabel(memory: LongTermMemory): string {
  const scope = memory.namespace;
  return `用户“${scope.user}” / 网络“${scope.network}” / 节点“${scope.node_id}” / 任务“${scope.task_type}” / 安全域“${scope.security_scope}”`;
}

function readableError(error: unknown): string {
  if (error instanceof ApiError) {
    return `${error.message}（${error.code}）`;
  }
  if (error instanceof Error && error.name === "ZodError") {
    return "服务返回的记忆数据不符合契约，页面不会猜测或跨作用域展示。";
  }
  return "无法读取长期记忆，请确认本机 TunnelMinion 仍在运行。";
}

function canReceiveRestoredFocus(target: HTMLElement | null): boolean {
  return (
    target !== null &&
    target.isConnected &&
    !target.matches(":disabled, [aria-disabled='true']")
  );
}

function ConfirmationDialog({
  title,
  description,
  confirmLabel,
  busy,
  returnFocus,
  fallbackFocus,
  safeFallbackFocus,
  onCancel,
  onConfirm,
}: {
  title: string;
  description: ReactNode;
  confirmLabel: string;
  busy: boolean;
  returnFocus: HTMLElement | null;
  fallbackFocus: HTMLElement | null;
  safeFallbackFocus: HTMLElement | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
    return () => {
      const target = [returnFocus, fallbackFocus, safeFallbackFocus].find(
        canReceiveRestoredFocus,
      );
      target?.focus();
    };
  }, [fallbackFocus, returnFocus, safeFallbackFocus]);

  function keepFocusInside(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape" && !busy) {
      event.preventDefault();
      onCancel();
      return;
    }
    if (event.key !== "Tab") {
      return;
    }
    const controls = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>(
        "button:not([disabled]), [href], input:not([disabled]), textarea:not([disabled])",
      ) ?? [],
    );
    const first = controls[0];
    const last = controls.at(-1);
    if (first === undefined || last === undefined) {
      return;
    }
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="memory-dialog-backdrop">
      <div
        aria-describedby="memory-confirm-description"
        aria-labelledby="memory-confirm-title"
        aria-modal="true"
        className="memory-dialog"
        onKeyDown={keepFocusInside}
        ref={dialogRef}
        role="dialog"
      >
        <h3 id="memory-confirm-title">{title}</h3>
        <div id="memory-confirm-description">{description}</div>
        <div className="memory-dialog__actions">
          <button
            disabled={busy}
            onClick={onCancel}
            ref={cancelRef}
            type="button"
          >
            取消
          </button>
          <button
            className="memory-button--danger"
            disabled={busy}
            onClick={onConfirm}
            type="button"
          >
            {busy ? "正在提交一次请求……" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function MemoryEditor({
  state,
  disabled,
  onCancel,
  onChange,
  onReview,
}: {
  state: EditState;
  disabled: boolean;
  onCancel: () => void;
  onChange: (next: EditState) => void;
  onReview: (returnFocus: HTMLElement | null) => void;
}) {
  const contentRef = useRef<HTMLTextAreaElement>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    contentRef.current?.focus();
  }, []);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (state.content.trim() === "" || state.source.trim() === "") {
      setValidationError("内容和来源都不能为空。请修正后再检查。 ");
      contentRef.current?.focus();
      return;
    }
    setValidationError(null);
    onReview(document.activeElement as HTMLElement | null);
  }

  return (
    <form className="memory-editor" onSubmit={submit}>
      <p className="memory-editor__scope">
        修正只会留在原作用域：{returnedScopeLabel(state.memory)}
      </p>
      <label>
        记忆内容
        <textarea
          disabled={disabled}
          maxLength={20_000}
          onChange={(event) =>
            onChange({ ...state, content: event.currentTarget.value })
          }
          ref={contentRef}
          required
          rows={5}
          value={state.content}
        />
      </label>
      <label>
        来源说明
        <input
          disabled={disabled}
          maxLength={2_000}
          onChange={(event) =>
            onChange({ ...state, source: event.currentTarget.value })
          }
          required
          value={state.source}
        />
      </label>
      {validationError === null ? null : (
        <p className="memory-inline-error" role="alert">
          {validationError}
        </p>
      )}
      <div className="memory-actions">
        <button disabled={disabled} type="submit">
          检查并确认修正
        </button>
        <button disabled={disabled} onClick={onCancel} type="button">
          取消编辑
        </button>
      </div>
    </form>
  );
}

export function MemoriesPage() {
  const [scopeDraft, setScopeDraft] = useState<MemoryScope>({
    user: "local-user",
    network: "home",
    nodeId: "",
  });
  const [activeScope, setActiveScope] = useState<MemoryScope | null>(null);
  const [scopeError, setScopeError] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [editState, setEditState] = useState<EditState | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [writing, setWriting] = useState(false);
  const refreshRef = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const query = useQuery({
    queryKey: [
      "memories",
      activeScope?.user,
      activeScope?.network,
      activeScope?.nodeId,
    ],
    queryFn: () => {
      if (activeScope === null) {
        return Promise.resolve([]);
      }
      return getMemories(activeScope);
    },
    enabled: activeScope !== null,
    retry: false,
  });

  function chooseScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const next = {
      user: scopeDraft.user.trim(),
      network: scopeDraft.network.trim(),
      nodeId: scopeDraft.nodeId.trim(),
    };
    if (next.user === "" || next.network === "" || next.nodeId === "") {
      setScopeError("用户、网络和节点 ID 都必须填写，才能精确读取作用域。 ");
      return;
    }
    if (!nodeIdSchema.safeParse(next.nodeId).success) {
      setScopeError("节点 ID 必须是 node_ 加 32 位小写十六进制字符。 ");
      return;
    }
    setScopeError(null);
    setNotice(null);
    setEditState(null);
    setActiveScope(next);
  }

  function cancelEditing() {
    const target = editState?.returnFocus;
    setEditState(null);
    window.setTimeout(() => target?.focus(), 0);
  }

  async function confirmWrite() {
    if (confirmation === null || activeScope === null || writing) {
      return;
    }
    setWriting(true);
    setNotice(null);

    if (confirmation.kind === "revise") {
      let response: LongTermMemory | undefined;
      let requestError: unknown;
      try {
        response = await reviseMemory(
          confirmation.memory.memory_id,
          confirmation.input,
        );
      } catch (error) {
        requestError = error;
      }
      const refreshed = await query.refetch();
      const confirmed =
        response !== undefined &&
        refreshed.data?.some(
          (item) =>
            item.memory_id === response?.memory_id &&
            item.content === confirmation.input.content &&
            item.source === confirmation.input.source,
        ) === true;
      if (confirmed) {
        setNotice({
          kind: "success",
          message: "服务端已确认修正，并返回了新的更新时间。",
        });
        setEditState(null);
      } else if (requestError instanceof ApiError) {
        setNotice({ kind: "error", message: readableError(requestError) });
      } else {
        setNotice({
          kind: "warning",
          message:
            "修正请求的结果无法确认。页面只重新读取了作用域，没有重放写请求；请先核对当前记录再决定下一步。",
        });
      }
    } else if (confirmation.kind === "delete") {
      let requestError: unknown;
      try {
        await deleteMemory(confirmation.memory.memory_id);
      } catch (error) {
        requestError = error;
      }
      if (requestError === undefined) {
        setNotice({
          kind: "success",
          message: "服务端已用 204 明确确认：这条长期记忆已删除。",
        });
        if (editState?.memory.memory_id === confirmation.memory.memory_id) {
          setEditState(null);
        }
        await query.refetch();
      } else if (requestError instanceof ApiError) {
        setNotice({ kind: "error", message: readableError(requestError) });
      } else {
        await query.refetch();
        setNotice({
          kind: "warning",
          message:
            "删除请求的结果未知。页面只重新读取了一次，没有自动重放删除；当前记录仍在，请稍后再次刷新。",
        });
      }
    } else {
      let requestError: unknown;
      try {
        await clearMemoryScope(confirmation.scope);
      } catch (error) {
        requestError = error;
      }
      if (requestError === undefined) {
        setNotice({
          kind: "success",
          message: "服务端已用 204 明确确认：这个精确作用域已经清空。",
        });
        setEditState(null);
        await query.refetch();
      } else if (requestError instanceof ApiError) {
        setNotice({ kind: "error", message: readableError(requestError) });
      } else {
        await query.refetch();
        setNotice({
          kind: "warning",
          message:
            "清空请求的结果未知。页面只重新读取了一次，没有自动重放；其他作用域和聊天线程未被触碰。",
        });
      }
    }

    setWriting(false);
    setConfirmation(null);
  }

  const memories = query.data;

  return (
    <section aria-labelledby="memories-title" className="memories-page surface">
      <header className="memories-page__header">
        <div>
          <p className="eyebrow">独立于聊天记录</p>
          <h2 id="memories-title" ref={headingRef} tabIndex={-1}>
            长期记忆
          </h2>
          <p>
            这里只管理用户确认过的稳定事实和偏好。删除聊天不会删除这些记录，清空记忆也不会删除聊天线程。
          </p>
        </div>
        {activeScope === null ? null : (
          <button
            disabled={query.isFetching || writing}
            onClick={() => void query.refetch()}
            ref={refreshRef}
            type="button"
          >
            {query.isFetching ? "正在重新读取……" : "重新读取"}
          </button>
        )}
      </header>

      <form className="memory-scope-form" onSubmit={chooseScope}>
        <fieldset disabled={writing}>
          <legend>选择精确作用域</legend>
          <label>
            用户
            <input
              maxLength={128}
              onChange={(event) =>
                setScopeDraft({
                  ...scopeDraft,
                  user: event.currentTarget.value,
                })
              }
              required
              value={scopeDraft.user}
            />
          </label>
          <label>
            网络
            <input
              maxLength={128}
              onChange={(event) =>
                setScopeDraft({
                  ...scopeDraft,
                  network: event.currentTarget.value,
                })
              }
              required
              value={scopeDraft.network}
            />
          </label>
          <label>
            节点 ID
            <input
              autoComplete="off"
              onChange={(event) =>
                setScopeDraft({
                  ...scopeDraft,
                  nodeId: event.currentTarget.value,
                })
              }
              placeholder="填写完整节点 ID"
              required
              value={scopeDraft.nodeId}
            />
          </label>
          <button type="submit">查看这个作用域</button>
        </fieldset>
        {scopeError === null ? null : (
          <p className="memory-inline-error" role="alert">
            {scopeError}
          </p>
        )}
      </form>

      {activeScope === null ? (
        <p className="memory-prompt" role="status">
          填写完整作用域后再读取；页面不会把一个作用域的缓存显示到另一个作用域。
        </p>
      ) : (
        <div className="memory-results">
          <div className="memory-results__heading">
            <div>
              <h3>当前作用域</h3>
              <p>{scopeLabel(activeScope)}</p>
            </div>
            <button
              className="memory-button--danger-outline"
              disabled={
                writing ||
                query.isFetching ||
                memories === undefined ||
                memories.length === 0
              }
              onClick={(event) =>
                setConfirmation({
                  kind: "clear",
                  scope: activeScope,
                  returnFocus: event.currentTarget,
                })
              }
              type="button"
            >
              清空这个精确作用域
            </button>
          </div>

          {notice === null ? null : (
            <p
              className={`memory-notice memory-notice--${notice.kind}`}
              role={notice.kind === "success" ? "status" : "alert"}
            >
              {notice.message}
            </p>
          )}

          {query.isPending ? (
            <p aria-live="polite" role="status">
              正在读取这个精确作用域的长期记忆……
            </p>
          ) : memories === undefined ? (
            <div className="memory-query-error" role="alert">
              <h3>现在读不到长期记忆</h3>
              <p>{readableError(query.error)}</p>
              <button onClick={() => void query.refetch()} type="button">
                重新读取
              </button>
            </div>
          ) : (
            <>
              {query.isRefetchError ? (
                <p
                  className="memory-notice memory-notice--warning"
                  role="alert"
                >
                  重新读取失败。下面是上一次成功读取的缓存，不能视为当前事实。
                </p>
              ) : null}
              {memories.length === 0 ? (
                <p className="memory-empty" role="status">
                  这个精确作用域还没有长期记忆。
                </p>
              ) : (
                <ul className="memory-list">
                  {memories.map((memory) => (
                    <li key={memory.memory_id}>
                      <article
                        aria-labelledby={`memory-${memory.memory_id}`}
                        className="memory-card"
                      >
                        <div className="memory-card__heading">
                          <h4 id={`memory-${memory.memory_id}`}>
                            {kindLabels[memory.kind]}
                          </h4>
                          <span>已由用户确认</span>
                        </div>
                        {editState?.memory.memory_id === memory.memory_id ? (
                          <MemoryEditor
                            disabled={writing}
                            onCancel={cancelEditing}
                            onChange={setEditState}
                            onReview={(returnFocus) =>
                              setConfirmation({
                                kind: "revise",
                                memory,
                                input: {
                                  content: editState.content.trim(),
                                  source: editState.source.trim(),
                                },
                                returnFocus,
                              })
                            }
                            state={editState}
                          />
                        ) : (
                          <>
                            <p className="memory-content">{memory.content}</p>
                            <dl className="memory-metadata">
                              <div>
                                <dt>来源</dt>
                                <dd>{memory.source}</dd>
                              </div>
                              <div>
                                <dt>更新时间</dt>
                                <dd>{formatTimestamp(memory.updated_at)}</dd>
                              </div>
                              <div>
                                <dt>有效期</dt>
                                <dd>{formatTimestamp(memory.valid_until)}</dd>
                              </div>
                              <div>
                                <dt>完整作用域</dt>
                                <dd>{returnedScopeLabel(memory)}</dd>
                              </div>
                            </dl>
                            <div className="memory-actions">
                              <button
                                disabled={writing}
                                onClick={(event) =>
                                  setEditState({
                                    memory,
                                    content: memory.content,
                                    source: memory.source,
                                    returnFocus: event.currentTarget,
                                  })
                                }
                                type="button"
                              >
                                修正这条记忆
                              </button>
                              <button
                                className="memory-button--danger-outline"
                                disabled={writing}
                                onClick={(event) =>
                                  setConfirmation({
                                    kind: "delete",
                                    memory,
                                    returnFocus: event.currentTarget,
                                  })
                                }
                                type="button"
                              >
                                删除这条记忆
                              </button>
                            </div>
                          </>
                        )}
                      </article>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      )}

      {confirmation === null ? null : (
        <ConfirmationDialog
          busy={writing}
          confirmLabel={
            confirmation.kind === "revise"
              ? "确认修正一次"
              : confirmation.kind === "delete"
                ? "确认删除一次"
                : "确认清空一次"
          }
          description={
            confirmation.kind === "revise" ? (
              <>
                <p>原作用域：{returnedScopeLabel(confirmation.memory)}</p>
                <p>修正后内容：{confirmation.input.content}</p>
                <p>修正后来源：{confirmation.input.source}</p>
              </>
            ) : confirmation.kind === "delete" ? (
              <>
                <p>将删除：{confirmation.memory.content}</p>
                <p>作用域：{returnedScopeLabel(confirmation.memory)}</p>
              </>
            ) : (
              <>
                <p>将清空：{scopeLabel(confirmation.scope)}</p>
                <p>其他作用域和聊天线程不会被删除。</p>
              </>
            )
          }
          fallbackFocus={refreshRef.current}
          onCancel={() => setConfirmation(null)}
          onConfirm={() => void confirmWrite()}
          returnFocus={confirmation.returnFocus}
          safeFallbackFocus={headingRef.current}
          title={
            confirmation.kind === "revise"
              ? "确认修正长期记忆"
              : confirmation.kind === "delete"
                ? "确认删除长期记忆"
                : "确认清空精确作用域"
          }
        />
      )}
    </section>
  );
}
