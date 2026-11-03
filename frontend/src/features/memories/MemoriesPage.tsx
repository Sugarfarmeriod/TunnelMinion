import { useQuery } from "@tanstack/react-query";
import type { FormEvent, ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import { ApiError } from "../../api/client";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { isReadOnlyPreview } from "../../shared/previewMode";

import {
  clearMemoryScope,
  deleteMemory,
  getMemories,
  nodeIdSchema,
  reviseMemory,
} from "./api";
import type { LongTermMemory, MemoryScope, ReviseMemoryInput } from "./api";
import { loadPeers, peersQueryKey } from "../service-map/api";
import "./memories.css";

const kindLabels: Record<LongTermMemory["kind"], string> = {
  "node-alias": "电脑的别名",
  preference: "你的习惯和偏好",
  "security-constraint": "不许做的事",
  "stable-service-fact": "服务的固定信息",
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
    return "一直有效";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

// 本机 Agent 默认把记忆记在这个用户、这个网络、这台电脑下。
const defaultUser = "local-user";
const defaultNetwork = "home";

function scopeLabel(scope: MemoryScope): string {
  return `用户“${scope.user}” / 网络“${scope.network}” / 电脑“${scope.nodeId}”`;
}

function returnedScopeLabel(memory: LongTermMemory): string {
  const scope = memory.namespace;
  return `用户“${scope.user}” / 网络“${scope.network}” / 电脑“${scope.node_id}” / 任务“${scope.task_type}” / 安全范围“${scope.security_scope}”`;
}

function readableError(error: unknown): string {
  if (error instanceof ApiError) {
    return `${error.message}（${error.code}）`;
  }
  if (error instanceof Error && error.name === "ZodError") {
    return "本机程序返回的记忆格式不对，页面没有显示它。";
  }
  return "读不到记忆，请确认这台电脑上的 TunnelMinion 还开着。";
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
  const cancelRef = useRef<HTMLButtonElement>(null);
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    escapeDisabled: busy,
    initialFocusRef: cancelRef,
    onEscape: onCancel,
    returnFocus: [returnFocus, fallbackFocus, safeFallbackFocus],
  });

  return (
    <div className="memory-dialog-backdrop">
      <div
        aria-describedby="memory-confirm-description"
        aria-labelledby="memory-confirm-title"
        aria-modal="true"
        className="memory-dialog"
        onKeyDown={handleKeyDown}
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
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
  const reviewButtonRef = useRef<HTMLButtonElement>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    contentRef.current?.focus();
  }, []);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (state.content.trim() === "" || state.source.trim() === "") {
      setValidationError("内容和来源都要填。");
      contentRef.current?.focus();
      return;
    }
    setValidationError(null);
    onReview(reviewButtonRef.current);
  }

  return (
    <form className="memory-editor" onSubmit={submit}>
      <p className="memory-editor__scope">
        改完还记在原来的范围里，不会挪到别处。
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
        <button disabled={disabled} ref={reviewButtonRef} type="submit">
          检查并确认修改
        </button>
        <button disabled={disabled} onClick={onCancel} type="button">
          取消编辑
        </button>
      </div>
    </form>
  );
}

export function MemoriesPage() {
  // 本机 Agent 的记忆存在这台电脑下；打开页面就直接看这台电脑的记忆，不用手抄 32 位编号。
  const peersQuery = useQuery({
    queryKey: peersQueryKey,
    queryFn: loadPeers,
    retry: false,
  });
  const localNodeId =
    peersQuery.data?.peers.find((peer) => peer.is_local)?.node_id ?? null;
  const defaultScope: MemoryScope | null =
    localNodeId === null
      ? null
      : { user: defaultUser, network: defaultNetwork, nodeId: localNodeId };
  const [scopeDraft, setScopeDraft] = useState<MemoryScope>({
    user: defaultUser,
    network: defaultNetwork,
    nodeId: "",
  });
  // 主人在“高级”里手动选过范围后才有值；没选过就看这台电脑。
  const [chosenScope, setChosenScope] = useState<MemoryScope | null>(null);
  const activeScope = chosenScope ?? defaultScope;
  const viewingDefault =
    activeScope !== null &&
    defaultScope !== null &&
    activeScope.user === defaultScope.user &&
    activeScope.network === defaultScope.network &&
    activeScope.nodeId === defaultScope.nodeId;
  useEffect(() => {
    if (localNodeId !== null) {
      setScopeDraft((draft) =>
        draft.nodeId === "" ? { ...draft, nodeId: localNodeId } : draft,
      );
    }
  }, [localNodeId]);
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
      setScopeError("用户、网络和电脑编号都要填。");
      return;
    }
    if (!nodeIdSchema.safeParse(next.nodeId).success) {
      setScopeError("电脑编号是 node_ 开头、后面跟 32 位数字和小写字母。");
      return;
    }
    setScopeError(null);
    setNotice(null);
    setEditState(null);
    setChosenScope(next);
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
          message: "已修改。",
        });
        setEditState(null);
      } else if (requestError instanceof ApiError) {
        setNotice({ kind: "error", message: readableError(requestError) });
      } else {
        setNotice({
          kind: "warning",
          message:
            "不确定刚才有没有改成功。页面只重新读了一次，没有再改一遍；请先看看下面的记录对不对。",
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
          message: "已删除这条记忆。",
        });
        if (editState?.memory.memory_id === confirmation.memory.memory_id) {
          setEditState(null);
        }
        await query.refetch();
      } else if (requestError instanceof ApiError) {
        await query.refetch();
        setNotice({
          kind: "error",
          message: `删除失败：${readableError(requestError)} 页面只重新读了一次，没有自动再删。`,
        });
      } else {
        await query.refetch();
        setNotice({
          kind: "warning",
          message:
            "不确定刚才有没有删成功。页面只重新读了一次，没有自动再删；过一会儿再点“重新读取”看看。",
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
          message: "已清空这里的全部记忆。",
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
            "不确定刚才有没有清空成功。页面只重新读了一次，没有自动再清；别的范围和聊天记录都没动。",
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
          <h2 id="memories-title" ref={headingRef} tabIndex={-1}>
            长期记忆
          </h2>
          <p className="page-lead">
            Agent
            记住的、经你确认过的事，比如电脑的别名、你的习惯、哪些事不许做。以后提问时它会参考这些。删聊天不会删这些记忆，清空记忆也不会删聊天。
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

      {activeScope === null ? (
        <p className="memory-prompt" role="status">
          {peersQuery.isPending
            ? "正在找这台电脑……"
            : "找不到这台电脑的编号。可以在下面“高级”里手动填写范围再看。"}
        </p>
      ) : (
        <div className="memory-results">
          <div className="memory-results__heading">
            <div>
              <h3>{viewingDefault ? "这台电脑的记忆" : "这个范围里的记忆"}</h3>
              {viewingDefault ? null : <p>{scopeLabel(activeScope)}</p>}
            </div>
            <button
              className="memory-button--danger-outline"
              disabled={
                isReadOnlyPreview() ||
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
              清空这里的全部记忆
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
              正在读取记忆……
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
                  这里还没有记忆。你在对话里让 Agent
                  记住某件事并确认后，就会出现在这里。
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
                          <span>你确认过</span>
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
                                <dt>有效到</dt>
                                <dd>{formatTimestamp(memory.valid_until)}</dd>
                              </div>
                            </dl>
                            <details className="memory-scope-detail">
                              <summary>记在哪个范围</summary>
                              <p>{returnedScopeLabel(memory)}</p>
                            </details>
                            <div className="memory-actions">
                              <button
                                disabled={isReadOnlyPreview() || writing}
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
                                修改这条记忆
                              </button>
                              <button
                                className="memory-button--danger-outline"
                                disabled={isReadOnlyPreview() || writing}
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

      <details className="advanced memory-scope">
        <summary>高级：看别的范围</summary>
        <p className="advanced-hint">
          记忆按“用户 / 网络 /
          电脑”分开存。平时只用这台电脑的；想看别的电脑或旧数据时，在这里填好再看。
        </p>
        <form className="memory-scope-form" onSubmit={chooseScope}>
          <fieldset disabled={writing}>
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
              电脑编号
              <input
                autoComplete="off"
                onChange={(event) =>
                  setScopeDraft({
                    ...scopeDraft,
                    nodeId: event.currentTarget.value,
                  })
                }
                placeholder="node_ 开头的完整编号"
                required
                value={scopeDraft.nodeId}
              />
            </label>
            <button type="submit">看这个范围</button>
          </fieldset>
          {scopeError === null ? null : (
            <p className="memory-inline-error" role="alert">
              {scopeError}
            </p>
          )}
        </form>
      </details>

      {confirmation === null ? null : (
        <ConfirmationDialog
          busy={writing}
          confirmLabel={
            confirmation.kind === "revise"
              ? "确认修改"
              : confirmation.kind === "delete"
                ? "确认删除"
                : "确认清空"
          }
          description={
            confirmation.kind === "revise" ? (
              <>
                <p>改成：{confirmation.input.content}</p>
                <p>来源：{confirmation.input.source}</p>
              </>
            ) : confirmation.kind === "delete" ? (
              <>
                <p>将删除：{confirmation.memory.content}</p>
              </>
            ) : (
              <>
                <p>
                  将清空：
                  {viewingDefault
                    ? "这台电脑的全部记忆"
                    : scopeLabel(confirmation.scope)}
                </p>
                <p>别的范围和聊天记录都不会动。</p>
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
              ? "确认修改这条记忆"
              : confirmation.kind === "delete"
                ? "确认删除这条记忆"
                : "确认清空这里的全部记忆"
          }
        />
      )}
    </section>
  );
}
