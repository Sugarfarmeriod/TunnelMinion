import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { isReadOnlyPreview } from "../../shared/previewMode";
import { listOperations } from "../operations/operationsApi";
import type { OperationSummary } from "../operations/schemas";
import type {
  DelegationPhase,
  RunEvent,
  RunStatus,
  RunView,
} from "./contracts";
import type { RunEventState } from "./eventReducer";

const runStatusLabels: Record<RunStatus, string> = {
  running: "正在检查",
  completed: "本次检查已结束",
  cancelled: "已停止检查",
  failed: "这次没查完",
  interrupted: "检查被打断",
};

const progressLabels: Record<string, string> = {
  get_node_summary: "查看电脑概况",
  get_wireguard_status: "查看网络连接",
  list_network_listeners: "查看服务端口",
  get_process_summary: "查看程序状态",
  list_docker_services: "查看容器状态",
  probe_service_reachability: "检查服务能否连接",
  read_container_logs: "查看容器日志",
  list_launch_records: "查看启动记录",
  propose_repair: "整理处理建议",
  delegate_to_node: "请另一台电脑协助检查",
};

const delegationLabels: Record<DelegationPhase, string> = {
  submitted: "已交给",
  investigating: "正在查",
  answered: "已交回",
  failed: "没查成",
  cancelled: "已取消",
};

const failureMessages = new Map([
  ["model_authentication_failed", "模型连接没有通过验证，这次检查没能完成。"],
  ["model_not_found", "没有找到设置中的模型，这次检查没能完成。"],
  ["model_timeout", "等模型回答等得太久，这次检查先停下了。"],
  ["model_network_unreachable", "这次联系模型时遇到问题，还没查完。"],
  ["model_invalid_response", "模型这次没有给出可用的回答，检查没能完成。"],
  ["model_capability_incompatible", "当前模型还不能完成这类检查。"],
  [
    "model_keychain_approval_pending",
    "模型密钥在等你授权：请在 Mac 屏幕上的钥匙串弹框点“始终允许”，再查一次。",
  ],
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
  peerName?: (nodeId: string) => string | undefined;
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

export function RunPanel({
  compact = false,
  activeRun,
  effectiveStatus,
  eventState,
  peerName,
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
      {compact && eventState.events.length > 0 ? (
        <ol className="chat-progress" aria-label="调查进度" aria-live="polite">
          {eventState.events
            .filter((event) => event.event_type !== "delegation")
            .map((event) => (
              <li
                key={event.sequence}
                className={
                  effectiveStatus === "running" &&
                  event.sequence === toolEvents.at(-1)?.sequence &&
                  event.tool_status === "started"
                    ? "is-running"
                    : undefined
                }
              >
                {event.event_type === "goal"
                  ? "已收到问题，开始检查"
                  : event.event_type === "tool"
                    ? `${progressLabels[event.tool_name ?? ""] ?? "检查服务"} · ${event.tool_status === "success" ? "已完成" : event.tool_status === "started" ? "开始检查" : "未完成"}`
                    : event.event_type === "finished"
                      ? "检查已结束"
                      : (event.message ?? "检查未完成")}
              </li>
            ))}
        </ol>
      ) : null}
      {Object.values(eventState.delegations).map((delegation) => (
        <p key={delegation.delegation_id}>
          交给 {peerName?.(delegation.peer_node_id) ?? delegation.peer_node_id}{" "}
          · {delegationLabels[delegation.phase]}
        </p>
      ))}
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
        activeRun.result.answer_basis !== "inferred" &&
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
        <>
          {!compact && activeRun.result?.answer_basis === "inferred" ? (
            <span className="chat-basis-badge chat-basis-badge--inferred">
              推断 · 尚未逐条核对
            </span>
          ) : null}
          <p className="chat-terminal-message chat-untrusted-text">
            {terminalMessage}
          </p>
        </>
      )}
    </section>
  );
}
