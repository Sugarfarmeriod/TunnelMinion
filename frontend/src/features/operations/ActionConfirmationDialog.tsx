import { useMemo, useRef, useState } from "react";

import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import {
  operationActionLabels,
  formatOperationTime,
} from "./operationPresentation";
import { RequestExplanation } from "./RequestExplanation";
import type { OperationActionPayload } from "./operationsApi";
import type { OperationAction, OperationDetail } from "./schemas";
import type { ResourceOverview } from "../../api/schemas/overview";

interface ActionConfirmationDialogProps {
  action: OperationAction;
  detail: OperationDetail;
  overview?: ResourceOverview;
  submitting: boolean;
  returnFocus: HTMLElement | null;
  fallbackFocus: HTMLElement | null;
  safeFallbackFocus: HTMLElement | null;
  onCancel: () => void;
  onConfirm: (payload: OperationActionPayload) => void;
}

function localDateTimeValue(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 19);
}

export function ActionConfirmationDialog({
  action,
  detail,
  overview,
  submitting,
  returnFocus,
  fallbackFocus,
  safeFallbackFocus,
  onCancel,
  onConfirm,
}: ActionConfirmationDialogProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    escapeDisabled: submitting,
    initialFocusRef: cancelRef,
    onEscape: onCancel,
    returnFocus: [returnFocus, fallbackFocus, safeFallbackFocus],
  });
  const [reason, setReason] = useState("");
  const defaultExpiry = useMemo(
    () => localDateTimeValue(new Date(Date.now() + 5 * 60 * 1_000)),
    [],
  );
  const [expiresAt, setExpiresAt] = useState(defaultExpiry);

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) {
      return;
    }
    if (action === "approve") {
      const parsed = new Date(expiresAt);
      if (Number.isNaN(parsed.getTime())) {
        return;
      }
      onConfirm({
        action,
        operator: "target-local-user",
        expires_at: parsed.toISOString(),
      });
      return;
    }
    if (action === "reject" || action === "cancel") {
      const trimmedReason = reason.trim();
      if (trimmedReason.length === 0) {
        return;
      }
      onConfirm({
        action,
        operator: "target-local-user",
        reason: trimmedReason,
      });
      return;
    }
    if (action === "execute") {
      onConfirm({ action, confirmed: true });
      return;
    }
    if (action === "revoke") {
      onConfirm({ action });
    }
  }

  const title = `确认${operationActionLabels[action]}`;

  return (
    <div className="operation-dialog-backdrop">
      <div
        ref={dialogRef}
        aria-describedby="operation-confirm-description"
        aria-labelledby="operation-confirm-title"
        aria-modal="true"
        className="operation-dialog"
        role="dialog"
        onKeyDown={handleKeyDown}
        tabIndex={-1}
      >
        <form onSubmit={handleSubmit}>
          <p className="eyebrow">最后确认</p>
          <h2 id="operation-confirm-title">{title}</h2>
          <p id="operation-confirm-description">
            {action === "approve"
              ? "这次同意只用于下面这一个请求，不会自动同意以后的请求。"
              : "请确认要对下面这个请求进行操作。"}
          </p>
          <RequestExplanation detail={detail} overview={overview} compact />
          <details className="operation-technical-details">
            <summary>查看请求编号与技术详情</summary>
            <dl className="operation-dialog__object">
              <div>
                <dt>操作 ID</dt>
                <dd>{detail.summary.operation_id}</dd>
              </div>
              <div>
                <dt>服务</dt>
                <dd>{detail.service_id}</dd>
              </div>
              <div>
                <dt>当前状态</dt>
                <dd>{detail.state}</dd>
              </div>
              <div>
                <dt>请求节点</dt>
                <dd>{detail.summary.request_node_id}</dd>
              </div>
              <div>
                <dt>目标入口</dt>
                <dd>{detail.service_endpoint}</dd>
              </div>
              <div>
                <dt>风险</dt>
                <dd>{detail.risk_summary}</dd>
              </div>
            </dl>
          </details>

          {action === "approve" ? (
            <p>
              对方需要在{" "}
              {Number.isNaN(new Date(expiresAt).getTime())
                ? "有效的截止时间"
                : formatOperationTime(new Date(expiresAt).toISOString())}{" "}
              前开始使用；超过这个时间，需要重新请求。
            </p>
          ) : null}
          {action === "approve" ? (
            <details className="operation-technical-details">
              <summary>调整批准有效期</summary>
              <p>对方必须在这个时间之前开始。开始后的访问时长不会因此延长。</p>
              <label className="operation-dialog__field">
                批准有效期截止时间
                <input
                  required
                  step="1"
                  type="datetime-local"
                  value={expiresAt}
                  onInvalid={(event) => {
                    const section = event.currentTarget.closest("details");
                    if (section !== null) {
                      section.open = true;
                    }
                  }}
                  onChange={(event) => setExpiresAt(event.currentTarget.value)}
                />
              </label>
            </details>
          ) : null}

          {action === "reject" || action === "cancel" ? (
            <label className="operation-dialog__field">
              {action === "reject" ? "拒绝原因" : "取消原因"}
              <textarea
                required
                maxLength={2_000}
                rows={3}
                value={reason}
                onChange={(event) => setReason(event.currentTarget.value)}
              />
            </label>
          ) : null}

          {action === "revoke" ? (
            <p className="operation-dialog__warning">
              对方将不能继续使用这个临时入口。如果关闭失败，页面会告诉你需要怎样处理。
            </p>
          ) : null}

          {action === "execute" ? (
            <p className="operation-dialog__warning">
              开始后会创建临时入口并检查能否使用。结果不明确时，请先刷新，不要重复开始。
            </p>
          ) : null}

          <div className="operation-dialog__actions">
            <button
              ref={cancelRef}
              disabled={submitting}
              type="button"
              onClick={onCancel}
            >
              返回检查详情
            </button>
            <button
              className={
                action === "reject" || action === "revoke"
                  ? "operation-button--danger"
                  : undefined
              }
              disabled={submitting}
              type="submit"
            >
              {submitting ? "正在提交一次……" : title}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
