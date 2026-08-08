import { useEffect, useMemo, useRef, useState } from "react";

import { operationActionLabels } from "./operationPresentation";
import type { OperationActionPayload } from "./operationsApi";
import type { OperationAction, OperationDetail } from "./schemas";

interface ActionConfirmationDialogProps {
  action: OperationAction;
  detail: OperationDetail;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: (payload: OperationActionPayload) => void;
}

function localDateTimeValue(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll<HTMLElement>(
      "button:not([disabled]), input:not([disabled]), textarea:not([disabled])",
    ),
  );
}

export function ActionConfirmationDialog({
  action,
  detail,
  submitting,
  onCancel,
  onConfirm,
}: ActionConfirmationDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [reason, setReason] = useState("");
  const defaultExpiry = useMemo(
    () =>
      localDateTimeValue(
        new Date(Date.now() + detail.duration_seconds * 1_000),
      ),
    [detail.duration_seconds],
  );
  const [expiresAt, setExpiresAt] = useState(defaultExpiry);

  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  function handleKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape" && !submitting) {
      event.preventDefault();
      onCancel();
      return;
    }
    if (event.key !== "Tab" || dialogRef.current === null) {
      return;
    }
    const controls = focusableElements(dialogRef.current);
    if (controls.length === 0) {
      return;
    }
    const first = controls[0];
    const last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

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
    onConfirm({ action });
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
      >
        <form onSubmit={handleSubmit}>
          <p className="eyebrow">对象明确确认</p>
          <h2 id="operation-confirm-title">{title}</h2>
          <p id="operation-confirm-description">
            这是刚刚按 ID
            复读的服务端详情。确认只提交一次；按钮是否出现不代替服务端授权与并发检查。
          </p>
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

          {action === "approve" ? (
            <label className="operation-dialog__field">
              批准绝对过期时间
              <input
                required
                type="datetime-local"
                value={expiresAt}
                onChange={(event) => setExpiresAt(event.currentTarget.value)}
              />
            </label>
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
              撤销会触发本机生命周期清理。若清理不能安全完成，详情会保留受影响资源和人工处理建议。
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
              className="operation-button--danger"
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
