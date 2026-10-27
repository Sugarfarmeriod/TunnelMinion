import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { isReadOnlyPreview } from "../../shared/previewMode";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { localServicesQueryKey } from "../service-map/api";
import {
  decideRepair,
  isRepairExecuting,
  isRepairTerminal,
  loadRepair,
  repairQueryKey,
  repairsQueryKey,
  type RepairDetail,
} from "./api";
import "./repairs.css";

export function RepairDialog({
  repairId,
  onClose,
  onStatus,
}: {
  repairId: string;
  onClose: () => void;
  onStatus: (repair: RepairDetail) => void;
}) {
  const client = useQueryClient();
  const preview = isReadOnlyPreview();
  const [now, setNow] = useState(Date.now);
  const [uncertain, setUncertain] = useState(false);
  const query = useQuery({
    queryKey: repairQueryKey(repairId),
    queryFn: ({ signal }) => loadRepair(repairId, signal),
    refetchInterval: (query) =>
      isRepairExecuting(query.state.data?.status ?? "planned") || uncertain
        ? 1_000
        : false,
  });
  const repair = query.data;
  const decision = useMutation({
    mutationFn: (action: "approve" | "reject") =>
      decideRepair(repairId, action),
    onMutate: () =>
      client.cancelQueries({ queryKey: repairQueryKey(repairId) }),
    onSuccess: (data) => {
      client.setQueryData(repairQueryKey(repairId), data);
      setUncertain(false);
    },
    onError: () => {
      setUncertain(true);
      void query.refetch();
    },
  });
  const executing = repair !== undefined && isRepairExecuting(repair.status);
  const locked = decision.isPending || executing;
  const closeRef = useRef<HTMLButtonElement>(null);
  const opener = useRef(
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null,
  );
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    initialFocusRef: closeRef,
    returnFocus: [
      opener.current,
      document.querySelector<HTMLButtonElement>(".map-node"),
    ],
    onEscape: onClose,
    escapeDisabled: locked,
  });
  const notified = useRef<string | null>(null);
  const statusCallback = useRef(onStatus);
  statusCallback.current = onStatus;
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!repair) return;
    statusCallback.current(repair);
    if (isRepairTerminal(repair.status) && notified.current !== repair.status) {
      notified.current = repair.status;
      setUncertain(false);
      void client.invalidateQueries({ queryKey: localServicesQueryKey });
      void client.invalidateQueries({ queryKey: repairsQueryKey });
      if (repair.origin.thread_id) {
        void client.invalidateQueries({
          queryKey: ["chat-thread", repair.origin.thread_id],
        });
        void client.invalidateQueries({ queryKey: ["chat-threads"] });
      }
    }
  }, [repair, client]);
  const seconds = Math.max(
    0,
    Math.ceil(
      ((repair?.approval_expires_at
        ? Date.parse(repair.approval_expires_at)
        : 0) -
        now) /
        1_000,
    ),
  );
  const waiting = repair?.status === "awaiting_authorization";
  const expired =
    (waiting && seconds === 0) ||
    repair?.status === "authorization_expired" ||
    repair?.status === "expired";
  const terminal = repair !== undefined && isRepairTerminal(repair.status);
  const step =
    repair?.status === "authorized"
      ? 0
      : repair?.status === "executing"
        ? 1
        : 2;
  return (
    <div className="repair-mask">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="repair-title"
        tabIndex={-1}
        className="repair-dialog"
        onKeyDown={handleKeyDown}
      >
        <header>
          <h2 id="repair-title">
            {repair ? `要修好“${repair.service_name}”吗？` : "查看修复"}
          </h2>
          <button
            ref={closeRef}
            type="button"
            className="map-close"
            aria-label="关闭修复"
            disabled={locked}
            onClick={onClose}
          >
            ×
          </button>
        </header>
        <div
          className="repair-body map-scroll"
          tabIndex={0}
          aria-label="修复详情"
        >
          {query.isPending ? <p role="status">正在读取修复……</p> : null}
          {query.isError ? (
            <p role="alert">
              暂时无法读取修复进展。
              <button
                type="button"
                className="map-button"
                onClick={() => void query.refetch()}
              >
                重新读取
              </button>
            </p>
          ) : null}
          {repair ? (
            <>
              <dl>
                {[
                  ["要做什么", repair.action_summary],
                  ["为什么", repair.reason],
                  ["会有什么影响", repair.impact_summary],
                  ["怎么确认修好", repair.verification_summary],
                  ["没修好怎么办", repair.failure_summary],
                ].map(([title, text]) => (
                  <div key={title}>
                    <dt>{title}</dt>
                    <dd>{text}</dd>
                  </div>
                ))}
              </dl>
              <details>
                <summary>高级：将执行的命令</summary>
                <pre>
                  {"commands" in repair.advanced
                    ? repair.advanced.commands.join("\n")
                    : JSON.stringify([
                        repair.advanced.interpreter,
                        ...repair.advanced.arguments,
                      ])}
                  {"working_directory" in repair.advanced
                    ? `\n工作目录：${repair.advanced.working_directory}`
                    : ""}
                </pre>
              </details>
              {preview ? <p>只读预览：可以查看修复，不能批准或拒绝。</p> : null}
              {decision.isError ? (
                <p role="alert">
                  {decision.variables === "approve"
                    ? "还不能确认是否批准，请查看最新进展后重试。"
                    : "先不用没有确认成功，请重试。"}
                </p>
              ) : null}
              {executing ? (
                <ol
                  className="repair-steps"
                  aria-label="修复进度"
                  aria-live="polite"
                >
                  {["再核对一次", "正在执行", "正在确认"].map((text, index) => (
                    <li
                      key={text}
                      className={
                        index < step ? "done" : index === step ? "doing" : ""
                      }
                      aria-current={index === step ? "step" : undefined}
                    >
                      {text}
                    </li>
                  ))}
                </ol>
              ) : null}
              {terminal ? (
                <div
                  className={`repair-result ${repair.status === "succeeded" ? "success" : ""}`}
                  role="status"
                >
                  <strong>
                    {repair.status === "succeeded"
                      ? "修好了"
                      : expired
                        ? "已过期"
                        : ["rejected", "cancelled"].includes(repair.status)
                          ? "已取消"
                          : "没修好"}
                  </strong>
                  {repair.error ? <p>{repair.error.message}</p> : null}
                  {repair.verification?.checks.map((check, index) => (
                    <p key={index}>{check.detail}</p>
                  ))}
                  {repair.cleanup ? <p>{repair.cleanup.detail}</p> : null}
                  {repair.error?.next_step ? (
                    <p>{repair.error.next_step}</p>
                  ) : null}
                </div>
              ) : null}
              {waiting ? (
                <p className="repair-expiry" role="status">
                  10 分钟内有效 ·{" "}
                  {expired
                    ? "已过期"
                    : `还剩 ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`}
                </p>
              ) : null}
            </>
          ) : null}
        </div>
        <footer>
          {waiting && !preview ? (
            <>
              <button
                type="button"
                className="map-button map-go"
                disabled={locked || expired}
                onClick={() => decision.mutate("approve")}
              >
                批准并修复
              </button>
              <button
                type="button"
                className="map-button"
                disabled={locked || expired}
                onClick={() => decision.mutate("reject")}
              >
                先不用
              </button>
            </>
          ) : null}
          {terminal || preview ? (
            <button
              type="button"
              className="map-button"
              disabled={locked}
              onClick={onClose}
            >
              关闭
            </button>
          ) : null}
        </footer>
      </div>
    </div>
  );
}
