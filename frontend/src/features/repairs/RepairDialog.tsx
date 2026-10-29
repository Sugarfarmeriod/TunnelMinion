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
import { ManualSteps } from "./ManualSteps";
import {
  RepairFacts,
  RepairProgress,
  repairResultTitle,
} from "./RepairPresentation";

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
              <RepairFacts repair={repair} />
              <details>
                <summary>高级：将执行的命令</summary>
                <pre>{advancedText(repair.advanced)}</pre>
              </details>
              {preview ? <p>只读预览：可以查看修复，不能批准或拒绝。</p> : null}
              {decision.isError ? (
                <p role="alert">
                  {decision.variables === "approve"
                    ? "还不能确认是否批准，请查看最新进展后重试。"
                    : "先不用没有确认成功，请重试。"}
                </p>
              ) : null}
              {executing ? <RepairProgress status={repair.status} /> : null}
              {terminal ? (
                <div
                  className={`repair-result ${repair.status === "succeeded" ? "success" : ""}`}
                  role="status"
                >
                  <strong>{repairResultTitle(repair.status)}</strong>
                  {repair.error ? <p>{repair.error.message}</p> : null}
                  {repair.verification?.checks.map((check, index) => (
                    <p key={index}>{check.detail}</p>
                  ))}
                  {repair.cleanup ? <p>{repair.cleanup.detail}</p> : null}
                  {repair.execution?.ended_process_id ? (
                    <p>
                      已结束卡住的进程 {repair.execution.ended_process_id}
                      {repair.execution.ended_forcibly ? "（强制结束）" : ""}
                    </p>
                  ) : null}
                  {repair.error?.next_step ? (
                    <p>{repair.error.next_step}</p>
                  ) : null}
                </div>
              ) : null}
              {repair.error?.manual_steps.length ? (
                <ManualSteps steps={repair.error.manual_steps} />
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

/** 按高级视图的特有字段区分修法：Windows 服务、后台服务、普通程序、容器、Python 脚本。 */
function advancedText(advanced: RepairDetail["advanced"]) {
  if ("binary_path" in advanced)
    return `${advanced.commands.join("\n")}\n服务程序：${advanced.binary_path}`;
  if ("plist_path" in advanced)
    return `${advanced.command}\n配置文件：${advanced.plist_path}`;
  if ("end_process_id" in advanced)
    return advanced.end_process_id === null
      ? advanced.command
      : `先结束卡住的进程 ${advanced.end_process_id}\n${advanced.command}`;
  if ("commands" in advanced) return advanced.commands.join("\n");
  return `${JSON.stringify([advanced.interpreter, ...advanced.arguments])}\n工作目录：${advanced.working_directory}`;
}
