import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { ApiError } from "../../api/client";
import { isReadOnlyPreview } from "../../shared/previewMode";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { peersQueryKey, type Peer } from "../service-map/api";
import {
  decidePeerRepair,
  isRepairExecuting,
  isRepairTerminal,
  loadPeerRepair,
  type RemoteRepair,
} from "./api";
import {
  RepairFacts,
  RepairProgress,
  repairResultTitle,
} from "./RepairPresentation";
import "./repairs.css";

export function RemoteRepairDialog({
  nodeId,
  repair: summary,
  name,
  onClose,
}: {
  nodeId: string;
  repair: RemoteRepair;
  name: string;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const preview = isReadOnlyPreview();
  const [now, setNow] = useState(Date.now);
  const queryKey = ["peer-repair", nodeId, summary.repair_id];
  const query = useQuery({
    queryKey,
    queryFn: ({ signal }) => loadPeerRepair(nodeId, summary.repair_id, signal),
    retry: false,
    staleTime: 0,
    refetchOnWindowFocus: false,
    refetchInterval: (query) =>
      query.state.status !== "error" &&
      query.state.data?.access === "allowed" &&
      query.state.data.repair !== null &&
      !isRepairTerminal(query.state.data.repair.status)
        ? 3_000
        : false,
  });
  const repair = query.data?.access === "allowed" ? query.data.repair : null;
  const access = query.isError ? "unreachable" : query.data?.access;
  const decision = useMutation({
    mutationFn: (action: "approve" | "reject") =>
      decidePeerRepair(nodeId, summary.repair_id, action),
    onMutate: () => client.cancelQueries({ queryKey }),
    onSuccess: async (data) => {
      await client.cancelQueries({ queryKey });
      client.setQueryData(queryKey, data);
      client.setQueryData<{ peers: Peer[] }>(peersQueryKey, (previous) =>
        previous
          ? {
              peers: previous.peers.map((peer) =>
                peer.node_id === nodeId
                  ? {
                      ...peer,
                      pending_repairs: peer.pending_repairs.filter(
                        (item) => item.repair_id !== summary.repair_id,
                      ),
                    }
                  : peer,
              ),
            }
          : previous,
      );
    },
    onError: () => void query.refetch(),
  });
  const executing = repair != null && isRepairExecuting(repair.status);
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
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const expiresAt = repair ? repair.approval_expires_at : summary.expires_at;
  const seconds = Math.max(
    0,
    Math.ceil(((expiresAt ? Date.parse(expiresAt) : 0) - now) / 1_000),
  );
  const waiting =
    access === "allowed" && repair?.status === "awaiting_authorization";
  const terminal = repair != null && isRepairTerminal(repair.status);
  const decisionStatus =
    decision.error instanceof ApiError ? decision.error.status : null;
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
            要修好“{repair?.service_name ?? summary.service_name}”吗？
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
          {repair ? (
            <>
              <p>
                <small>
                  由 {name} 提出 · {name} 允许这台电脑替它批准
                </small>
              </p>
              <RepairFacts repair={repair} />
            </>
          ) : (
            <dl>
              <div>
                <dt>要做什么</dt>
                <dd>{summary.action}</dd>
              </div>
            </dl>
          )}
          {query.isPending ? (
            <p role="status">正在问 {name} 能不能在这里批准……</p>
          ) : null}
          {access === "not_allowed" ? (
            <p>请到 {name} 的地图上点感叹号批准</p>
          ) : null}
          {access === "not_found" ? (
            <p>{name} 上已经没有这个修复了，可能已经处理或过期。</p>
          ) : null}
          {access === "unreachable" ? (
            <p>
              现在连不上 {name}，没法在这里批准。可以稍后再试，或到 {name}{" "}
              的地图上批准。
            </p>
          ) : null}
          <details>
            <summary>高级</summary>
            {access === "not_allowed" ? (
              <pre>{summary.how_to_approve}</pre>
            ) : (
              <p>修复编号 {summary.repair_id}</p>
            )}
          </details>
          {preview ? <p>只读预览：可以查看修复，不能批准或拒绝。</p> : null}
          {decision.isPending ? (
            <p role="status">正在把批准交给 {name}……</p>
          ) : null}
          {decision.isError ? (
            <p role="alert">
              {decisionStatus === 409
                ? `这个修复已经不等批准了（可能已过期，或 ${name} 本机已经处理）。`
                : decisionStatus === 403
                  ? `${name} 已经不允许这台电脑替它批准了，请到 ${name} 的地图上批准。`
                  : `连不上 ${name}，稍后再试`}
            </p>
          ) : null}
          {executing ? (
            <RepairProgress
              status={repair.status}
              prefix={
                repair.approved_by_peer === false
                  ? `${name} 本机已经批准，`
                  : undefined
              }
            />
          ) : null}
          {terminal ? (
            <div
              className={`repair-result ${repair.status === "succeeded" ? "success" : ""}`}
              role="status"
            >
              <strong>{repairResultTitle(repair.status)}</strong>
              {repair.error_message ? <p>{repair.error_message}</p> : null}
            </div>
          ) : null}
          {waiting || access === "not_allowed" ? (
            <p className="repair-expiry" role="status">
              10 分钟内有效 ·{" "}
              {seconds === 0 || (!repair && isRepairTerminal(summary.status))
                ? "已过期"
                : `还剩 ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`}
            </p>
          ) : null}
          {waiting ? (
            <p>
              批准后由 {name} 动手修。动手前 {name}{" "}
              会再核对一次，情况变了就不修。
            </p>
          ) : null}
        </div>
        <footer>
          {waiting ? (
            <>
              <button
                type="button"
                className="map-button map-go"
                disabled={
                  locked || preview || seconds === 0 || decisionStatus === 403
                }
                onClick={() => decision.mutate("approve")}
              >
                批准并修复
              </button>
              <button
                type="button"
                className="map-button"
                disabled={
                  locked || preview || seconds === 0 || decisionStatus === 403
                }
                onClick={() => decision.mutate("reject")}
              >
                先不用
              </button>
            </>
          ) : null}
          {access === "unreachable" ? (
            <button
              type="button"
              className="map-button"
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              再试一次
            </button>
          ) : null}
          {!waiting && !executing ? (
            <button
              type="button"
              className="map-button"
              disabled={locked}
              onClick={onClose}
            >
              知道了
            </button>
          ) : null}
        </footer>
      </div>
    </div>
  );
}
