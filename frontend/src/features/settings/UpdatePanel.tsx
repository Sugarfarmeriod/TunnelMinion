import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { ApiError } from "../../api/client";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";

import {
  applyUpdate,
  checkUpdate,
  getUpdate,
  updateQueryKey,
  type UpdateView,
} from "./updateApi";

const unsupportedText: Record<
  NonNullable<UpdateView["unsupported_reason"]>,
  string
> = {
  read_only_preview: "预览模式不能更新。",
  source_run: "从源码运行，不支持一键更新，请用 git pull。",
  no_runtime_profile: "不是用 runtime start 启动的，不支持一键更新。",
  unsupported_platform: "这个平台没有发布运行包。",
};

const errorText: Record<string, string> = {
  network_unreachable: "连不上 GitHub，请检查网络或代理。",
  github_rate_limited: "GitHub 暂时限制了查询次数，过一会儿再试。",
  no_release: "还没有发布过版本。",
  platform_not_released: "最新版本没有这个平台的运行包。",
  release_invalid: "发布信息不完整，暂时不能更新。",
  release_metadata_missing: "发布信息不完整，暂时不能更新。",
  release_feed_failed: "查询发布信息失败，过一会儿再试。",
  download_url_rejected: "下载地址不安全，已拒绝。",
  download_failed: "下载中断了，已删掉下载的文件，可以重试。",
  download_incomplete: "下载中断了，已删掉下载的文件，可以重试。",
  size_mismatch: "下载的文件和发布清单对不上，已删掉，没有换包。",
  checksum_mismatch: "下载的文件和发布清单对不上，已删掉，没有换包。",
  archive_invalid: "运行包校验没通过，已删掉，没有换包。",
  archive_too_large: "运行包校验没通过，已删掉，没有换包。",
  package_invalid: "运行包校验没通过，已删掉，没有换包。",
  already_current: "已经是最新版本。",
  update_in_progress: "已经有一次更新在进行。",
  install_failed: "安装新版本时出错，旧版不受影响。",
  stop_failed: "旧版没能停干净，没有换包。",
  new_version_unhealthy: "新版本没能启动，已自动退回原来的版本。",
  new_version_stuck:
    "新版本没能启动也没能停下，请在命令行运行 runtime stop 再 runtime start。",
  rollback_failed:
    "新版本没能启动，退回旧版也没成功，请在命令行运行 runtime start。",
};

function explain(code: string | null): string {
  if (code === null) {
    return "";
  }
  return errorText[code] ?? `更新没有完成（${code}）。`;
}

function shortRevision(revision: string | null): string {
  return revision === null ? "未知" : revision.slice(0, 7);
}

function currentLabel(view: UpdateView): string {
  return (
    view.current.release_tag ??
    `提交 ${shortRevision(view.current.source_revision)}`
  );
}

function availabilityText(view: UpdateView): string {
  switch (view.availability) {
    case "update_available":
      return "有新版本";
    case "up_to_date":
      return "已是最新";
    case "unreleased_build":
      return "当前是未发布的构建";
    case "unknown":
      return "无法确认是否比当前新";
    default:
      return "还没检查";
  }
}

function lastResultText(view: UpdateView): string | null {
  const result = view.last_result;
  if (result === null) {
    return null;
  }
  const target = result.release_tag ?? "新版本";
  if (result.outcome === "updated") {
    return `上次更新：已更新到 ${target}。`;
  }
  return `上次更新：${explain(result.error_code)}`;
}

function readable(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  return "读不到版本信息，请确认本机 TunnelMinion 仍在运行。";
}

const activePhases = new Set(["downloading", "installing", "restarting"]);

function UpdateConfirmDialog({
  view,
  busy,
  onCancel,
  onConfirm,
}: {
  view: UpdateView;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    escapeDisabled: busy,
    initialFocusRef: cancelRef,
    onEscape: onCancel,
  });
  const latest = view.latest;
  return (
    <div className="settings-dialog-backdrop">
      <div
        aria-describedby="update-confirm-description"
        aria-labelledby="update-confirm-title"
        aria-modal="true"
        className="settings-dialog"
        onKeyDown={handleKeyDown}
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
      >
        <h3 id="update-confirm-title">确认更新</h3>
        <div id="update-confirm-description">
          <p>
            从 {currentLabel(view)} 换到 {latest?.tag}（提交{" "}
            {shortRevision(latest?.source_revision ?? null)}）。
          </p>
          <p>
            先下载并校验，再停掉旧版、启动新版，网页会断开一到两分钟。新版起不来会自动退回现在的版本；数据和密钥不受影响。
          </p>
        </div>
        <div className="settings-actions settings-dialog__actions">
          <button
            disabled={busy}
            onClick={onCancel}
            ref={cancelRef}
            type="button"
          >
            取消
          </button>
          <button disabled={busy} onClick={onConfirm} type="button">
            {busy ? "正在提交……" : "确认更新"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function UpdatePanel() {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [restarted, setRestarted] = useState(false);
  const autoChecked = useRef(false);

  const query = useQuery({
    queryKey: updateQueryKey,
    queryFn: getUpdate,
    retry: false,
    refetchInterval: (current) =>
      restarting || activePhases.has(current.state.data?.job.phase ?? "idle")
        ? 1500
        : false,
  });

  const check = useMutation({
    mutationFn: checkUpdate,
    onSuccess: (view) => queryClient.setQueryData(updateQueryKey, view),
  });
  const apply = useMutation({
    mutationFn: applyUpdate,
    onSuccess: (view) => {
      queryClient.setQueryData(updateQueryKey, view);
      setConfirming(false);
      setRestarting(true);
    },
  });

  const view = query.data;
  const { mutate: runCheck } = check;
  useEffect(() => {
    if (
      view !== undefined &&
      view.supported &&
      view.checked_at === null &&
      !autoChecked.current
    ) {
      autoChecked.current = true;
      runCheck();
    }
  }, [view, runCheck]);

  // 新版本起来后，本机网页是一个新进程，任务回到 idle：说明换包已经结束
  useEffect(() => {
    if (restarting && view !== undefined && view.job.phase === "idle") {
      setRestarting(false);
      setRestarted(true);
    }
  }, [restarting, view]);

  const job = view?.job;
  const active = restarting || activePhases.has(job?.phase ?? "idle");
  const canUpdate =
    view !== undefined &&
    view.supported &&
    view.latest !== null &&
    (view.availability === "update_available" ||
      view.availability === "unknown") &&
    !active;

  return (
    <article aria-labelledby="update-title" className="settings-status-card">
      <div className="settings-status-card__heading">
        <h3 id="update-title">版本与更新</h3>
        {view === undefined ? null : (
          <span className="settings-status">{availabilityText(view)}</span>
        )}
      </div>
      {view === undefined ? (
        <p role={query.isPending ? "status" : "alert"}>
          {query.isPending ? "正在读取版本信息……" : readable(query.error)}
        </p>
      ) : (
        <>
          <dl className="settings-metadata">
            <div>
              <dt>当前版本</dt>
              <dd>{currentLabel(view)}</dd>
            </div>
            <div>
              <dt>最新版本</dt>
              <dd>
                {view.latest === null
                  ? "未知"
                  : `${view.latest.tag}（提交 ${shortRevision(view.latest.source_revision)}）`}
              </dd>
            </div>
          </dl>
          {view.supported ? null : (
            <p>{unsupportedText[view.unsupported_reason ?? "source_run"]}</p>
          )}
          {view.check_error === null ? null : (
            <p role="alert">{explain(view.check_error)}</p>
          )}
          {job?.phase === "downloading" ? (
            <p role="status">
              正在下载{" "}
              {Math.floor(
                (job.downloaded_bytes * 100) / Math.max(job.total_bytes, 1),
              )}
              %……旧版照常可用。
            </p>
          ) : null}
          {job?.phase === "installing" ? (
            <p role="status">正在校验并安装新版本……旧版照常可用。</p>
          ) : null}
          {restarting || job?.phase === "restarting" ? (
            <p role="status">
              正在停止旧版、启动新版，页面会断开一会儿，好了会自动显示结果。
            </p>
          ) : null}
          {job?.phase === "failed" ? (
            <p role="alert">{explain(job.error_code)}</p>
          ) : null}
          {restarted ? (
            <p role="status">
              {lastResultText(view) ?? "换包已结束。"}{" "}
              <button onClick={() => window.location.reload()} type="button">
                刷新页面
              </button>
            </p>
          ) : (
            lastResultText(view) && <p>{lastResultText(view)}</p>
          )}
          {check.isError ? <p role="alert">{readable(check.error)}</p> : null}
          {apply.isError ? <p role="alert">{readable(apply.error)}</p> : null}
          {view.supported ? (
            <div className="settings-actions">
              <button
                disabled={check.isPending || active}
                onClick={() => check.mutate()}
                type="button"
              >
                {check.isPending ? "正在检查……" : "检查更新"}
              </button>
              {canUpdate ? (
                <button onClick={() => setConfirming(true)} type="button">
                  更新到 {view.latest?.tag}
                </button>
              ) : null}
            </div>
          ) : null}
        </>
      )}
      {confirming && view !== undefined && view.latest !== null ? (
        <UpdateConfirmDialog
          busy={apply.isPending}
          onCancel={() => setConfirming(false)}
          onConfirm={() => apply.mutate(view.latest?.tag ?? "")}
          view={view}
        />
      ) : null}
    </article>
  );
}
