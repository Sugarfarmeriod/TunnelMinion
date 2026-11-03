import { useQuery } from "@tanstack/react-query";
import type { FormEvent, ReactNode } from "react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../../api/client";
import { requestJson } from "../../api/client";
import { resourceOverviewSchema } from "../../api/schemas/overview";
import type { ResourceOverview } from "../../api/schemas/overview";
import { RuntimeOverview } from "../overview/OverviewCards";
import { loadPeers, peersQueryKey } from "../service-map/api";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { isReadOnlyPreview } from "../../shared/previewMode";

import {
  borrowModel,
  deleteModelConfiguration,
  getModelConfiguration,
  saveModelConfiguration,
  stopBorrowingModel,
  validateModelConfiguration,
} from "./api";
import type { ModelConfiguration, ModelConfigurationInput } from "./api";
import { UpdatePanel } from "./UpdatePanel";
import "./settings.css";

const statusLabels: Record<ModelConfiguration["status"], string> = {
  unconfigured: "尚未配置",
  available: "模型可用",
  unavailable: "模型当前不可用",
};

const runtimeSummary: Record<ResourceOverview["local"]["runtime"], string> = {
  running: "TunnelMinion 在运行，但有些功能暂时用不了",
  starting: "TunnelMinion 正在启动",
  stopping: "TunnelMinion 正在停止",
  stopped: "TunnelMinion 已经停了",
  degraded: "TunnelMinion 在运行，但有些功能暂时用不了",
  unknown: "暂时不知道 TunnelMinion 是否正常",
};

const platformNames: Record<
  NonNullable<ResourceOverview["local"]["platform"]>,
  string
> = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
};

interface Notice {
  kind: "success" | "warning" | "error";
  message: string;
}

type Confirmation =
  | {
      kind: "save";
      input: ModelConfigurationInput;
      secretAction: string;
      returnFocus: HTMLElement | null;
    }
  | {
      kind: "delete";
      returnFocus: HTMLElement | null;
    };

function readableError(error: unknown): string {
  if (error instanceof ApiError) {
    return `${error.message}（${error.code}）`;
  }
  if (error instanceof Error && error.name === "ZodError") {
    return "本机程序返回的模型设置格式不对，页面没有显示它。";
  }
  return "读不到模型设置，请确认这台电脑上的 TunnelMinion 还开着。";
}

function SettingsConfirmationDialog({
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
    <div className="settings-dialog-backdrop">
      <div
        aria-describedby="settings-confirm-description"
        aria-labelledby="settings-confirm-title"
        aria-modal="true"
        className="settings-dialog"
        onKeyDown={handleKeyDown}
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
      >
        <h3 id="settings-confirm-title">{title}</h3>
        <div id="settings-confirm-description">{description}</div>
        <div className="settings-actions settings-dialog__actions">
          <button
            disabled={busy}
            onClick={onCancel}
            ref={cancelRef}
            type="button"
          >
            取消
          </button>
          <button
            className="settings-button--danger"
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

export function SettingsPage() {
  const query = useQuery({
    queryKey: ["model-configuration"],
    queryFn: getModelConfiguration,
    retry: false,
  });
  const systemQuery = useQuery({
    queryKey: ["resource-overview"],
    queryFn: () =>
      requestJson("/api/resources/overview", resourceOverviewSchema),
    retry: false,
  });
  const peersQuery = useQuery({
    queryKey: peersQueryKey,
    queryFn: loadPeers,
    retry: false,
  });
  const [endpoint, setEndpoint] = useState("");
  const [model, setModel] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState("30");
  const [disableThinking, setDisableThinking] = useState(false);
  const [maxTools, setMaxTools] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [clearApiKey, setClearApiKey] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [writing, setWriting] = useState(false);
  const [deleteUncertain, setDeleteUncertain] = useState(false);
  const refreshRef = useRef<HTMLButtonElement>(null);
  const saveButtonRef = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (query.data === undefined) {
      return;
    }
    setEndpoint(query.data.endpoint ?? "");
    setModel(query.data.model ?? "");
    setTimeoutSeconds(String(query.data.timeout_seconds ?? 30));
    setDisableThinking(query.data.disable_thinking);
    setMaxTools(
      query.data.max_tools === null ? "" : String(query.data.max_tools),
    );
    setClearApiKey(false);
    // 服务端响应永远不能填充这个字段；用户输入也会在每次写请求后立即清空。
    setApiKey("");
  }, [query.data]);

  function reviewSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedEndpoint = endpoint.trim();
    const normalizedModel = model.trim();
    const timeout = Number(timeoutSeconds);
    if (
      normalizedEndpoint === "" ||
      normalizedModel === "" ||
      !Number.isFinite(timeout) ||
      timeout < 0.1 ||
      timeout > 600
    ) {
      setFormError(
        "请填好模型服务地址和模型名称；超时要在 0.1–600 秒之间（在“高级”里）。",
      );
      return;
    }
    const toolLimit = maxTools.trim() === "" ? null : Number(maxTools);
    if (
      toolLimit !== null &&
      (!Number.isInteger(toolLimit) || toolLimit < 3 || toolLimit > 12)
    ) {
      setFormError("工具上限请填 3–12 的整数，或留空表示不限制。");
      return;
    }
    const input: ModelConfigurationInput = {
      endpoint: normalizedEndpoint,
      model: normalizedModel,
      timeout_seconds: timeout,
      disable_thinking: disableThinking,
      max_tools: toolLimit,
    };
    let secretAction = "沿用这个地址已保存的密钥";
    if (clearApiKey) {
      input.api_key = "";
      secretAction = "删掉已保存的密钥";
    } else if (apiKey !== "") {
      input.api_key = apiKey;
      secretAction = "换成新填的密钥（确认页不会显示密钥内容）";
    }
    setFormError(null);
    setConfirmation({
      kind: "save",
      input,
      secretAction,
      returnFocus: saveButtonRef.current,
    });
  }

  async function confirmWrite() {
    if (confirmation === null || writing) {
      return;
    }
    setWriting(true);
    setNotice(null);

    if (confirmation.kind === "save") {
      let response: ModelConfiguration | undefined;
      let requestError: unknown;
      try {
        response = await saveModelConfiguration(confirmation.input);
      } catch (error) {
        requestError = error;
      } finally {
        setApiKey("");
      }
      const refreshed = await query.refetch();
      const confirmed =
        response !== undefined &&
        refreshed.data?.endpoint === response.endpoint &&
        refreshed.data.model === response.model &&
        refreshed.data.timeout_seconds === response.timeout_seconds &&
        refreshed.data.disable_thinking === response.disable_thinking &&
        refreshed.data.max_tools === response.max_tools;
      if (confirmed) {
        setDeleteUncertain(false);
        setNotice({
          kind: "success",
          message: "已保存。可以点“测试模型能不能用”确认一下。",
        });
      } else if (requestError instanceof ApiError) {
        setNotice({ kind: "error", message: readableError(requestError) });
      } else {
        setNotice({
          kind: "warning",
          message:
            "不确定刚才有没有保存成功。页面只重新读了一次设置，没有再保存一遍；请先看看下面的设置对不对。",
        });
      }
    } else {
      let requestError: unknown;
      try {
        await deleteModelConfiguration();
      } catch (error) {
        requestError = error;
      } finally {
        setApiKey("");
      }
      if (requestError === undefined) {
        setDeleteUncertain(false);
        setNotice({
          kind: "success",
          message: "已清除模型设置和保存的密钥。",
        });
        await query.refetch();
      } else {
        await query.refetch();
        setDeleteUncertain(true);
        const detail =
          requestError instanceof ApiError
            ? `清除失败：${readableError(requestError)}。`
            : "不确定刚才有没有清除成功。";
        setNotice({
          kind: "warning",
          message: `${detail} 即使下面显示“尚未配置”，系统凭据库里的密钥也可能还在。页面没有自动重试；确认后可以点“重试清除配置与密钥”。`,
        });
      }
    }

    setWriting(false);
    setConfirmation(null);
  }

  async function validateOnce() {
    if (writing) {
      return;
    }
    setWriting(true);
    setNotice(null);
    let response: ModelConfiguration | undefined;
    let requestError: unknown;
    try {
      response = await validateModelConfiguration();
    } catch (error) {
      requestError = error;
    }
    const refreshed = await query.refetch();
    if (
      response !== undefined &&
      refreshed.data?.status === response.status &&
      refreshed.data.error_code === response.error_code
    ) {
      setNotice({
        kind: response.status === "available" ? "success" : "warning",
        message:
          response.status === "available"
            ? "测试通过：模型现在能用。"
            : "测试做完了，模型还是用不了；地图、服务清单和记忆不受影响。",
      });
    } else if (requestError instanceof ApiError) {
      setNotice({ kind: "error", message: readableError(requestError) });
    } else {
      setNotice({
        kind: "warning",
        message: "不确定测试结果。页面没有自动重测，只重新读了一次设置。",
      });
    }
    setWriting(false);
  }

  /** 借用或停止借用都只发一次请求；失败时原配置不变，页面只重新读一次。 */
  async function changeBorrowing(
    target: { kind: "borrow"; nodeId: string; name: string } | { kind: "stop" },
  ) {
    if (writing) {
      return;
    }
    setWriting(true);
    setNotice(null);
    try {
      if (target.kind === "borrow") {
        await borrowModel(target.nodeId);
        setNotice({
          kind: "success",
          message: `已改为借用 ${target.name} 的模型，可以去地图上提问了。`,
        });
      } else {
        const view = await stopBorrowingModel();
        setNotice({
          kind: "success",
          message:
            view.profiles.length > 0
              ? "已停止借用。这台电脑现在没有模型：可以再借一台，或在下面“以前用过的模型”里选回自己的模型。"
              : "已停止借用。这台电脑现在没有模型：可以再借一台，或在下面填好自己的模型。",
        });
      }
    } catch (error) {
      setNotice({
        kind: "error",
        message:
          target.kind === "borrow"
            ? `没借到 ${target.name} 的模型：${
                error instanceof ApiError && error.status === 404
                  ? "这台电脑找不到它的连接，确认它在“电脑与朋友”里并且开着。"
                  : readableError(error)
              }`
            : `没能停止借用：${readableError(error)}`,
      });
    }
    await query.refetch();
    setWriting(false);
  }

  const data = query.data;
  const selectedProfile = data?.profiles.find(
    (item) => item.endpoint === endpoint.trim() && item.model === model.trim(),
  );
  const selectedApiKeyConfigured =
    selectedProfile?.api_key_configured ??
    (data?.endpoint === endpoint.trim() && data.model === model.trim()
      ? data.api_key_configured
      : false);

  const borrowedFrom =
    data?.borrowed_from === null || data?.borrowed_from === undefined
      ? null
      : (peersQuery.data?.peers.find(
          (peer) => peer.node_id === data.borrowed_from,
        )?.display_name ?? `另一台电脑（${data.borrowed_from.slice(-8)}）`);
  const system = systemQuery.data;
  // 能借模型的只有已经加进来的电脑：先列我自己的，再列朋友的；对方要在它那边允许这台电脑借。
  const lenders = (peersQuery.data?.peers ?? [])
    .filter(
      (peer) =>
        !peer.is_local &&
        (peer.relationship === "mine" || peer.relationship === "friend") &&
        peer.node_id !== data?.borrowed_from,
    )
    .sort(
      (a, b) =>
        Number(a.relationship !== "mine") - Number(b.relationship !== "mine"),
    );

  return (
    <section aria-labelledby="settings-title" className="settings-page surface">
      <header className="settings-page__header">
        <div>
          <h2 id="settings-title" ref={headingRef} tabIndex={-1}>
            设置
          </h2>
          <p className="page-lead">
            TunnelMinion 自己的几样设置：用哪个 AI
            模型、这台电脑是否正常、版本更新，以及出问题时导出求助用的诊断包。
          </p>
        </div>
        <button
          disabled={query.isFetching || writing}
          onClick={() => {
            void query.refetch();
            void systemQuery.refetch();
          }}
          ref={refreshRef}
          type="button"
        >
          {query.isFetching ? "正在重新读取……" : "重新读取"}
        </button>
      </header>

      <article
        aria-labelledby="system-status-title"
        className="settings-status-card"
      >
        <div className="settings-status-card__heading">
          <h3 id="system-status-title">这台电脑现在怎么样</h3>
          <span
            className={`settings-status settings-status--${
              system === undefined
                ? "unconfigured"
                : system.local.readiness === "ready"
                  ? "available"
                  : "unavailable"
            }`}
          >
            {system === undefined
              ? systemQuery.isPending
                ? "正在读取"
                : "暂时不知道"
              : system.local.readiness === "ready"
                ? "正常"
                : "需要留意"}
          </span>
        </div>
        <p className="page-lead">
          TunnelMinion 在这台电脑上有没有正常运行。不正常时，先看这里。
        </p>
        {system === undefined ? (
          <div role={systemQuery.isPending ? "status" : "alert"}>
            <p>
              {systemQuery.isPending
                ? "正在读取这台电脑的运行状态……"
                : "暂时读不到运行状态；模型设置和诊断包仍可单独使用。"}
            </p>
            {systemQuery.isPending ? null : (
              <button onClick={() => void systemQuery.refetch()} type="button">
                重新读取运行状态
              </button>
            )}
          </div>
        ) : (
          <>
            <p>
              {system.local.readiness === "ready" &&
              system.local.runtime === "running"
                ? "一切正常：TunnelMinion 正在运行。"
                : `${runtimeSummary[system.local.runtime]}。先确认这台电脑上的 TunnelMinion 还开着，再点“重新读取”。`}
            </p>
            <p className="settings-facts">
              {system.local.platform === null
                ? "系统未知"
                : platformNames[system.local.platform]}{" "}
              · 版本 {system.local.version ?? "未知"}
            </p>
            {systemQuery.isRefetchError ? (
              <p role="alert">刷新失败，上面是上一次读到的状态。</p>
            ) : null}
            <details className="advanced">
              <summary>高级：运行细节</summary>
              <p className="advanced-hint">
                排查问题时才用得上的内部状态。“Coordinator”是可选的多电脑目录服务，没配置也不影响使用；“网络路径”是这台电脑和其他电脑之间走哪条线。
              </p>
              <RuntimeOverview data={system} />
            </details>
          </>
        )}
      </article>

      {notice === null ? null : (
        <p
          className={`settings-notice settings-notice--${notice.kind}`}
          role={notice.kind === "success" ? "status" : "alert"}
        >
          {notice.message}
        </p>
      )}

      {query.isPending ? (
        <p aria-live="polite" role="status">
          正在读取模型设置……
        </p>
      ) : data === undefined ? (
        <div className="settings-query-error" role="alert">
          <h3>现在读不到模型设置</h3>
          <p>{readableError(query.error)}</p>
          <button onClick={() => void query.refetch()} type="button">
            重新读取
          </button>
        </div>
      ) : (
        <article
          aria-labelledby="model-status-title"
          className="settings-status-card"
        >
          {query.isRefetchError ? (
            <p
              className="settings-notice settings-notice--warning"
              role="alert"
            >
              重新读取失败。下面是上一次读到的设置，可能已经变了。
            </p>
          ) : null}
          <div className="settings-status-card__heading">
            <h3 id="model-status-title">AI 模型</h3>
            <span className={`settings-status settings-status--${data.status}`}>
              {statusLabels[data.status]}
            </span>
          </div>
          <p className="page-lead">
            Agent
            用这个模型回答你的问题、调查服务为什么出问题。没设置时，地图和服务清单照样能用，只是不能提问。
          </p>
          {data.status === "unconfigured" ? (
            <p role="status">
              还没设置模型。在下面填好模型服务地址和名称就能用。
            </p>
          ) : borrowedFrom !== null ? (
            <div className="settings-borrowing">
              <p>正在借用 {borrowedFrom} 的模型，这台电脑不用自己配置。</p>
              <button
                disabled={isReadOnlyPreview() || writing}
                onClick={() => void changeBorrowing({ kind: "stop" })}
                type="button"
              >
                停止借用
              </button>
            </div>
          ) : (
            <dl className="settings-metadata">
              <div>
                <dt>模型服务地址</dt>
                <dd>{data.endpoint ?? "未返回"}</dd>
              </div>
              <div>
                <dt>模型名称</dt>
                <dd>{data.model ?? "未返回"}</dd>
              </div>
              <div>
                <dt>API 密钥</dt>
                <dd>{data.api_key_configured ? "已安全保存" : "未保存"}</dd>
              </div>
            </dl>
          )}
          {data.error_code === null && data.error_message === null ? null : (
            <div className="settings-provider-error" role="alert">
              <strong>模型报错</strong>
              <p>{data.error_message ?? "模型没有给出错误说明。"}</p>
              <span>{data.error_code ?? "unknown_provider_error"}</span>
            </div>
          )}
          {data.borrowed_from === null && data.status === "unavailable" ? (
            <p className="settings-recovery">
              先确认模型服务开着，再核对下面的地址、模型名称和密钥。模型不可用时，地图、服务清单和记忆照常能用。
            </p>
          ) : null}

          <section
            aria-labelledby="settings-borrow-title"
            className="settings-borrow"
          >
            <h4 id="settings-borrow-title">
              {data.borrowed_from === null
                ? "借用别的电脑的模型"
                : "改借另一台电脑的模型"}
            </h4>
            <p className="advanced-hint">
              这台电脑不用自己装模型，可以借另一台电脑已经配好的。你自己的电脑默认允许互相借；朋友的电脑要对方在“电脑与朋友”里打开“允许借我的模型”。点了之后会先试着调用一次，借不到会告诉你原因。
            </p>
            {peersQuery.isPending ? (
              <p role="status">正在读取可以借的电脑……</p>
            ) : lenders.length === 0 ? (
              <p>
                {data.borrowed_from === null
                  ? "还没有可以借的电脑。先在“电脑与朋友”里加上你的其他电脑。"
                  : "没有别的电脑可以改借。"}
              </p>
            ) : (
              <div className="settings-actions">
                {lenders.map((peer) => (
                  <button
                    disabled={isReadOnlyPreview() || writing}
                    key={peer.node_id}
                    onClick={() =>
                      void changeBorrowing({
                        kind: "borrow",
                        nodeId: peer.node_id,
                        name: peer.display_name,
                      })
                    }
                    type="button"
                  >
                    借用 {peer.display_name} 的模型
                    {peer.relationship === "friend" ? "（朋友）" : ""}
                  </button>
                ))}
              </div>
            )}
          </section>

          <form className="settings-form" onSubmit={reviewSave}>
            <fieldset
              disabled={isReadOnlyPreview() || writing || deleteUncertain}
            >
              <legend>
                {data.status === "unconfigured" ? "设置模型" : "换一个模型"}
              </legend>
              {/* 正在用某个本机模型时，只有一份档案就不必再选；没在用时（未配置或在借用）有一份也给出来。 */}
              {data.profiles.length > (data.endpoint === null ? 0 : 1) ? (
                <>
                  <label>
                    以前用过的模型
                    <select
                      onChange={(event) => {
                        const profile =
                          data.profiles[Number(event.currentTarget.value)];
                        if (profile === undefined) {
                          return;
                        }
                        setEndpoint(profile.endpoint);
                        setModel(profile.model);
                        setTimeoutSeconds(String(profile.timeout_seconds));
                        setDisableThinking(profile.disable_thinking);
                        setMaxTools(
                          profile.max_tools === null
                            ? ""
                            : String(profile.max_tools),
                        );
                        setApiKey("");
                        setClearApiKey(false);
                        setFormError(null);
                      }}
                      value=""
                    >
                      <option value="">选一个，自动填到下面</option>
                      {data.profiles.map((profile, index) => (
                        <option
                          key={`${profile.endpoint}\n${profile.model}`}
                          value={index}
                        >
                          {profile.model} — {profile.endpoint}
                        </option>
                      ))}
                    </select>
                  </label>
                  <p className="settings-secret-note">
                    选了只是填表，点“检查并确认保存”后才切换；
                    {selectedApiKeyConfigured
                      ? "这个地址已经存过密钥，密钥框留空就沿用。"
                      : "这个地址还没存过密钥。"}
                  </p>
                </>
              ) : null}
              <label>
                模型服务地址
                <input
                  aria-describedby="settings-endpoint-hint"
                  autoComplete="url"
                  onChange={(event) => setEndpoint(event.currentTarget.value)}
                  placeholder="http://127.0.0.1:8080/v1"
                  required
                  type="url"
                  value={endpoint}
                />
              </label>
              <p className="settings-field-hint" id="settings-endpoint-hint">
                兼容 OpenAI 接口的地址，比如本机 llama-server 一般是
                http://127.0.0.1:8080/v1
              </p>
              <label>
                模型名称
                <input
                  aria-describedby="settings-model-hint"
                  autoComplete="off"
                  onChange={(event) => setModel(event.currentTarget.value)}
                  required
                  value={model}
                />
              </label>
              <p className="settings-field-hint" id="settings-model-hint">
                模型服务里这个模型的名字，比如 deepseek-chat、qwen3-8b
              </p>
              {data.borrowed_from === null ? (
                <>
                  <label>
                    新 API 密钥（可选）
                    <input
                      aria-describedby="settings-key-hint"
                      autoComplete="new-password"
                      disabled={clearApiKey || writing}
                      maxLength={4096}
                      onChange={(event) => setApiKey(event.currentTarget.value)}
                      placeholder={
                        selectedApiKeyConfigured
                          ? "留空就沿用已保存的密钥"
                          : "不需要密钥就留空"
                      }
                      type="password"
                      value={apiKey}
                    />
                  </label>
                  <p className="settings-field-hint" id="settings-key-hint">
                    云端模型才需要，本机模型一般留空。密钥存在这台电脑的系统凭据库里，之后页面不会再显示它。
                  </p>
                  {selectedApiKeyConfigured ? (
                    <label className="settings-checkbox">
                      <input
                        checked={clearApiKey}
                        onChange={(event) => {
                          const checked = event.currentTarget.checked;
                          setClearApiKey(checked);
                          if (checked) {
                            setApiKey("");
                          }
                        }}
                        type="checkbox"
                      />
                      保存时顺便删掉已保存的密钥
                    </label>
                  ) : null}
                </>
              ) : null}
              <details className="advanced">
                <summary>高级：速度与工具</summary>
                <p className="advanced-hint">
                  一般不用动。本机跑的小模型比较慢、容易乱时，再按下面的说明调。
                </p>
                <div className="settings-advanced-fields">
                  <label>
                    超时（秒）
                    <input
                      aria-describedby="settings-timeout-hint"
                      max={600}
                      min={0.1}
                      onChange={(event) =>
                        setTimeoutSeconds(event.currentTarget.value)
                      }
                      required
                      step={0.1}
                      type="number"
                      value={timeoutSeconds}
                    />
                  </label>
                  <p className="settings-field-hint" id="settings-timeout-hint">
                    模型多久没回话就算失败。本机模型慢，可以调大。
                  </p>
                  <label className="settings-checkbox">
                    <input
                      aria-describedby="settings-thinking-hint"
                      checked={disableThinking}
                      onChange={(event) =>
                        setDisableThinking(event.currentTarget.checked)
                      }
                      type="checkbox"
                    />
                    关闭思考模式（更快，适合本机 Qwen）
                  </label>
                  <p
                    className="settings-field-hint"
                    id="settings-thinking-hint"
                  >
                    让模型跳过“先想一遍”直接回答。本机小模型建议勾上。
                  </p>
                  <label>
                    工具上限（本机小模型建议 5，留空不限制）
                    <input
                      aria-describedby="settings-tools-hint"
                      max={12}
                      min={3}
                      onChange={(event) =>
                        setMaxTools(event.currentTarget.value)
                      }
                      placeholder="不限制"
                      step={1}
                      type="number"
                      value={maxTools}
                    />
                  </label>
                  <p className="settings-field-hint" id="settings-tools-hint">
                    一次最多给模型几样工具。小模型拿到的工具太多容易选错。
                  </p>
                </div>
              </details>
            </fieldset>
            {formError === null ? null : (
              <p className="settings-inline-error" role="alert">
                {formError}
              </p>
            )}
            <div className="settings-actions">
              <button
                disabled={isReadOnlyPreview() || writing || deleteUncertain}
                ref={saveButtonRef}
                type="submit"
              >
                检查并确认保存
              </button>
              <button
                disabled={
                  isReadOnlyPreview() ||
                  writing ||
                  deleteUncertain ||
                  data.status === "unconfigured"
                }
                onClick={() => void validateOnce()}
                type="button"
              >
                测试模型能不能用
              </button>
              <button
                className="settings-button--danger-outline"
                disabled={
                  isReadOnlyPreview() ||
                  writing ||
                  (data.status === "unconfigured" && !deleteUncertain)
                }
                onClick={(event) =>
                  setConfirmation({
                    kind: "delete",
                    returnFocus: event.currentTarget,
                  })
                }
                type="button"
              >
                {deleteUncertain ? "重试清除配置与密钥" : "清除模型配置与密钥"}
              </button>
            </div>
          </form>
        </article>
      )}

      <article
        className="settings-status-card"
        aria-labelledby="peer-settings-title"
      >
        <h3 id="peer-settings-title">其他电脑和朋友</h3>
        <p className="page-lead">
          加电脑、邀请朋友、决定谁能用你的服务，都在“电脑与朋友”页。
        </p>
        <Link className="pixel-button settings-link-button" to="/app/people">
          去“电脑与朋友”
        </Link>
      </article>

      <UpdatePanel />

      <article
        aria-labelledby="diagnostics-export-title"
        className="settings-status-card"
      >
        <h3 id="diagnostics-export-title">出问题时：导出诊断包</h3>
        <p className="page-lead">
          想请别人帮忙查问题时，下载这个文件发给对方。里面只有运行状态和排查线索，不含模型密钥、登录凭据和聊天内容。
        </p>
        <a
          className="pixel-button settings-link-button"
          download
          href="/api/diagnostics/export"
        >
          下载脱敏诊断包
        </a>
        <details className="advanced settings-recovery-guide">
          <summary>自己先排查：按这个顺序看</summary>
          <ol>
            <li>先看上面“这台电脑现在怎么样”是不是正常。</li>
            <li>
              别的电脑连不上时，回服务地图看两台电脑之间的连线；连不上不一定是防火墙挡了。
            </li>
            <li>
              有些检查要额外的工具或权限（比如 Mac 的 Murus 防火墙日志、厂商 VPN
              工具），没有时只会显示“不可用”，不影响其他功能。
            </li>
            <li>还是不行，就把刚下载的诊断包发给帮你的人。</li>
          </ol>
        </details>
      </article>

      {confirmation === null ? null : (
        <SettingsConfirmationDialog
          busy={writing}
          confirmLabel={
            confirmation.kind === "save" ? "确认保存一次" : "确认清除一次"
          }
          description={
            confirmation.kind === "save" ? (
              <>
                <p>模型服务地址：{confirmation.input.endpoint}</p>
                <p>模型：{confirmation.input.model}</p>
                <p>超时：{confirmation.input.timeout_seconds} 秒</p>
                <p>
                  关闭思考模式：
                  {confirmation.input.disable_thinking ? "是" : "否"}
                </p>
                <p>
                  工具上限：
                  {confirmation.input.max_tools === null
                    ? "不限制"
                    : `${confirmation.input.max_tools} 个`}
                </p>
                <p>密钥处理：{confirmation.secretAction}</p>
              </>
            ) : (
              <p>
                会同时清除模型设置和系统凭据库里保存的模型密钥；记忆、服务清单和电脑名单都不会动。
              </p>
            )
          }
          fallbackFocus={refreshRef.current}
          onCancel={() => setConfirmation(null)}
          onConfirm={() => void confirmWrite()}
          returnFocus={confirmation.returnFocus}
          safeFallbackFocus={headingRef.current}
          title={
            confirmation.kind === "save"
              ? "确认保存模型配置"
              : "确认清除模型配置"
          }
        />
      )}
    </section>
  );
}
