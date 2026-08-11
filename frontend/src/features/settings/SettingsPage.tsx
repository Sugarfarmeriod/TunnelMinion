import { useQuery } from "@tanstack/react-query";
import type { FormEvent, ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import { ApiError } from "../../api/client";
import { requestJson } from "../../api/client";
import { resourceOverviewSchema } from "../../api/schemas/overview";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";

import {
  deleteModelConfiguration,
  getModelConfiguration,
  saveModelConfiguration,
  validateModelConfiguration,
} from "./api";
import type { ModelConfiguration, ModelConfigurationInput } from "./api";
import "./settings.css";

const statusLabels: Record<ModelConfiguration["status"], string> = {
  unconfigured: "尚未配置",
  available: "模型可用",
  unavailable: "模型当前不可用",
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
    return "服务返回的模型配置包含未允许的字段或不符合脱敏契约，页面已拒绝显示。";
  }
  return "无法读取模型配置，请确认本机 TunnelMinion 仍在运行。";
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
    enabled: query.isSuccess,
    retry: false,
  });
  const [endpoint, setEndpoint] = useState("");
  const [model, setModel] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState("30");
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
      setFormError("请填写 endpoint、模型名称，以及 0.1–600 秒的超时时间。 ");
      return;
    }
    const input: ModelConfigurationInput = {
      endpoint: normalizedEndpoint,
      model: normalizedModel,
      timeout_seconds: timeout,
    };
    let secretAction = "保留当前已保存的密钥";
    if (clearApiKey) {
      input.api_key = "";
      secretAction = "清除当前已保存的密钥";
    } else if (apiKey !== "") {
      input.api_key = apiKey;
      secretAction = "替换密钥（值不会显示在确认页或服务端响应中）";
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
        refreshed.data.timeout_seconds === response.timeout_seconds;
      if (confirmed) {
        setDeleteUncertain(false);
        setNotice({
          kind: "success",
          message: "服务端已验证、保存并重新返回脱敏模型配置。",
        });
      } else if (requestError instanceof ApiError) {
        setNotice({ kind: "error", message: readableError(requestError) });
      } else {
        setNotice({
          kind: "warning",
          message:
            "保存请求的结果无法确认。页面只重新读取了配置，没有自动重放写请求；请先核对当前状态。",
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
          message: "服务端已用 204 明确确认：模型配置和已保存密钥均已清除。",
        });
        await query.refetch();
      } else {
        await query.refetch();
        setDeleteUncertain(true);
        const detail =
          requestError instanceof ApiError
            ? `服务端报告 ${readableError(requestError)}。`
            : "请求响应丢失或无法读取。";
        setNotice({
          kind: "warning",
          message: `${detail} 即使重读显示“未配置”，也无法确认操作系统秘密存储中的密钥是否已清除。页面没有自动重放；请只使用重新读取，或在明确确认后手动重试清除。`,
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
            ? "服务端已重新验证：模型现在可用。"
            : "服务端已完成验证，模型仍不可用；资源与记忆功能不受影响。",
      });
    } else if (requestError instanceof ApiError) {
      setNotice({ kind: "error", message: readableError(requestError) });
    } else {
      setNotice({
        kind: "warning",
        message:
          "验证请求的结果无法确认。页面没有自动重放验证，只重新读取了当前配置。",
      });
    }
    setWriting(false);
  }

  const data = query.data;

  return (
    <section aria-labelledby="settings-title" className="settings-page surface">
      <header className="settings-page__header">
        <div>
          <p className="eyebrow">脱敏的本机配置</p>
          <h2 id="settings-title" ref={headingRef} tabIndex={-1}>
            模型设置
          </h2>
          <p>
            页面只显示非秘密字段和“是否已保存密钥”。密钥不会从服务端返回，也不会写入浏览器存储。
          </p>
        </div>
        <button
          disabled={query.isFetching || writing}
          onClick={() => void query.refetch()}
          ref={refreshRef}
          type="button"
        >
          {query.isFetching ? "正在重新读取……" : "重新读取状态"}
        </button>
      </header>

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
          正在读取脱敏模型配置……
        </p>
      ) : data === undefined ? (
        <div className="settings-query-error" role="alert">
          <h3>现在读不到模型配置</h3>
          <p>{readableError(query.error)}</p>
          <button onClick={() => void query.refetch()} type="button">
            重新读取
          </button>
        </div>
      ) : (
        <>
          {query.isRefetchError ? (
            <p
              className="settings-notice settings-notice--warning"
              role="alert"
            >
              重新读取失败。下面是上一次成功读取的缓存，不能视为当前事实。
            </p>
          ) : null}

          <article
            aria-labelledby="model-status-title"
            className="settings-status-card"
          >
            <div className="settings-status-card__heading">
              <h3 id="model-status-title">当前状态</h3>
              <span
                className={`settings-status settings-status--${data.status}`}
              >
                {statusLabels[data.status]}
              </span>
            </div>
            {data.status === "unconfigured" ? (
              <p role="status">
                还没有模型配置。聊天的新 AI run
                暂不可用，但长期记忆和确定性资源仍可管理。
              </p>
            ) : (
              <dl className="settings-metadata">
                <div>
                  <dt>Endpoint</dt>
                  <dd>{data.endpoint ?? "未返回"}</dd>
                </div>
                <div>
                  <dt>模型</dt>
                  <dd>{data.model ?? "未返回"}</dd>
                </div>
                <div>
                  <dt>超时</dt>
                  <dd>
                    {data.timeout_seconds === null
                      ? "未返回"
                      : `${data.timeout_seconds} 秒`}
                  </dd>
                </div>
                <div>
                  <dt>API 密钥</dt>
                  <dd>{data.api_key_configured ? "已安全保存" : "未保存"}</dd>
                </div>
              </dl>
            )}
            {data.error_code === null && data.error_message === null ? null : (
              <div className="settings-provider-error" role="alert">
                <strong>模型验证错误</strong>
                <span>{data.error_code ?? "unknown_provider_error"}</span>
                <p>{data.error_message ?? "服务没有返回错误说明。"}</p>
              </div>
            )}
            <p className="settings-recovery">
              {data.status === "available"
                ? "模型可用，无需处理。"
                : "先确认模型服务正在运行，再核对 endpoint、模型名称和密钥。即使模型不可用，长期记忆与确定性资源仍可使用。"}
            </p>
          </article>

          <form className="settings-form" onSubmit={reviewSave}>
            <fieldset disabled={writing || deleteUncertain}>
              <legend>受限模型配置入口</legend>
              <label>
                OpenAI-compatible endpoint
                <input
                  autoComplete="url"
                  onChange={(event) => setEndpoint(event.currentTarget.value)}
                  placeholder="http://127.0.0.1:8080/v1"
                  required
                  type="url"
                  value={endpoint}
                />
              </label>
              <label>
                模型名称
                <input
                  autoComplete="off"
                  onChange={(event) => setModel(event.currentTarget.value)}
                  required
                  value={model}
                />
              </label>
              <label>
                超时（秒）
                <input
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
              <label>
                新 API 密钥（可选）
                <input
                  autoComplete="new-password"
                  disabled={clearApiKey || writing}
                  maxLength={4096}
                  onChange={(event) => setApiKey(event.currentTarget.value)}
                  placeholder={
                    data.api_key_configured
                      ? "留空会保留已保存密钥"
                      : "无密钥 Provider 可留空"
                  }
                  type="password"
                  value={apiKey}
                />
              </label>
              {data.api_key_configured ? (
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
                  保存配置时清除已保存密钥
                </label>
              ) : null}
              <p className="settings-secret-note">
                密钥只随这一次同源保存请求进入现有受限配置流程；页面不会读回、记录或导出它。
              </p>
            </fieldset>
            {formError === null ? null : (
              <p className="settings-inline-error" role="alert">
                {formError}
              </p>
            )}
            <div className="settings-actions">
              <button
                disabled={writing || deleteUncertain}
                ref={saveButtonRef}
                type="submit"
              >
                检查并确认保存
              </button>
              <button
                disabled={
                  writing || deleteUncertain || data.status === "unconfigured"
                }
                onClick={() => void validateOnce()}
                type="button"
              >
                重新验证一次
              </button>
              <button
                className="settings-button--danger-outline"
                disabled={
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
        </>
      )}

      <article
        aria-labelledby="system-status-title"
        className="settings-status-card"
      >
        <div className="settings-status-card__heading">
          <h3 id="system-status-title">Runtime、Coordinator 与网络路径</h3>
          <span className="settings-status">
            {systemQuery.data === undefined
              ? systemQuery.isPending
                ? "正在读取"
                : "当前未知"
              : systemQuery.data.local.readiness === "ready"
                ? "本机就绪"
                : "需要留意"}
          </span>
        </div>
        {systemQuery.data === undefined ? (
          <div role={systemQuery.isPending ? "status" : "alert"}>
            <p>
              {systemQuery.isPending
                ? "正在读取本机运行状态……"
                : "暂时读不到本机总览；模型设置和诊断下载仍可独立使用。"}
            </p>
            {systemQuery.isPending ? null : (
              <button onClick={() => void systemQuery.refetch()} type="button">
                重试读取运行状态
              </button>
            )}
          </div>
        ) : (
          <dl className="settings-metadata">
            <div>
              <dt>Runtime</dt>
              <dd>{systemQuery.data.local.runtime}</dd>
            </div>
            <div>
              <dt>平台 / 版本</dt>
              <dd>
                {systemQuery.data.local.platform ?? "unknown"} /{" "}
                {systemQuery.data.local.version ?? "unknown"}
              </dd>
            </div>
            <div>
              <dt>Package</dt>
              <dd>
                {systemQuery.data.local.package.kind} /{" "}
                {systemQuery.data.local.package.version ?? "unknown"}
              </dd>
            </div>
            <div>
              <dt>Coordinator</dt>
              <dd>
                {systemQuery.data.coordinator.state}（
                {systemQuery.data.coordinator.freshness}）
              </dd>
            </div>
            <div>
              <dt>网络路径</dt>
              <dd>
                {systemQuery.data.network_path.state}（probe:{" "}
                {systemQuery.data.network_path.probe.status}）
              </dd>
            </div>
            <div>
              <dt>证据时间</dt>
              <dd>
                {systemQuery.data.network_path.evidence_at ??
                  "尚无网络路径证据"}
              </dd>
            </div>
          </dl>
        )}
        <p className="settings-recovery">
          Coordinator
          或网络路径不可用时，本机资源、记忆和已有操作清理仍应继续工作；总览页提供更完整的来源与新鲜度说明。
        </p>
      </article>

      <article
        aria-labelledby="diagnostics-export-title"
        className="settings-diagnostics-card"
      >
        <div>
          <p className="eyebrow">只读、脱敏</p>
          <h3 id="diagnostics-export-title">导出诊断包</h3>
          <p>
            下载当前本机状态、可选诊断来源和恢复建议。诊断包不会包含模型密钥、Gateway
            token、认证头、私钥或完整聊天内容，也不会保存到浏览器存储。
          </p>
        </div>
        <a
          className="settings-download-link"
          download
          href="/api/diagnostics/export"
        >
          下载脱敏诊断包
        </a>
        <div className="settings-recovery-guide">
          <h4>看不懂状态时，按这个顺序来</h4>
          <ol>
            <li>先看总览里的本机 Runtime 是否正在运行。</li>
            <li>再看真实 probe 结果；不可达不等于一定是防火墙。</li>
            <li>
              没有 Murus、防火墙日志权限或厂商 VPN
              工具时，相关来源只会显示“不可用”，不会阻止 TunnelMinion
              的其他功能。
            </li>
            <li>需要协助时，把刚下载的脱敏 JSON 发给维护者。</li>
          </ol>
        </div>
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
                <p>Endpoint：{confirmation.input.endpoint}</p>
                <p>模型：{confirmation.input.model}</p>
                <p>超时：{confirmation.input.timeout_seconds} 秒</p>
                <p>密钥处理：{confirmation.secretAction}</p>
              </>
            ) : (
              <p>
                将同时清除非秘密模型配置和操作系统秘密存储中的模型密钥；长期记忆与确定性资源不会被删除。
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
