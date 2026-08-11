import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { ActionConfirmationDialog } from "./ActionConfirmationDialog";
import {
  formatOperationTime,
  operationActionLabels,
  operationStatusLabels,
  operationTone,
  readableOperationError,
} from "./operationPresentation";
import {
  getOperation,
  isUnknownOperationWriteError,
  operationActionWasAdjudicated,
  operationQueryKeys,
  serverAllowsAction,
  submitOperationAction,
  type OperationActionPayload,
  type PendingOperationAction,
} from "./operationsApi";
import type { OperationAction, OperationDetail } from "./schemas";
import "./operations.css";

interface ConfirmationState {
  action: OperationAction;
  detail: OperationDetail;
  returnFocus: HTMLElement | null;
}

type UnknownResultState = PendingOperationAction;

function DetailList({
  title,
  items,
}: {
  title: string;
  items: readonly { label: string; value: React.ReactNode }[];
}) {
  return (
    <section
      aria-labelledby={`operation-${title}`}
      className="operation-detail-card"
    >
      <h3 id={`operation-${title}`}>{title}</h3>
      <dl className="operation-detail-grid">
        {items.map((item) => (
          <div key={item.label}>
            <dt>{item.label}</dt>
            <dd>{item.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function LifecycleEvidence({ detail }: { detail: OperationDetail }) {
  const cleanupFailed =
    detail.cleanup_record !== null &&
    detail.cleanup_record.result !== "succeeded";

  return (
    <section
      aria-labelledby="operation-lifecycle-title"
      className={`operation-detail-card${cleanupFailed ? " operation-detail-card--danger" : ""}`}
    >
      <h3 id="operation-lifecycle-title">验证、资源与清理</h3>

      <h4>请求节点验证</h4>
      {detail.verification_summaries.length === 0 ? (
        <p className="operation-muted">还没有请求节点验证记录。</p>
      ) : (
        <ul className="operation-detail-list">
          {detail.verification_summaries.map((verification) => (
            <li
              key={`${verification.verifier_node_id}-${verification.verified_at}`}
            >
              <strong>{verification.result}</strong>
              <span>{verification.evidence_summary}</span>
              <span>
                请求节点 {verification.verifier_node_id} · HTTP
                {verification.status_code ?? " 未报告"} ·
                {formatOperationTime(verification.verified_at)}
              </span>
            </li>
          ))}
        </ul>
      )}

      <h4>受此操作所有的资源</h4>
      {detail.owned_resources.length === 0 ? (
        <p className="operation-muted">当前没有服务端报告的自有资源。</p>
      ) : (
        <ul className="operation-detail-list">
          {detail.owned_resources.map((resource) => (
            <li key={resource.resource_id}>
              <strong>{resource.kind}</strong>
              <span>
                {resource.bind_host}:{resource.bind_port}
              </span>
              <span>
                资源 {resource.resource_id} · 创建于
                {formatOperationTime(resource.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}

      <h4>清理记录</h4>
      {detail.cleanup_record === null ? (
        <p className="operation-muted">尚未产生清理记录。</p>
      ) : (
        <div className="operation-cleanup-record">
          <p>
            <strong>结果：</strong>
            {detail.cleanup_record.result}
          </p>
          <p>
            <strong>脱敏原因：</strong>
            {detail.cleanup_record.reason}
          </p>
          <p>
            <strong>完成时间：</strong>
            {formatOperationTime(detail.cleanup_record.completed_at)}
          </p>
        </div>
      )}

      {detail.manual_action === null ? null : (
        <div className="operation-manual-action" role="alert">
          <strong>需要人工处理</strong>
          <p>{detail.manual_action}</p>
        </div>
      )}
    </section>
  );
}

function OperationHistory({ detail }: { detail: OperationDetail }) {
  return (
    <section
      aria-labelledby="operation-history-title"
      className="operation-detail-card"
    >
      <h3 id="operation-history-title">服务端状态历史</h3>
      <ol className="operation-history">
        {detail.transitions.map((transition, index) => (
          <li key={`${transition.occurred_at}-${index}`}>
            <strong>
              {transition.from_status} → {transition.to_status}
            </strong>
            <span>{transition.reason}</span>
            <time dateTime={transition.occurred_at}>
              {formatOperationTime(transition.occurred_at)}
            </time>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function OperationDetailPage() {
  const { operationId } = useParams<{ operationId: string }>();
  const queryClient = useQueryClient();
  const writeInFlightRef = useRef(false);
  const [preparingAction, setPreparingAction] =
    useState<OperationAction | null>(null);
  const [confirmation, setConfirmation] = useState<ConfirmationState | null>(
    null,
  );
  const [submitting, setSubmitting] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [unknownResult, setUnknownResult] = useState<UnknownResultState | null>(
    null,
  );
  const detailTitleRef = useRef<HTMLHeadingElement>(null);

  const query = useQuery({
    queryKey: operationQueryKeys.detail(operationId ?? "missing"),
    queryFn: () => getOperation(operationId ?? ""),
    enabled: operationId !== undefined && operationId.length > 0,
  });

  function closeConfirmation() {
    setConfirmation(null);
  }

  async function readLatest(): Promise<OperationDetail> {
    if (operationId === undefined) {
      throw new Error("operation id missing");
    }
    const latest = await getOperation(operationId);
    queryClient.setQueryData(operationQueryKeys.detail(operationId), latest);
    return latest;
  }

  async function prepareAction(
    action: OperationAction,
    returnFocus: HTMLElement | null,
  ) {
    if (preparingAction !== null || submitting || operationId === undefined) {
      return;
    }
    setActionError(null);
    setActionMessage(null);
    setPreparingAction(action);
    try {
      const latest = await readLatest();
      if (!serverAllowsAction(latest, action)) {
        setActionMessage(
          `服务器最新状态是“${operationStatusLabels[latest.state]}”，现在不允许${operationActionLabels[action]}。本次未提交。`,
        );
        return;
      }
      setConfirmation({ action, detail: latest, returnFocus });
    } catch (error) {
      setActionError(
        `提交前无法复读最新详情：${readableOperationError(error as Error)} 未执行任何写请求。`,
      );
    } finally {
      setPreparingAction(null);
    }
  }

  async function queryAfterUnknownResult(
    pending: UnknownResultState | null = unknownResult,
  ) {
    if (pending === null) {
      return;
    }
    setActionError(null);
    try {
      const latest = await readLatest();
      if (operationActionWasAdjudicated(pending, latest)) {
        setUnknownResult((current) =>
          current?.action === pending.action &&
          current.initialState === pending.initialState
            ? null
            : current,
        );
        setActionMessage(
          "写请求响应曾经未知；随后只读查询显示 state 或 allowed_actions 已变化，服务端已经裁决原动作。页面没有重放写请求，也不根据响应缺失猜测成功。",
        );
        return;
      }
      setActionMessage(
        `已只查询服务端最新详情，但 state 仍是“${operationStatusLabels[latest.state]}”且仍允许${operationActionLabels[pending.action]}。写入结果继续未知，页面只允许继续查询。`,
      );
    } catch (error) {
      setActionMessage(null);
      setActionError(
        `写入结果仍未知，最新详情也读取失败：${readableOperationError(error as Error)}`,
      );
    }
  }

  async function confirmAction(payload: OperationActionPayload) {
    if (
      writeInFlightRef.current ||
      operationId === undefined ||
      confirmation === null
    ) {
      return;
    }
    writeInFlightRef.current = true;
    setSubmitting(true);
    setActionError(null);
    setActionMessage(null);
    const submittedAction = confirmation.action;
    const submittedDetail = confirmation.detail;
    try {
      await submitOperationAction(operationId, payload);
      closeConfirmation();
      try {
        await readLatest();
        setActionMessage(
          `服务器已回应${operationActionLabels[submittedAction]}请求，并已重新读取最新详情。`,
        );
      } catch (error) {
        setActionError(
          `服务器已回应写请求，但最新详情读取失败：${readableOperationError(error as Error)} 不会自动重放写请求。`,
        );
      }
    } catch (error) {
      closeConfirmation();
      if (!isUnknownOperationWriteError(error)) {
        setActionError(
          `${readableOperationError(error as Error)}。服务端已明确拒绝且未执行请求；页面不会自动重放。`,
        );
        try {
          await readLatest();
        } catch {
          // 已有明确的写入失败结果，详情可由用户稍后手动刷新。
        }
      } else {
        const pending = {
          action: submittedAction,
          initialState: submittedDetail.state,
        };
        setUnknownResult(pending);
        setActionError(null);
        await queryAfterUnknownResult(pending);
      }
    } finally {
      writeInFlightRef.current = false;
      setSubmitting(false);
    }
  }

  if (operationId === undefined || operationId.length === 0) {
    return (
      <section className="operations-page surface">
        <h2>操作详情</h2>
        <div
          className="operations-callout operations-callout--danger"
          role="alert"
        >
          路由中缺少 operation ID，未发起请求。
        </div>
      </section>
    );
  }

  if (query.isPending) {
    return (
      <section
        aria-labelledby="operation-detail-title"
        className="operations-page surface"
      >
        <h2 id="operation-detail-title">操作详情</h2>
        <p aria-live="polite" role="status">
          正在按 operation ID 读取最新详情……
        </p>
      </section>
    );
  }

  if (query.data === undefined) {
    return (
      <section
        aria-labelledby="operation-detail-title"
        className="operations-page surface"
      >
        <Link to="/app/operations">返回操作列表</Link>
        <h2 id="operation-detail-title">操作详情</h2>
        <div
          className="operations-callout operations-callout--danger"
          role="alert"
        >
          <h3>现在读不到这条操作</h3>
          <p>{readableOperationError(query.error)}</p>
          <button type="button" onClick={() => void query.refetch()}>
            重新读取详情
          </button>
        </div>
      </section>
    );
  }

  const detail = query.data;
  const summary = detail.summary;
  const actions = detail.allowed_actions.filter((action) =>
    serverAllowsAction(detail, action),
  );

  return (
    <section
      aria-labelledby="operation-detail-title"
      className="operations-page surface"
    >
      <Link className="operation-back-link" to="/app/operations">
        ← 返回操作列表
      </Link>
      <header className="operation-detail-header">
        <div>
          <p className="eyebrow">服务端最新详情</p>
          <h2 id="operation-detail-title" ref={detailTitleRef} tabIndex={-1}>
            {detail.service_id}
          </h2>
          <p className="operation-id">operation {summary.operation_id}</p>
        </div>
        <div className="operation-detail-header__controls">
          <span
            className={`operation-status operation-status--${operationTone(detail.state)}`}
          >
            {operationStatusLabels[detail.state]}
          </span>
          <button
            disabled={query.isFetching || submitting}
            type="button"
            onClick={() => void query.refetch()}
          >
            {query.isFetching ? "正在刷新……" : "刷新详情"}
          </button>
        </div>
      </header>

      {query.isRefetchError ? (
        <div
          className="operations-callout operations-callout--warning"
          role="alert"
        >
          <strong>刷新失败，下面是上一次成功读取的陈旧详情。</strong>
          <span>在重新读到服务端允许动作前，不应把这里的状态视为最新。</span>
        </div>
      ) : null}

      {unknownResult === null ? null : (
        <div
          className="operations-callout operations-callout--danger"
          role="alert"
        >
          <strong>
            {operationActionLabels[unknownResult.action]}请求的写入结果未知。
          </strong>
          <span>
            页面没有重放该请求。下面即使读到新状态，也不把它自动解释为刚才的写入成功。
          </span>
          <button
            disabled={query.isFetching || submitting}
            type="button"
            onClick={() => void queryAfterUnknownResult()}
          >
            只查询最新状态
          </button>
        </div>
      )}

      {actionError === null ? null : (
        <div
          className="operations-callout operations-callout--danger"
          role="alert"
        >
          {actionError}
        </div>
      )}
      {actionMessage === null ? null : (
        <div
          aria-live="polite"
          className="operations-callout operations-callout--neutral"
          role="status"
        >
          {actionMessage}
        </div>
      )}

      <div className="operation-detail-layout">
        <DetailList
          title="计划目标与证据"
          items={[
            { label: "服务 ID", value: detail.service_id },
            { label: "服务端点", value: detail.service_endpoint },
            {
              label: "进程或容器",
              value: detail.service_process_or_container,
            },
            { label: "服务指纹", value: detail.service_fingerprint },
            { label: "预期变化", value: detail.expected_change },
            { label: "风险", value: detail.risk_summary },
            {
              label: "计划创建",
              value: formatOperationTime(detail.created_at),
            },
          ]}
        />
        <DetailList
          title="访问者、端口与有效期"
          items={[
            { label: "请求节点（访问者）", value: summary.request_node_id },
            { label: "目标节点", value: summary.target_node_id },
            { label: "绑定地址", value: summary.bind_host },
            { label: "绑定端口", value: summary.bind_port },
            { label: "计划持续时间", value: `${detail.duration_seconds} 秒` },
            {
              label: "绝对到期时间",
              value: formatOperationTime(summary.absolute_expires_at),
            },
          ]}
        />
        <DetailList
          title="授权、验证与回滚依据"
          items={[
            { label: "操作等级", value: `L${summary.level}` },
            {
              label: "授权类型",
              value: summary.authorization_kind ?? "尚未授权",
            },
            {
              label: "授权依据",
              value: summary.authorization_basis ?? "尚未授权",
            },
            { label: "验证方法", value: detail.verification_method },
            { label: "回滚方法", value: detail.rollback_method },
            {
              label: "最后更新",
              value: formatOperationTime(summary.updated_at),
            },
          ]}
        />
        {summary.error === null ? null : (
          <section
            aria-labelledby="operation-error-title"
            className="operation-detail-card operation-detail-card--danger"
          >
            <h3 id="operation-error-title">脱敏错误</h3>
            <p>
              <strong>{summary.error.code}</strong>：{summary.error.message}
            </p>
            <p>
              {summary.error.retryable
                ? "服务端允许稍后重试。"
                : "不要重复提交。"}
              关联 ID：{summary.error.correlation_id}
            </p>
          </section>
        )}
        <LifecycleEvidence detail={detail} />
        <OperationHistory detail={detail} />
      </div>

      <section
        aria-labelledby="operation-actions-title"
        className="operation-actions"
      >
        <div>
          <h3 id="operation-actions-title">服务端当前允许动作</h3>
          <p>
            每次打开确认前都会重新按 ID 读取详情。模型或 Coordinator
            离线不会替代本机服务端判断。
          </p>
        </div>
        <div className="operation-actions__buttons">
          {unknownResult !== null ? (
            <span>写入结果未知期间只允许查询最新状态，不提供写动作。</span>
          ) : actions.length === 0 ? (
            <span>当前没有可提交动作。</span>
          ) : (
            actions.map((action) => (
              <button
                key={action}
                id={`operation-action-${action}`}
                disabled={
                  preparingAction !== null || submitting || query.isRefetchError
                }
                type="button"
                onClick={(event) =>
                  void prepareAction(action, event.currentTarget)
                }
              >
                {preparingAction === action
                  ? "正在复读详情……"
                  : operationActionLabels[action]}
              </button>
            ))
          )}
        </div>
      </section>

      {confirmation === null ? null : (
        <ActionConfirmationDialog
          action={confirmation.action}
          detail={confirmation.detail}
          fallbackFocus={detailTitleRef.current}
          returnFocus={confirmation.returnFocus}
          safeFallbackFocus={detailTitleRef.current}
          submitting={submitting}
          onCancel={closeConfirmation}
          onConfirm={(payload) => void confirmAction(payload)}
        />
      )}
    </section>
  );
}
