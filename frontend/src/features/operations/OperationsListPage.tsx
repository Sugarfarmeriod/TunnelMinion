import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import {
  formatOperationTime,
  operationStatusLabels,
  operationTone,
  readableOperationError,
} from "./operationPresentation";
import {
  createRequesterOperation,
  isUnknownOperationWriteError,
  listEligibleOperationPeers,
  listOperations,
  operationQueryKeys,
} from "./operationsApi";
import "./operations.css";

const incidentIdPattern = /^incident_[0-9a-f]{32}$/;
const nodeIdPattern = /^node_[0-9a-f]{32}$/;

export type IncidentOperationPrefill =
  | { kind: "none" }
  | { kind: "invalid" }
  | {
      kind: "valid";
      incidentId: string;
      servicePort: number;
      targetNodeId: string;
    };

export function parseIncidentOperationPrefill(
  searchParams: URLSearchParams,
): IncidentOperationPrefill {
  const names = ["incident_id", "target_node_id", "service_port"] as const;
  if (names.every((name) => !searchParams.has(name))) {
    return { kind: "none" };
  }
  if (names.some((name) => searchParams.getAll(name).length !== 1)) {
    return { kind: "invalid" };
  }
  const incidentId = searchParams.get("incident_id") ?? "";
  const targetNodeId = searchParams.get("target_node_id") ?? "";
  const servicePort = Number(searchParams.get("service_port"));
  if (
    !incidentIdPattern.test(incidentId) ||
    !nodeIdPattern.test(targetNodeId) ||
    !Number.isInteger(servicePort) ||
    servicePort < 1 ||
    servicePort > 65_535
  ) {
    return { kind: "invalid" };
  }
  return { kind: "valid", incidentId, targetNodeId, servicePort };
}

export function OperationsListPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const createInFlight = useRef(false);
  const [creating, setCreating] = useState(false);
  const [createMessage, setCreateMessage] = useState<string | null>(null);
  const query = useQuery({
    queryKey: operationQueryKeys.list,
    queryFn: listOperations,
  });
  const peersQuery = useQuery({
    queryKey: [...operationQueryKeys.all, "eligible-peers"],
    queryFn: listEligibleOperationPeers,
  });
  const incidentPrefill = parseIncidentOperationPrefill(searchParams);
  const prefillTargetAvailable =
    incidentPrefill.kind === "valid" &&
    peersQuery.data?.some(
      (peer) => peer.node_id === incidentPrefill.targetNodeId,
    ) === true;
  const prefillBlocked =
    incidentPrefill.kind === "invalid" ||
    (incidentPrefill.kind === "valid" &&
      peersQuery.data !== undefined &&
      !prefillTargetAvailable);
  const defaultTargetNodeId =
    incidentPrefill.kind === "valid"
      ? incidentPrefill.targetNodeId
      : (peersQuery.data?.[0]?.node_id ?? "");

  async function createOperation(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (createInFlight.current) {
      return;
    }
    if (prefillBlocked) {
      setCreateMessage(
        "Incident 预填上下文已经失效；本次没有创建操作。请返回总览刷新，或打开普通新建入口。",
      );
      return;
    }
    const form = new FormData(event.currentTarget);
    if (form.get("confirmed") !== "on") {
      setCreateMessage("请先确认：目标节点批准后，这会创建一个临时访问入口。");
      return;
    }
    createInFlight.current = true;
    setCreating(true);
    setCreateMessage(null);
    try {
      const detail = await createRequesterOperation({
        target_node_id: String(form.get("target_node_id")),
        service_port: Number(form.get("service_port")),
        bind_port: Number(form.get("bind_port")),
        duration_seconds: Number(form.get("duration_seconds")),
        confirmed: true,
      });
      queryClient.setQueryData(
        operationQueryKeys.detail(detail.summary.operation_id),
        detail,
      );
      void queryClient.invalidateQueries({ queryKey: operationQueryKeys.list });
      navigate(
        `/app/operations/${encodeURIComponent(detail.summary.operation_id)}`,
      );
    } catch (error) {
      const prefix = isUnknownOperationWriteError(error)
        ? "创建结果无法确认，页面没有自动重试。请刷新列表查找原操作。"
        : "服务端已拒绝创建，未产生远端写入。";
      setCreateMessage(`${prefix} ${readableOperationError(error as Error)}`);
    } finally {
      createInFlight.current = false;
      setCreating(false);
    }
  }

  if (query.isPending) {
    return (
      <section
        aria-labelledby="operations-title"
        className="operations-page surface"
      >
        <h2 id="operations-title">操作</h2>
        <p aria-live="polite" role="status">
          正在读取操作记录……
        </p>
      </section>
    );
  }

  if (query.data === undefined) {
    return (
      <section
        aria-labelledby="operations-title"
        className="operations-page surface"
      >
        <h2 id="operations-title">操作</h2>
        <div
          className="operations-callout operations-callout--danger"
          role="alert"
        >
          <h3>现在读不到操作记录</h3>
          <p>{readableOperationError(query.error)}</p>
          <button type="button" onClick={() => void query.refetch()}>
            重新读取
          </button>
        </div>
      </section>
    );
  }

  const operations = query.data;

  return (
    <section
      aria-labelledby="operations-title"
      className="operations-page surface"
    >
      <header className="operations-page__header">
        <div>
          <p className="eyebrow">本机批准与远端请求</p>
          <h2 id="operations-title">操作</h2>
          <p>
            列表只显示摘要。打开详情后会按 ID 重新读取完整计划和服务端允许动作。
          </p>
        </div>

        {incidentPrefill.kind === "valid" ? (
          <div
            className={`operations-callout ${prefillBlocked ? "operations-callout--warning" : ""}`}
            role={prefillBlocked ? "alert" : "status"}
          >
            <strong>来自 Incident {incidentPrefill.incidentId}</strong>
            <span>
              已预填目标节点和端口；所有值仍会按最新证据重新诊断，调查结论不等于确认或授权。
            </span>
            {prefillBlocked ? (
              <>
                <span>
                  该目标当前不在服务端返回的合格对端中，本次上下文请求已禁用。
                </span>
                <Link to="/app/operations">打开普通新建入口</Link>
              </>
            ) : (
              <Link to="/app/overview">返回 Incident 总览</Link>
            )}
          </div>
        ) : incidentPrefill.kind === "invalid" ? (
          <div
            className="operations-callout operations-callout--warning"
            role="alert"
          >
            <strong>Incident 预填参数无效，本次上下文请求已禁用。</strong>
            <Link to="/app/operations">打开普通新建入口</Link>
          </div>
        ) : null}
        <button
          disabled={query.isFetching}
          type="button"
          onClick={() => void query.refetch()}
        >
          {query.isFetching ? "正在刷新……" : "刷新列表"}
        </button>
      </header>

      {query.isRefetchError ? (
        <div
          className="operations-callout operations-callout--warning"
          role="alert"
        >
          <strong>刷新失败，下面是上一次成功读取的陈旧列表。</strong>
          <span>
            列表状态不能视为最新；进入详情仍会按 operation ID 单独读取。
          </span>
        </div>
      ) : null}

      <section
        aria-labelledby="request-operation-title"
        className="operation-request-card"
      >
        <div>
          <p className="eyebrow">请求节点</p>
          <h3 id="request-operation-title">请求临时 HTTP 访问</h3>
          <p>
            这里只收集目标节点和端口。远端地址、Gateway 凭据、回调 token
            与访问凭据都由本机服务端处理。
          </p>
        </div>

        {peersQuery.isError ? (
          <div
            className="operations-callout operations-callout--warning"
            role="alert"
          >
            <strong>现在读不到可用对端，新建入口已禁用。</strong>
            <span>已有操作仍可查看和控制。</span>
            <button type="button" onClick={() => void peersQuery.refetch()}>
              重新读取对端
            </button>
          </div>
        ) : null}

        {!peersQuery.isPending && peersQuery.data?.length === 0 ? (
          <p className="operation-muted" role="status">
            当前没有已配置凭据且允许临时 HTTP 共享的对端；已有操作不受影响。
          </p>
        ) : null}

        <form className="operation-request-form" onSubmit={createOperation}>
          <label>
            目标节点
            <select
              key={`${defaultTargetNodeId}-${peersQuery.data?.length ?? "loading"}`}
              required
              disabled={
                prefillBlocked ||
                peersQuery.data === undefined ||
                peersQuery.data.length === 0
              }
              defaultValue={defaultTargetNodeId}
              name="target_node_id"
            >
              {incidentPrefill.kind === "valid" &&
              peersQuery.data !== undefined &&
              !prefillTargetAvailable ? (
                <option value={incidentPrefill.targetNodeId}>
                  {incidentPrefill.targetNodeId} · 当前不合格
                </option>
              ) : null}
              {(peersQuery.data ?? []).map((peer) => (
                <option key={peer.node_id} value={peer.node_id}>
                  {peer.node_id} · {peer.host}
                </option>
              ))}
            </select>
          </label>
          <label>
            目标服务端口
            <input
              defaultValue={
                incidentPrefill.kind === "valid"
                  ? incidentPrefill.servicePort
                  : 8080
              }
              max="65535"
              min="1"
              name="service_port"
              required
              type="number"
            />
          </label>
          <label>
            临时共享端口
            <input
              defaultValue="18881"
              max="65535"
              min="1024"
              name="bind_port"
              required
              type="number"
            />
          </label>
          <label>
            持续秒数
            <input
              defaultValue="300"
              max="86400"
              min="1"
              name="duration_seconds"
              required
              type="number"
            />
          </label>
          <label className="operation-request-form__confirmation">
            <input name="confirmed" required type="checkbox" />
            我确认：目标节点批准后会创建临时入口，目标节点仍拥有撤销和到期清理权。
          </label>
          <button
            disabled={
              creating ||
              prefillBlocked ||
              peersQuery.data === undefined ||
              peersQuery.data.length === 0
            }
            type="submit"
          >
            {creating ? "正在生成并提交一次……" : "生成计划并请求批准"}
          </button>
        </form>
        {createMessage === null ? null : (
          <div
            className="operations-callout operations-callout--warning"
            role="alert"
          >
            {createMessage}
          </div>
        )}
      </section>

      {operations.length === 0 ? (
        <div className="operations-empty">
          <h3>当前没有操作记录</h3>
          <p>聊天、模型或 Coordinator 不可用时，这里仍会保留已有操作。</p>
        </div>
      ) : (
        <ul aria-label="操作记录" className="operations-list">
          {operations.map((operation) => (
            <li key={`${operation.role}-${operation.operation_id}`}>
              <article className="operation-summary-card">
                <div className="operation-summary-card__heading">
                  <div>
                    <p className="operation-summary-card__tool">
                      {`${operation.role === "target" ? "目标端审批" : "请求端跟进"} · ${operation.tool_name}`}
                    </p>
                    <h3>L{operation.level} 操作</h3>
                  </div>
                  <span
                    className={`operation-status operation-status--${operationTone(operation.status)}`}
                  >
                    {operationStatusLabels[operation.status]}
                  </span>
                </div>
                <dl className="operation-summary-grid">
                  <div>
                    <dt>请求节点</dt>
                    <dd>{operation.request_node_id}</dd>
                  </div>
                  <div>
                    <dt>目标节点</dt>
                    <dd>{operation.target_node_id}</dd>
                  </div>
                  <div>
                    <dt>计划端口</dt>
                    <dd>
                      {operation.bind_host}:{operation.bind_port}
                    </dd>
                  </div>
                  <div>
                    <dt>最后更新</dt>
                    <dd>{formatOperationTime(operation.updated_at)}</dd>
                  </div>
                </dl>
                {operation.error === null ? null : (
                  <p className="operation-summary-card__error">
                    <strong>{operation.error.code}</strong>：
                    {operation.error.message}
                  </p>
                )}
                {operation.submission_result_unknown ||
                operation.execution_result_unknown ? (
                  <p className="operation-summary-card__error">
                    写入结果尚未确认；只刷新这条操作，不要重新创建或自动执行。
                  </p>
                ) : operation.error_code === null ? null : (
                  <p className="operation-summary-card__error">
                    {operation.error_code}
                  </p>
                )}
                <Link
                  className="operation-link"
                  to={`/app/operations/${encodeURIComponent(operation.operation_id)}`}
                >
                  查看操作最新详情
                </Link>
              </article>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
