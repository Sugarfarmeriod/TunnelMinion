import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { requestJson } from "../../api/client";
import { resourceOverviewSchema } from "../../api/schemas/overview";
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
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [selectedPort, setSelectedPort] = useState<number | null>(null);
  const [duration, setDuration] = useState("300");
  const query = useQuery({
    queryKey: operationQueryKeys.list,
    queryFn: listOperations,
  });
  const peersQuery = useQuery({
    queryKey: [...operationQueryKeys.all, "eligible-peers"],
    queryFn: listEligibleOperationPeers,
  });
  const overviewQuery = useQuery({
    queryKey: ["resource-overview"],
    queryFn: () =>
      requestJson("/api/resources/overview", resourceOverviewSchema),
    retry: false,
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
  const targetNodeId = selectedTarget ?? defaultTargetNodeId;
  const targetAvailable =
    peersQuery.data?.some((peer) => peer.node_id === targetNodeId) === true;
  const servicePort =
    selectedPort ??
    (incidentPrefill.kind === "valid" ? incidentPrefill.servicePort : 8080);
  const overview = overviewQuery.isError ? undefined : overviewQuery.data;
  function computerName(nodeId: string, host: string) {
    const nodes = overview?.nodes.items.filter(
      (node) => node.node_id === nodeId,
    );
    const node = nodes?.length === 1 ? nodes[0] : undefined;
    const name =
      node &&
      ["live", "fresh"].includes(node.freshness) &&
      ["local", "online"].includes(node.state)
        ? node.display_name.trim()
        : "";
    if (
      name &&
      overview?.nodes.items.filter((item) => item.display_name.trim() === name)
        .length === 1
    ) {
      return name;
    }
    const duplicateHost =
      (peersQuery.data ?? []).filter((peer) => peer.host === host).length > 1;
    return `${name || "名称未知"} · ${host}${duplicateHost ? ` · ${nodeId.slice(-8)}` : ""}`;
  }
  const sourceIncidents =
    incidentPrefill.kind === "valid"
      ? overview?.incidents.items.filter(
          (item) => item.incident_id === incidentPrefill.incidentId,
        )
      : undefined;
  const sourceIncident =
    sourceIncidents?.length === 1 ? sourceIncidents[0] : undefined;
  const sourceServices =
    sourceIncident?.object_kind === "service"
      ? overview?.services.items.filter(
          (item) => item.service_id === sourceIncident.object_id,
        )
      : undefined;
  const sourceService =
    sourceServices?.length === 1 ? sourceServices[0] : undefined;
  const serviceName =
    sourceService &&
    sourceService.node_id === targetNodeId &&
    sourceService.port === servicePort &&
    ["live", "fresh"].includes(sourceService.freshness) &&
    sourceService.lifecycle === "active" &&
    sourceService.state === "available"
      ? sourceService.display_name?.trim()
      : undefined;

  async function createOperation(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (createInFlight.current) {
      return;
    }
    if (prefillBlocked || !targetAvailable) {
      setCreateMessage(
        "这台电脑现在不能申请访问，没有发送请求。请返回总览刷新，或重新选择可申请的电脑。",
      );
      return;
    }
    const form = new FormData(event.currentTarget);
    if (form.get("confirmed") !== "on") {
      setCreateMessage("请先勾选确认风险，再发送访问请求。");
      return;
    }
    createInFlight.current = true;
    setCreating(true);
    setCreateMessage(null);
    try {
      const detail = await createRequesterOperation({
        ...(incidentPrefill.kind === "valid"
          ? { source_incident_id: incidentPrefill.incidentId }
          : {}),
        target_node_id: String(form.get("target_node_id")),
        service_port: Number(form.get("service_port")),
        bind_port: Number(form.get("bind_port")),
        duration_seconds: Number(
          duration === "custom" ? form.get("duration_seconds") : duration,
        ),
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
          <p className="eyebrow">访问请求与处理记录</p>
          <h2 id="operations-title">操作</h2>
          <p>
            发出请求、等待对方批准，再由你确认开始。已有请求可以在下方继续查看。
          </p>
        </div>

        {incidentPrefill.kind === "valid" ? (
          <div
            className={`operations-callout ${prefillBlocked ? "operations-callout--warning" : ""}`}
            role={prefillBlocked ? "alert" : "status"}
          >
            <strong>已带入刚才调查的服务</strong>
            <span>
              发送前会重新检查。现在只是填写申请，还没有发出请求或获得批准。
            </span>
            {prefillBlocked ? (
              <>
                <span>这台电脑当前不可申请，本次不会发送请求。</span>
                <Link to="/app/operations">打开普通新建入口</Link>
              </>
            ) : (
              <Link
                to={`/app/overview?incident_id=${incidentPrefill.incidentId}#overview-incidents`}
              >
                返回调查结果
              </Link>
            )}
          </div>
        ) : incidentPrefill.kind === "invalid" ? (
          <div
            className="operations-callout operations-callout--warning"
            role="alert"
          >
            <strong>带入的服务信息不完整，本次不会发送请求。</strong>
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
          <h3 id="request-operation-title">申请临时访问</h3>
          <p>
            临时使用另一台电脑上的网页服务。对方可以拒绝、随时停止，到期后会自动关闭。
          </p>
        </div>

        {peersQuery.isError ? (
          <div
            className="operations-callout operations-callout--warning"
            role="alert"
          >
            <strong>现在读不到可申请的电脑，暂时不能发送新请求。</strong>
            <span>已有操作仍可查看和控制。</span>
            <button type="button" onClick={() => void peersQuery.refetch()}>
              重新读取电脑
            </button>
          </div>
        ) : null}

        {!peersQuery.isPending && peersQuery.data?.length === 0 ? (
          <p className="operation-muted" role="status">
            还没有允许临时访问的电脑。需要先完成连接和授权；已有请求仍可查看。
          </p>
        ) : null}

        <form className="operation-request-form" onSubmit={createOperation}>
          <label>
            哪台电脑
            <select
              key={`${defaultTargetNodeId}-${peersQuery.data?.length ?? "loading"}`}
              required
              disabled={
                prefillBlocked ||
                peersQuery.data === undefined ||
                peersQuery.data.length === 0
              }
              value={targetNodeId}
              onChange={(event) => setSelectedTarget(event.target.value)}
              name="target_node_id"
            >
              {targetNodeId &&
              peersQuery.data !== undefined &&
              !targetAvailable ? (
                <option value={targetNodeId}>原来的电脑 · 当前不可申请</option>
              ) : null}
              {(peersQuery.data ?? []).map((peer) => (
                <option key={peer.node_id} value={peer.node_id}>
                  {computerName(peer.node_id, peer.host)}
                </option>
              ))}
            </select>
          </label>
          <div>
            <p>
              <strong>什么服务</strong>
            </p>
            <p>{serviceName || "还不能确认服务名称"}</p>
            {!serviceName ? (
              <p className="operation-muted">
                请向服务的主人确认下面的端口号码，不要凭号码猜服务用途。
              </p>
            ) : null}
            {serviceName ? (
              <input name="service_port" type="hidden" value={servicePort} />
            ) : (
              <label>
                服务的端口号码
                <input
                  value={servicePort}
                  onChange={(event) =>
                    setSelectedPort(Number(event.target.value))
                  }
                  max="65535"
                  min="1"
                  name="service_port"
                  required
                  type="number"
                />
              </label>
            )}
          </div>
          <label>
            使用多久
            <select
              value={duration}
              onChange={(event) => setDuration(event.target.value)}
            >
              <option value="60">1 分钟</option>
              <option value="300">5 分钟</option>
              <option value="900">15 分钟</option>
              <option value="3600">1 小时</option>
              <option value="custom">自定义时长</option>
            </select>
            {duration === "custom" ? (
              <input
                aria-label="自定义时长（秒）"
                defaultValue="300"
                min="1"
                max="86400"
                name="duration_seconds"
                required
                type="number"
              />
            ) : null}
          </label>
          <details className="operation-request-form__technical">
            <summary>技术设置（通常不用改）</summary>
            <p className="operation-muted">
              电脑编号：{targetNodeId || "尚未取得"}；服务端口：{servicePort}
            </p>
            {incidentPrefill.kind === "valid" ? (
              <p className="operation-muted">
                来源事件：{incidentPrefill.incidentId}
              </p>
            ) : null}
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
          </details>
          <div className="operation-request-form__risk">
            <p>
              <strong>先确认风险</strong>
            </p>
            <p>
              能查看什么、能修改什么，取决于服务本身。临时访问不代表只能查看。
            </p>
            <p className="operation-muted">
              发送会进行模型诊断，可能使用模型额度。对方批准后，还需要你确认开始。
            </p>
          </div>
          <label className="operation-request-form__confirmation">
            <input name="confirmed" required type="checkbox" />
            我了解风险，要向对方申请临时访问。对方可以拒绝或随时停止。
          </label>
          <button
            disabled={
              creating ||
              prefillBlocked ||
              !targetAvailable ||
              peersQuery.data === undefined ||
              peersQuery.data.length === 0
            }
            type="submit"
          >
            {creating ? "正在检查并发送，请稍候……" : "发送访问请求"}
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
