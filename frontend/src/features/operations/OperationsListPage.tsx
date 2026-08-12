import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import {
  formatOperationTime,
  operationStatusLabels,
  operationTone,
  readableOperationError,
} from "./operationPresentation";
import { listOperations, operationQueryKeys } from "./operationsApi";
import "./operations.css";

export function OperationsListPage() {
  const query = useQuery({
    queryKey: operationQueryKeys.list,
    queryFn: listOperations,
  });

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
          <p className="eyebrow">目标节点本机控制</p>
          <h2 id="operations-title">操作</h2>
          <p>
            列表只显示摘要。打开详情后会按 ID 重新读取完整计划和服务端允许动作。
          </p>
        </div>
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

      {operations.length === 0 ? (
        <div className="operations-empty">
          <h3>当前没有操作记录</h3>
          <p>聊天、模型或 Coordinator 不可用时，这里仍会保留已有操作。</p>
        </div>
      ) : (
        <ul aria-label="操作记录" className="operations-list">
          {operations.map((operation) => (
            <li key={operation.operation_id}>
              <article className="operation-summary-card">
                <div className="operation-summary-card__heading">
                  <div>
                    <p className="operation-summary-card__tool">
                      {operation.tool_name}
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
                <Link
                  className="operation-link"
                  to={`/app/operations/${encodeURIComponent(operation.operation_id)}`}
                >
                  查看服务端最新详情
                </Link>
              </article>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
