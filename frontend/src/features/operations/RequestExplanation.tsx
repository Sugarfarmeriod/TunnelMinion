import type { ResourceOverview } from "../../api/schemas/overview";
import { formatOperationTime } from "./operationPresentation";
import type { OperationDetail } from "./schemas";

export function RequestExplanation({
  detail,
  overview,
  compact = false,
}: {
  detail: OperationDetail;
  overview?: ResourceOverview;
  compact?: boolean;
}) {
  const isTemporaryAccess =
    detail.summary.tool_name === "share_local_http_service";
  const duration =
    detail.duration_seconds % 60 === 0
      ? `${detail.duration_seconds / 60} 分钟`
      : `${detail.duration_seconds} 秒`;
  const requester = overview?.nodes.items.find(
    (node) =>
      node.node_id === detail.summary.request_node_id &&
      ["fresh", "live"].includes(node.freshness),
  );
  const service = overview?.services.items.find(
    (item) =>
      item.service_id === detail.service_id &&
      item.node_id === detail.summary.target_node_id &&
      ["fresh", "live"].includes(item.freshness),
  );

  return (
    <section
      className="operation-request-explanation"
      aria-label="这次请求会做什么"
    >
      {compact ? null : (
        <p className="operation-request-intent">
          {isTemporaryAccess
            ? detail.role === "target"
              ? "另一台设备想临时使用这台电脑上的一个服务。是否允许，由你决定。"
              : "你正在请求临时使用另一台电脑上的服务。需要对方先同意。"
            : detail.expected_change}
        </p>
      )}
      <dl className="operation-request-facts">
        <div>
          <dt>使用什么</dt>
          <dd>
            {service?.display_name ||
              detail.service_process_or_container ||
              "程序名称未知"}
          </dd>
          <dd className="operation-muted">{detail.service_endpoint}</dd>
        </div>
        <div>
          <dt>谁来使用</dt>
          <dd>{requester?.display_name || "访问者名称未知"}</dd>
          <dd className="operation-muted">
            请先与发起请求的人确认。不认识的请求不要批准。
          </dd>
        </div>
        <div>
          <dt>开放多久</dt>
          <dd>开始使用后，最多 {duration}</dd>
          <dd className="operation-muted">
            {detail.summary.absolute_expires_at === null
              ? "到期自动关闭临时入口。你也可以提前结束。"
              : `截止时间：${formatOperationTime(detail.summary.absolute_expires_at)}`}
          </dd>
        </div>
      </dl>
      <div className="operation-request-risk">
        <strong>批准前请留意</strong>
        {isTemporaryAccess ? (
          <p>
            对方能看到什么、能做什么，取决于这个服务本身。对方不一定只能看，也可能更改内容。
          </p>
        ) : null}
        <p>{detail.risk_summary}</p>
      </div>
    </section>
  );
}
