import type { ResourceOverview } from "../../api/schemas/overview";
import { formatOperationTime } from "./operationPresentation";
import { serverAllowsAction } from "./operationsApi";
import type { OperationDetail, OperationStatus } from "./schemas";

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
  const isTarget = detail.role === "target";
  const stateDescriptions: Record<OperationStatus, string> = {
    planned: "请求已准备好，还没有开始使用。请刷新查看是否需要批准。",
    awaiting_authorization: isTarget
      ? "有人想临时使用这台电脑上的服务。认识这个请求再批准；不确定就拒绝。"
      : "请求已发出，正在等待对方同意。对方同意后，请刷新再确认开始。",
    authorized: isTarget
      ? "这次请求已同意，正在等待对方开始使用。还没有开放临时入口。"
      : serverAllowsAction(detail, "execute")
        ? "对方已同意。请确认开始使用，开始后才计算访问时长。"
        : "对方已同意，但这台电脑目前不能开始。请刷新确认批准是否仍有效。",
    executing: "正在准备临时入口。请稍后刷新，不要重复开始。",
    verifying: "正在检查能否访问。请稍后刷新，检查通过前不要当作已经可用。",
    succeeded: isTarget
      ? serverAllowsAction(detail, "revoke")
        ? "对方已通过访问检查。你可以提前结束这次临时访问。"
        : "对方已通过访问检查。请刷新查看最新状态。"
      : serverAllowsAction(detail, "access")
        ? "访问检查已通过。现在可以打开临时访问，到期后入口会关闭。"
        : "对方的访问检查已通过，但这台电脑目前没有可用入口。请刷新，不要重复开始。",
    expiring: "访问时长已结束，正在关闭临时入口。请稍后刷新确认关闭结果。",
    expired: "这次临时访问已到期，入口已关闭。无需再次批准或开始。",
    rolling_back: "正在撤回这次访问并关闭临时入口。请稍后刷新确认结果。",
    rolled_back: "这次访问已撤回，临时入口已关闭。",
    cleanup_failed:
      "临时入口未能安全关闭。请按下面的提示处理，不要当作已经结束。",
    rejected: "这次请求已被拒绝，没有开始临时访问。",
    cancelled: "这次请求已取消，没有开始临时访问。",
    authorization_expired:
      "批准的开始期限已过，不能再开始这次访问。仍需使用时，要重新申请。",
  };
  const resultUnknown =
    detail.submission_result_unknown || detail.execution_result_unknown;
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
            ? resultUnknown
              ? "这次请求的结果还不明确。请先刷新状态，不要重复批准或开始。"
              : stateDescriptions[detail.state]
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
            {isTarget
              ? "请与发起请求的人确认身份，不要只凭设备名称判断。"
              : "这是发起请求的设备；对方电脑决定是否允许。"}
          </dd>
        </div>
        <div>
          <dt>开放多久</dt>
          <dd>开始使用后，最多 {duration}</dd>
          <dd className="operation-muted">
            {detail.state === "expired" || detail.state === "rolled_back"
              ? "这次临时访问已结束。"
              : (detail.access_expires_at ??
                    detail.summary.absolute_expires_at) === null
                ? "从开始使用时计时，到期自动关闭临时入口。"
                : `访问结束时间：${formatOperationTime(detail.access_expires_at ?? detail.summary.absolute_expires_at)}`}
          </dd>
        </div>
      </dl>
      <div className="operation-request-risk">
        <strong>访问风险</strong>
        {isTemporaryAccess ? (
          <p>
            临时入口会让请求设备访问这个服务。能看到什么、能否修改内容或是否需要登录，取决于服务本身；访问检查通过不代表这些风险已确认安全。
          </p>
        ) : (
          <p>{detail.risk_summary}</p>
        )}
      </div>
    </section>
  );
}
