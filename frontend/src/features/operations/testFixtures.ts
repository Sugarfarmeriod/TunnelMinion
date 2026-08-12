import type { OperationDetail, OperationSummary } from "./schemas";

export const operationId = `operation_${"1".repeat(32)}`;
export const requestNodeId = `node_${"5".repeat(32)}`;
export const targetNodeId = `node_${"6".repeat(32)}`;
export const resourceId = `resource_${"7".repeat(32)}`;
export const recordedAt = "2026-08-08T09:00:00+08:00";

export function makeOperationSummary(
  overrides: Partial<OperationSummary> = {},
): OperationSummary {
  return {
    operation_id: operationId,
    thread_id: `thread_${"2".repeat(32)}`,
    run_id: `run_${"3".repeat(32)}`,
    tool_run_ids: [`toolrun_${"4".repeat(32)}`],
    request_node_id: requestNodeId,
    target_node_id: targetNodeId,
    tool_name: "share_local_http_service",
    level: 2,
    status: "awaiting_authorization",
    authorization_kind: null,
    authorization_basis: null,
    bind_host: "10.77.0.1",
    bind_port: 18_881,
    absolute_expires_at: null,
    resource_ids: [],
    verification_results: [],
    cleanup_result: null,
    error: null,
    updated_at: recordedAt,
    ...overrides,
  };
}

export function makeOperationDetail(
  overrides: Partial<OperationDetail> = {},
): OperationDetail {
  const state = overrides.state ?? "awaiting_authorization";
  return {
    summary: overrides.summary ?? makeOperationSummary({ status: state }),
    state,
    allowed_actions: ["approve", "reject", "cancel"],
    service_id: "local-admin",
    service_endpoint: "http://127.0.0.1:8080",
    service_process_or_container: "local-admin.exe",
    service_fingerprint: `sha256:${"a".repeat(64)}`,
    expected_change: "创建一个仅供请求节点访问的临时入口",
    risk_summary: "会短暂开放一个受限端口",
    verification_method: "请求节点沿真实路径发起 HTTP 探测",
    rollback_method: "删除 TunnelMinion 自有入口并验证端口关闭",
    duration_seconds: 300,
    created_at: recordedAt,
    owned_resources: [],
    verification_summaries: [],
    cleanup_record: null,
    manual_action: null,
    transitions: [
      {
        from_status: "none",
        to_status: state,
        reason: "服务端已校验结构化计划",
        occurred_at: recordedAt,
      },
    ],
    ...overrides,
  };
}
