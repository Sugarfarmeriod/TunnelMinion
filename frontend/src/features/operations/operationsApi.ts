import { ApiError, requestJson } from "../../api/client";

import {
  operationDetailSchema,
  operationListSchema,
  operationSummarySchema,
  type OperationAction,
  type OperationDetail,
  type OperationSummary,
} from "./schemas";

export const operationQueryKeys = {
  all: ["operations"] as const,
  list: ["operations", "list"] as const,
  detail: (operationId: string) =>
    ["operations", "detail", operationId] as const,
};

export function listOperations(): Promise<OperationSummary[]> {
  return requestJson("/api/operations", operationListSchema);
}

export function getOperation(operationId: string): Promise<OperationDetail> {
  return requestJson(
    `/api/operations/${encodeURIComponent(operationId)}`,
    operationDetailSchema,
  );
}

export type OperationActionPayload =
  | {
      action: "approve";
      operator: "target-local-user";
      expires_at: string;
    }
  | {
      action: "reject" | "cancel";
      operator: "target-local-user";
      reason: string;
    }
  | { action: "revoke" };

export function submitOperationAction(
  operationId: string,
  payload: OperationActionPayload,
): Promise<OperationSummary> {
  const { action } = payload;
  const body =
    action === "revoke" ? undefined : JSON.stringify(withoutAction(payload));
  return requestJson(
    `/api/operations/${encodeURIComponent(operationId)}/${action}`,
    operationSummarySchema,
    {
      method: "POST",
      headers:
        body === undefined ? undefined : { "Content-Type": "application/json" },
      body,
    },
  );
}

const requestGuardFailureCodes = new Set([
  "invalid_host",
  "cross_site_request",
  "invalid_origin",
  "request_header_required",
  "invalid_request_header",
]);

const knownNoSideEffectStatuses = new Set([404, 409, 422]);

/**
 * 只有服务端明确保证未进入副作用处理的 4xx 才能判定为直接失败；
 * 限流、超时、服务端错误、响应解析错误和传输错误都保留为未知结果。
 */
export function isUnknownOperationWriteError(error: unknown): boolean {
  if (!(error instanceof ApiError)) {
    return true;
  }
  if (error.status === 408 || error.status === 429 || error.status >= 500) {
    return true;
  }
  if (knownNoSideEffectStatuses.has(error.status)) {
    return false;
  }
  return !(error.status === 403 && requestGuardFailureCodes.has(error.code));
}

export interface PendingOperationAction {
  action: OperationAction;
  initialState: OperationDetail["state"];
}

const terminalOperationStates = new Set<OperationDetail["state"]>([
  "expired",
  "rolled_back",
  "cleanup_failed",
  "rejected",
  "cancelled",
  "authorization_expired",
]);

export function operationActionWasAdjudicated(
  pending: PendingOperationAction,
  latest: OperationDetail,
): boolean {
  return (
    terminalOperationStates.has(latest.state) ||
    latest.state !== pending.initialState ||
    !latest.allowed_actions.includes(pending.action)
  );
}

function withoutAction(
  payload: Exclude<OperationActionPayload, { action: "revoke" }>,
): Record<string, string> {
  if (payload.action === "approve") {
    return { operator: payload.operator, expires_at: payload.expires_at };
  }
  return { operator: payload.operator, reason: payload.reason };
}

const actionStates: Record<
  OperationAction,
  readonly OperationDetail["state"][]
> = {
  approve: ["awaiting_authorization"],
  reject: ["awaiting_authorization"],
  cancel: ["planned", "awaiting_authorization", "authorized"],
  revoke: ["succeeded"],
};

export function serverAllowsAction(
  detail: OperationDetail,
  action: OperationAction,
): boolean {
  return (
    detail.allowed_actions.includes(action) &&
    actionStates[action].includes(detail.state)
  );
}
