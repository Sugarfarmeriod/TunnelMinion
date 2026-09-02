import { ApiError } from "../../api/client";

import type { OperationAction, OperationStatus } from "./schemas";

export type OperationTone = "positive" | "warning" | "danger" | "neutral";

export const operationStatusLabels: Record<OperationStatus, string> = {
  planned: "计划已校验",
  awaiting_authorization: "等待本机批准",
  authorized: "已授权，等待执行",
  executing: "正在创建临时入口",
  verifying: "正在验证真实访问路径",
  succeeded: "请求节点验证通过",
  expiring: "正在到期清理",
  expired: "已到期并清理",
  rolling_back: "正在回滚",
  rolled_back: "已回滚",
  cleanup_failed: "清理失败，需要人工处理",
  rejected: "已拒绝",
  cancelled: "已取消",
  authorization_expired: "批准有效期已过",
};

export const operationActionLabels: Record<OperationAction, string> = {
  approve: "批准一次",
  reject: "拒绝",
  cancel: "取消操作",
  revoke: "主动撤销",
};

export function operationTone(state: OperationStatus): OperationTone {
  switch (state) {
    case "succeeded":
    case "expired":
    case "rolled_back":
      return "positive";
    case "planned":
    case "awaiting_authorization":
    case "authorized":
    case "executing":
    case "verifying":
    case "expiring":
    case "rolling_back":
      return "warning";
    case "cleanup_failed":
    case "authorization_expired":
      return "danger";
    case "rejected":
    case "cancelled":
      return "neutral";
  }
}

export function formatOperationTime(value: string | null): string {
  if (value === null) {
    return "尚未产生";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

export function readableOperationError(error: Error): string {
  if (error instanceof ApiError) {
    return `${error.code}：${error.message}`;
  }
  if (error.name === "ZodError") {
    return "服务返回的数据不符合操作契约，页面不会猜测状态。";
  }
  return "无法读取本机操作，请确认 TunnelMinion 仍在运行。";
}
