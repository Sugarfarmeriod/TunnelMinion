import { ApiError } from "../../api/client";

import type {
  OperationAction,
  OperationRole,
  OperationStatus,
} from "./schemas";

export type OperationTone = "positive" | "warning" | "danger" | "neutral";

const operationStatusLabels: Record<OperationStatus, string> = {
  planned: "请求已准备好",
  awaiting_authorization: "等待批准",
  authorized: "请求已同意",
  executing: "正在创建临时入口",
  verifying: "正在检查能否访问",
  succeeded: "访问检查通过",
  expiring: "正在关闭临时入口",
  expired: "已到期，入口已关闭",
  rolling_back: "正在结束临时访问",
  rolled_back: "已结束，入口已关闭",
  cleanup_failed: "入口关闭失败，需要处理",
  rejected: "已拒绝",
  cancelled: "已取消",
  authorization_expired: "开始期限已过",
};

export const operationActionLabels: Record<OperationAction, string> = {
  approve: "批准一次",
  reject: "拒绝",
  cancel: "取消请求",
  revoke: "结束临时访问",
  refresh: "查看对方状态",
  execute: "开始临时访问",
  access: "打开临时访问",
};

export function operationStatusLabel(
  status: OperationStatus,
  role: OperationRole,
): string {
  if (status === "awaiting_authorization") {
    return role === "target" ? "等待你决定" : "等待对方同意";
  }
  if (status === "authorized") {
    return role === "target" ? "等待对方开始" : "对方已同意";
  }
  return operationStatusLabels[status];
}

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
