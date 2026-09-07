import type { ResourceOverview } from "../../api/schemas/overview";
import type { OperationListItem } from "../operations/schemas";

type NodeItem = ResourceOverview["nodes"]["items"][number];
type ServiceItem = ResourceOverview["services"]["items"][number];

export interface IncidentHandoffInput {
  incidentId: string;
  status: ResourceOverview["incidents"]["items"][number]["status"];
  eventType: ResourceOverview["incidents"]["items"][number]["event_type"];
  objectKind: ResourceOverview["incidents"]["items"][number]["object_kind"];
  objectId: string;
  targetNodeId: string;
}

export type IncidentOperationHandoff =
  | {
      available: true;
      href: string;
      servicePort: number;
      targetNodeId: string;
    }
  | { available: false; message: string };

export function incidentOperationHandoff(
  incident: IncidentHandoffInput,
  nodes: readonly NodeItem[],
  services: readonly ServiceItem[],
): IncidentOperationHandoff {
  if (incident.status !== "confirmed") {
    return {
      available: false,
      message: "调查还没有形成证据充分的确认结论，当前只保留只读调查。",
    };
  }
  if (
    incident.eventType !== "local_only" ||
    incident.objectKind !== "service"
  ) {
    return {
      available: false,
      message: "当前安全操作只支持远端仅本机可用的 HTTP 服务。",
    };
  }
  const localNodes = nodes.filter((node) => node.state === "local");
  if (localNodes.length !== 1) {
    return {
      available: false,
      message: "当前无法唯一确认本机节点，不能生成远端候选处理入口。",
    };
  }
  if (localNodes[0]?.node_id === incident.targetNodeId) {
    return {
      available: false,
      message: "这是本机事件；现有安全操作只允许请求节点向远端目标发起。",
    };
  }
  const matches = services.filter(
    (service) =>
      service.service_id === incident.objectId &&
      service.node_id === incident.targetNodeId,
  );
  if (matches.length !== 1) {
    return {
      available: false,
      message: "当前服务快照里已找不到唯一的同一服务，请先刷新证据。",
    };
  }
  const service = matches[0];
  if (
    (service?.state !== "available" && service?.state !== "degraded") ||
    service.lifecycle !== "active"
  ) {
    return {
      available: false,
      message: "服务已经停止或不可用，当前不生成临时访问候选计划。",
    };
  }
  if (service?.freshness !== "live" && service?.freshness !== "fresh") {
    return {
      available: false,
      message: "服务证据已经陈旧，请先刷新后再决定是否处理。",
    };
  }
  if (service.port === null) {
    return {
      available: false,
      message: "当前证据无法确定服务端口，不能安全预填候选计划。",
    };
  }
  const query = new URLSearchParams({
    incident_id: incident.incidentId,
    target_node_id: incident.targetNodeId,
    service_port: String(service.port),
  });
  return {
    available: true,
    href: `/app/operations?${query.toString()}`,
    servicePort: service.port,
    targetNodeId: incident.targetNodeId,
  };
}

export type OperationAttentionKind =
  | "approval"
  | "execution"
  | "unknown_result"
  | "cleanup";

export interface OperationAttentionItem {
  kind: OperationAttentionKind;
  label: string;
  operation: OperationListItem;
}

export function operationsRequiringAttention(
  operations: readonly OperationListItem[],
): OperationAttentionItem[] {
  return operations.reduce<OperationAttentionItem[]>((items, operation) => {
    if (operation.status === "cleanup_failed") {
      items.push({ kind: "cleanup", label: "清理失败，需人工处理", operation });
    } else if (
      operation.submission_result_unknown ||
      operation.execution_result_unknown
    ) {
      items.push({
        kind: "unknown_result",
        label: "写入结果待确认",
        operation,
      });
    } else if (
      operation.role === "target" &&
      operation.status === "awaiting_authorization"
    ) {
      items.push({ kind: "approval", label: "待本机批准", operation });
    } else if (
      operation.role === "requester" &&
      operation.status === "authorized"
    ) {
      items.push({ kind: "execution", label: "待确认执行", operation });
    }
    return items;
  }, []);
}
