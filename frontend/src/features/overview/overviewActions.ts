import type { ResourceOverview } from "../../api/schemas/overview";
import type { OperationListItem } from "../operations/schemas";

type NodeItem = ResourceOverview["nodes"]["items"][number];
type ServiceItem = ResourceOverview["services"]["items"][number];

export const serviceKindLabels = {
  python: "Python 程序",
  docker: "Docker 容器",
  model: "模型服务",
  program: "自行安装的程序",
};

export function serviceDisplayName(
  service: ServiceItem | undefined,
): string | undefined {
  const name = service?.display_name?.trim();
  if (!name || !service || !["fresh", "live"].includes(service.freshness))
    return undefined;
  return service.application?.name.trim() || name;
}

export interface ServiceApplicationGroup {
  key: string;
  application: NonNullable<ServiceItem["application"]> | null;
  services: ServiceItem[];
}

export function groupServiceApplications(
  services: readonly ServiceItem[],
): ServiceApplicationGroup[] {
  const identities = new Map<string, string>();
  const conflicts = new Set<string>();
  for (const service of services) {
    const app = service.application;
    if (!app) continue;
    const key = `${service.node_id}:${app.group_id}`;
    const identity = JSON.stringify([app.name, app.kind]);
    if (identities.has(key) && identities.get(key) !== identity)
      conflicts.add(key);
    identities.set(key, identity);
  }
  const groups: ServiceApplicationGroup[] = [];
  const seen = new Map<string, ServiceApplicationGroup>();
  services.forEach((service, index) => {
    const app = service.application;
    const key = `${service.node_id}:${app?.group_id}`;
    if (
      !app?.name.trim() ||
      !["fresh", "live"].includes(service.freshness) ||
      conflicts.has(key)
    ) {
      groups.push({
        key: `${service.service_id}:${index}`,
        application: null,
        services: [service],
      });
      return;
    }
    const group = seen.get(key);
    if (group) group.services.push(service);
    else {
      const created = { key, application: app, services: [service] };
      seen.set(key, created);
      groups.push(created);
    }
  });
  return groups.some((group) => group.application)
    ? groups.sort((a, b) =>
        (
          a.application?.name ??
          a.services[0]!.display_name ??
          ""
        ).localeCompare(
          b.application?.name ?? b.services[0]!.display_name ?? "",
          "zh-CN",
          { numeric: true },
        ),
      )
    : groups;
}

export function serviceIncidentLinks(
  services: readonly ServiceItem[],
  incidents: ResourceOverview["incidents"]["items"],
): Map<string, string> {
  const counts = new Map<string, number>();
  for (const service of services) {
    counts.set(service.service_id, (counts.get(service.service_id) ?? 0) + 1);
  }
  const links = new Map<string, string>();
  const latestFirst = [...incidents].sort(
    (a, b) => Date.parse(b.last_observed_at) - Date.parse(a.last_observed_at),
  );
  for (const incident of latestFirst) {
    if (
      incident.object_kind === "service" &&
      counts.get(incident.object_id) === 1 &&
      !links.has(incident.object_id)
    ) {
      links.set(incident.object_id, incident.incident_id);
    }
  }
  return links;
}

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
  if (service.protocol === "udp") {
    return {
      available: false,
      message: "这是 UDP 连接，不适用于现有网页临时访问方案。",
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
        label: "结果待确认",
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
