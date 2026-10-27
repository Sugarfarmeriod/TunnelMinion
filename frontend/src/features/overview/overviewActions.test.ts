import { describe, expect, it } from "vitest";

import type { ResourceOverview } from "../../api/schemas/overview";

import {
  incidentOperationHandoff,
  type IncidentHandoffInput,
  serviceDisplayName,
} from "./overviewActions";

const localNodeId = `node_${"1".repeat(32)}`;
const remoteNodeId = `node_${"2".repeat(32)}`;
const serviceId = `service_${"3".repeat(32)}`;
const incidentId = `incident_${"4".repeat(32)}`;
const observedAt = "2026-09-08T09:00:00+08:00";

const nodes: ResourceOverview["nodes"]["items"] = [
  {
    node_id: localNodeId,
    display_name: "本机",
    platform: "windows",
    state: "local",
    source: "local_observation",
    evidence_at: observedAt,
    freshness: "live",
    service_count: 0,
  },
  {
    node_id: remoteNodeId,
    display_name: "远端 Mac",
    platform: "macos",
    state: "online",
    source: "coordinator_directory",
    evidence_at: observedAt,
    freshness: "fresh",
    service_count: 1,
  },
];

const services: ResourceOverview["services"]["items"] = [
  {
    service_id: serviceId,
    node_id: remoteNodeId,
    display_name: "管理面板",
    protocol: "tcp",
    port: 8080,
    access_address: "tcp://127.0.0.1:8080",
    accessibility: "loopback",
    lifecycle: "active",
    state: "available",
    source: "coordinator_directory",
    evidence_at: observedAt,
    freshness: "fresh",
  },
];

const incident: IncidentHandoffInput = {
  incidentId,
  status: "confirmed",
  eventType: "local_only",
  objectKind: "service",
  objectId: serviceId,
  targetNodeId: remoteNodeId,
};

describe("serviceDisplayName", () => {
  const service = {
    ...services[0]!,
    display_name: "Python · nanobot · 8080",
    application: {
      group_id: `application_${"a".repeat(32)}`,
      name: "nanobot",
      kind: "python" as const,
    },
  };
  it("程序名优先，旧端仍用原名称，不修改服务或入口身份", () => {
    expect(serviceDisplayName(service)).toBe("nanobot");
    expect(serviceDisplayName({ ...service, application: null })).toBe(
      service.display_name,
    );
    expect(
      serviceDisplayName({
        ...service,
        application: { ...service.application, name: " " },
      }),
    ).toBe(service.display_name);
    expect(service.service_id).toBe(serviceId);
    expect(service.port).toBe(8080);
  });
  it.each(["stale", "expired", "unknown", "unavailable"] as const)(
    "%s 的名称不冒充当前程序",
    (freshness) => {
      expect(serviceDisplayName({ ...service, freshness })).toBeUndefined();
    },
  );
  it("没有已识别名称或服务记录时仍保持未知", () => {
    expect(serviceDisplayName(undefined)).toBeUndefined();
    expect(
      serviceDisplayName({ ...service, display_name: null }),
    ).toBeUndefined();
    expect(
      serviceDisplayName({ ...service, display_name: " " }),
    ).toBeUndefined();
  });
});

describe("incidentOperationHandoff", () => {
  it("只为已确认且仍新鲜的远端 local-only 服务生成预填链接", () => {
    expect(incidentOperationHandoff(incident, nodes, services)).toEqual({
      available: true,
      href: `/app/operations?incident_id=${incidentId}&target_node_id=${remoteNodeId}&service_port=8080`,
      servicePort: 8080,
      targetNodeId: remoteNodeId,
    });
  });

  it.each([
    [
      { ...incident, status: "investigating" as const },
      nodes,
      services,
      "还没有形成",
    ],
    [{ ...incident, targetNodeId: localNodeId }, nodes, services, "本机事件"],
    [incident, nodes, [], "找不到唯一"],
    [incident, nodes, [{ ...services[0], port: null }], "无法确定服务端口"],
    [
      incident,
      nodes,
      [{ ...services[0], protocol: "udp" as const }],
      "UDP 连接",
    ],
    [
      incident,
      nodes,
      [{ ...services[0], freshness: "stale" as const }],
      "证据已经陈旧",
    ],
    [
      incident,
      nodes,
      [{ ...services[0], state: "stopped" as const }],
      "停止或不可用",
    ],
  ])(
    "不可安全交接时给出确定性原因",
    (value, knownNodes, knownServices, message) => {
      expect(
        incidentOperationHandoff(value, knownNodes, knownServices),
      ).toEqual(
        expect.objectContaining({
          available: false,
          message: expect.stringContaining(message),
        }),
      );
    },
  );
});
