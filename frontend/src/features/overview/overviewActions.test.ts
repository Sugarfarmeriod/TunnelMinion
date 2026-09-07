import { describe, expect, it } from "vitest";

import type { ResourceOverview } from "../../api/schemas/overview";
import { makeOperationListItem } from "../operations/testFixtures";

import {
  incidentOperationHandoff,
  operationsRequiringAttention,
  type IncidentHandoffInput,
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

describe("operationsRequiringAttention", () => {
  it("只保留本机待批准、待执行、结果未知和清理失败", () => {
    const attention = operationsRequiringAttention([
      makeOperationListItem({ operation_id: `operation_${"1".repeat(32)}` }),
      makeOperationListItem({
        operation_id: `operation_${"2".repeat(32)}`,
        role: "requester",
        status: "authorized",
      }),
      makeOperationListItem({
        operation_id: `operation_${"3".repeat(32)}`,
        role: "requester",
        status: "awaiting_authorization",
      }),
      makeOperationListItem({
        operation_id: `operation_${"4".repeat(32)}`,
        status: "succeeded",
      }),
      makeOperationListItem({
        operation_id: `operation_${"5".repeat(32)}`,
        role: "requester",
        submission_result_unknown: true,
      }),
      makeOperationListItem({
        operation_id: `operation_${"6".repeat(32)}`,
        status: "cleanup_failed",
      }),
    ]);

    expect(
      attention.map(({ kind, operation }) => [kind, operation.operation_id]),
    ).toEqual([
      ["approval", `operation_${"1".repeat(32)}`],
      ["execution", `operation_${"2".repeat(32)}`],
      ["unknown_result", `operation_${"5".repeat(32)}`],
      ["cleanup", `operation_${"6".repeat(32)}`],
    ]);
  });
});
