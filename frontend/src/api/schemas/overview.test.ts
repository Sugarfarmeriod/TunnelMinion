import { describe, expect, it } from "vitest";

import { resourceOverviewSchema } from "./overview";

const section = {
  source: "unknown",
  evidence_at: null,
  freshness: "unknown",
  error: { code: "overview_provider_missing", retryable: false },
} as const;

function validOverview() {
  return {
    schema_version: "resource-overview/v1",
    generated_at: "2026-08-08T00:00:00Z",
    local: {
      ...section,
      runtime: "unknown",
      platform: null,
      version: null,
      package: {
        name: "tunnelminion",
        kind: "unknown",
        version: null,
        manifest_schema: null,
      },
      readiness: "unknown",
    },
    model: { ...section, configured: null, status: "unknown" },
    coordinator: {
      ...section,
      configured: null,
      state: "unknown",
      revision: null,
      last_success_at: null,
    },
    network_path: {
      ...section,
      configured: null,
      state: "unknown",
      provider: null,
      revision: null,
      handshake: { status: "unknown", observed_at: null },
      route: { status: "unknown", observed_at: null },
      probe: { status: "unknown", observed_at: null },
    },
    nodes: { ...section, items: [] },
    services: { ...section, items: [] },
  };
}

describe("overview 运行时契约", () => {
  it("接受服务端显式 unknown 降级", () => {
    expect(
      resourceOverviewSchema.parse(validOverview()).coordinator.state,
    ).toBe("unknown");
  });

  it("接受后端公开的不透明 node/service 标识符，不把它们误当 UUID", () => {
    const node = {
      node_id: `node_${"1".repeat(32)}`,
      display_name: "本机",
      platform: "windows",
      state: "local",
      source: "local_observation",
      evidence_at: "2026-08-08T00:00:00Z",
      freshness: "live",
      service_count: 1,
    };
    const overview = {
      ...validOverview(),
      nodes: { ...section, items: [node] },
      services: {
        ...section,
        items: [
          {
            service_id: `service_${"2".repeat(32)}`,
            node_id: node.node_id,
            display_name: "本机面板",
            protocol: "http",
            port: 4175,
            access_address: "http://127.0.0.1:4175",
            accessibility: "loopback",
            lifecycle: "active",
            state: "available",
            source: "local_observation",
            evidence_at: "2026-08-08T00:00:00Z",
            freshness: "live",
          },
        ],
      },
    };

    expect(resourceOverviewSchema.parse(overview).nodes.items).toHaveLength(1);
    expect(() =>
      resourceOverviewSchema.parse({
        ...overview,
        nodes: {
          ...overview.nodes,
          items: [{ ...node, node_id: "6fcf3484-754b-46c6-bc3e-f4571e76495e" }],
        },
      }),
    ).toThrow();
  });

  it("拒绝未知字段和伪造正常状态", () => {
    expect(() =>
      resourceOverviewSchema.parse({
        ...validOverview(),
        access_token: "secret",
      }),
    ).toThrow();
    const invalid = validOverview();
    invalid.network_path.state = "healthy";
    expect(() => resourceOverviewSchema.parse(invalid)).toThrow();
  });
});
