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
