import type { ResourceOverview } from "../../api/schemas/overview";
import type { LocalServices, ServiceEntry } from "./api";

export function makeService(
  overrides: Partial<ServiceEntry> = {},
): ServiceEntry {
  return {
    key: "python:app.py",
    name: "WireGuard Panel",
    kind: "python",
    tier: "show",
    mark: null,
    web_title: "WireGuard Panel",
    endpoints: [
      { protocol: "tcp", address: "127.0.0.1", port: 8787, has_web_page: true },
    ],
    ...overrides,
  };
}

export function makeLocalServices(services = [makeService()]): LocalServices {
  return {
    node_id: "node_0123456789abcdef0123456789abcdef",
    observed_at: "2026-10-22T12:21:18.989784Z",
    services,
  };
}

export function makeMapOverview(
  platform: ResourceOverview["local"]["platform"] = "windows",
): ResourceOverview {
  const section = {
    source: "unknown",
    evidence_at: null,
    freshness: "unknown",
    error: null,
  } as const;
  return {
    schema_version: "resource-overview/v1",
    generated_at: "2026-10-22T12:21:18Z",
    local: {
      ...section,
      platform,
      runtime: "running",
      version: null,
      readiness: "ready",
      package: {
        name: "tunnelminion",
        kind: "source",
        version: null,
        manifest_schema: null,
      },
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
    incidents: { ...section, items: [] },
  };
}
