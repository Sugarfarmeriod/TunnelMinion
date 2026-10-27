import type { ResourceOverview } from "../../api/schemas/overview";
import type { LocalServices, Peer, PeerServices, ServiceEntry } from "./api";

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

export function makePeer(index = 1, overrides: Partial<Peer> = {}): Peer {
  return {
    node_id: `node_${index.toString(16).padStart(32, "0")}`,
    display_name: `测试电脑 ${index}`,
    platform: "macos",
    is_local: false,
    source: "gateway",
    reachable: true,
    last_seen_at: "2026-10-27T08:00:00Z",
    services_visible: true,
    service_count: 1,
    pending_repairs: [],
    ...overrides,
  };
}

export function makePeerServices(
  peer = makePeer(),
  overrides: Partial<PeerServices> = {},
): PeerServices {
  return {
    node_id: peer.node_id,
    display_name: peer.display_name,
    host: "192.0.2.42",
    observed_at: "2026-10-27T08:00:00Z",
    fetched_at: "2026-10-27T08:00:01Z",
    outcome: "ok",
    services: [
      {
        key: "python:app.py",
        name: "远端相册",
        kind: "python",
        state: "running",
        mark: null,
        web_title: null,
        ports: [{ protocol: "tcp", port: 8080, has_web_page: true }],
      },
    ],
    ...overrides,
  };
}
