import type { ResourceOverview } from "../../api/schemas/overview";
const generatedAt = "2026-08-08T09:00:00+08:00";
const evidenceAt = "2026-08-08T08:59:00+08:00";

export function makeOverview(): ResourceOverview {
  return {
    schema_version: "resource-overview/v1",
    generated_at: generatedAt,
    local: {
      source: "local_runtime",
      evidence_at: evidenceAt,
      freshness: "live",
      error: null,
      runtime: "running",
      platform: "windows",
      version: "0.1.0",
      package: {
        name: "tunnelminion",
        kind: "source",
        version: "0.1.0",
        manifest_schema: null,
      },
      readiness: "ready",
    },
    model: {
      source: "model_configuration",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      status: "available",
    },
    coordinator: {
      source: "coordinator_sync",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      state: "ready",
      revision: 12,
      last_success_at: evidenceAt,
    },
    network_path: {
      source: "network_path_evidence",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      state: "direct",
      provider: "windows",
      revision: 4,
      handshake: { status: "passed", observed_at: evidenceAt },
      route: { status: "passed", observed_at: evidenceAt },
      probe: { status: "passed", observed_at: evidenceAt },
    },
    nodes: {
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      items: [],
    },
    services: {
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      items: [],
    },
    incidents: {
      source: "local_observation",
      evidence_at: null,
      freshness: "not_applicable",
      error: null,
      items: [],
    },
  };
}
