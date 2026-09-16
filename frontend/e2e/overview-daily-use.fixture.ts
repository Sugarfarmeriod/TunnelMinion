import type { ResourceOverview } from "../src/api/schemas/overview";

const generatedAt = "2026-09-16T09:00:00+08:00";
const evidenceAt = generatedAt;
const observedAt = generatedAt;
const remoteNodeId = `node_${"2".repeat(32)}`;
const serviceId = `service_${"3".repeat(32)}`;
export const incidentId = `incident_${"4".repeat(32)}`;
const snapshotA = `snapshot_${"5".repeat(32)}`;
const snapshotB = `snapshot_${"6".repeat(32)}`;
function makeOverview(): ResourceOverview {
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

export function incidentDetail() {
  return {
    incident: {
      schema_version: "incident/v1",
      incident_id: incidentId,
      dedup_key: `sha256:${"a".repeat(64)}`,
      event: {
        event_type: "local_only",
        object_kind: "service",
        object_id: serviceId,
        target_node_id: remoteNodeId,
        baseline_snapshot_id: snapshotA,
        current_snapshot_id: snapshotB,
        baseline_revision: 1,
        current_revision: 2,
        observed_at: observedAt,
        source: "coordinator_directory",
        before_state: "network",
        after_state: "loopback",
        dedup_key: `sha256:${"a".repeat(64)}`,
      },
      status: "confirmed",
      created_at: observedAt,
      last_observed_at: observedAt,
      run_id: `run_${"8".repeat(32)}`,
      hypotheses: [],
      trace: [],
      report: {
        facts: ["服务只监听环回地址"],
        candidate_explanations: [],
        unknowns: [],
        conclusion: "远端服务只监听环回地址",
        stop_reason: "evidence_sufficient",
        evidence: [
          {
            snapshot_id: snapshotB,
            tool_run_id: null,
            observed_at: observedAt,
            summary: "当前快照确认环回监听",
          },
        ],
      },
    },
    suggested_questions: [],
    thread_id: null,
  };
}

export function dailyOverview(): ResourceOverview {
  const overview = makeOverview();
  overview.services.items = Array.from({ length: 13 }, (_, index) => ({
    service_id: `service_${index.toString(16).padStart(32, "0")}`,
    node_id: remoteNodeId,
    display_name: `本机服务 ${index + 1}`,
    protocol: "tcp",
    port: 9000 + index,
    access_address:
      `tcp://service-${index + 1}.example: ${9000 + index}`.replace(": ", ":"),
    accessibility: "network",
    lifecycle: "active",
    state: "available",
    source: "local_observation",
    evidence_at: evidenceAt,
    freshness: "fresh",
  }));
  overview.incidents.items = [
    {
      incident_id: incidentId,
      event_type: "local_only",
      object_kind: "service",
      object_id: serviceId,
      severity: "warning",
      status: "confirmed",
      first_observed_at: observedAt,
      last_observed_at: observedAt,
      conclusion: "服务只监听环回地址",
    },
  ];
  return overview;
}
