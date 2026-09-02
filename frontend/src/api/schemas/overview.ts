import { z } from "zod";

const timestamp = z.string().datetime({ offset: true });
const optionalTimestamp = timestamp.nullable();
const nodeId = z.string().regex(/^node_[0-9a-f]{32}$/);
const serviceId = z.string().regex(/^service_[0-9a-f]{32}$/);
const incidentId = z.string().regex(/^incident_[0-9a-f]{32}$/);
const snapshotId = z.string().regex(/^snapshot_[0-9a-f]{32}$/);
const toolRunId = z.string().regex(/^toolrun_[0-9a-f]{32}$/);
const threadId = z.string().regex(/^thread_[0-9a-f]{32}$/);
const incidentEventType = z.enum([
  "service_added",
  "service_removed",
  "node_offline",
  "state_stale",
  "local_only",
  "remote_unreachable",
]);
const incidentStatus = z.enum([
  "pending",
  "investigating",
  "confirmed",
  "insufficient_evidence",
  "budget_exhausted",
  "cancelled",
  "failed",
  "interrupted",
  "investigation_unavailable",
  "closed",
]);
const stopReason = z.enum([
  "evidence_sufficient",
  "insufficient_evidence",
  "budget_exhausted",
  "cancelled",
  "failed",
  "interrupted",
  "model_unavailable",
]);
const freshness = z.enum([
  "live",
  "fresh",
  "stale",
  "expired",
  "unavailable",
  "not_applicable",
  "unknown",
]);
const source = z.enum([
  "local_runtime",
  "model_configuration",
  "coordinator_sync",
  "coordinator_directory",
  "network_path_evidence",
  "local_observation",
  "aggregated",
  "unknown",
]);
const error = z
  .object({
    code: z.string().regex(/^[a-z][a-z0-9_-]*$/),
    retryable: z.boolean(),
  })
  .strict()
  .nullable();
const section = {
  source,
  evidence_at: optionalTimestamp,
  freshness,
  error,
} as const;

const networkEvidence = z
  .object({
    status: z.enum(["passed", "failed", "missing", "unknown"]),
    observed_at: optionalTimestamp,
  })
  .strict();

export const resourceOverviewSchema = z
  .object({
    schema_version: z.literal("resource-overview/v1"),
    generated_at: timestamp,
    local: z
      .object({
        ...section,
        runtime: z.enum([
          "running",
          "starting",
          "stopping",
          "stopped",
          "degraded",
          "unknown",
        ]),
        platform: z.enum(["windows", "macos", "linux"]).nullable(),
        version: z.string().nullable(),
        package: z
          .object({
            name: z.literal("tunnelminion"),
            kind: z.enum(["source", "wheel", "standalone", "unknown"]),
            version: z.string().nullable(),
            manifest_schema: z.string().nullable(),
          })
          .strict(),
        readiness: z.enum(["ready", "degraded", "unavailable", "unknown"]),
      })
      .strict(),
    model: z
      .object({
        ...section,
        configured: z.boolean().nullable(),
        status: z.enum(["unconfigured", "available", "unavailable", "unknown"]),
      })
      .strict(),
    coordinator: z
      .object({
        ...section,
        configured: z.boolean().nullable(),
        state: z.enum([
          "unconfigured",
          "config_invalid",
          "credential_missing",
          "sync_not_started",
          "connecting",
          "ready",
          "stale",
          "offline",
          "incompatible",
          "managed_auth_expired",
          "unknown",
        ]),
        revision: z.number().int().nonnegative().nullable(),
        last_success_at: optionalTimestamp,
      })
      .strict(),
    network_path: z
      .object({
        ...section,
        configured: z.boolean().nullable(),
        state: z.enum([
          "unconfigured",
          "pending",
          "direct",
          "relayed",
          "static",
          "offline",
          "unknown",
        ]),
        provider: z.enum(["windows", "macos"]).nullable(),
        revision: z.number().int().nonnegative().nullable(),
        handshake: networkEvidence,
        route: networkEvidence,
        probe: networkEvidence,
      })
      .strict(),
    nodes: z
      .object({
        ...section,
        items: z.array(
          z
            .object({
              node_id: nodeId,
              display_name: z.string(),
              platform: z.enum(["windows", "macos", "linux"]).nullable(),
              state: z.enum([
                "local",
                "online",
                "stale",
                "offline",
                "revoked",
                "incompatible",
                "unknown",
              ]),
              source,
              evidence_at: optionalTimestamp,
              freshness,
              service_count: z.number().int().nonnegative(),
            })
            .strict(),
        ),
      })
      .strict(),
    services: z
      .object({
        ...section,
        items: z.array(
          z
            .object({
              service_id: serviceId,
              node_id: nodeId,
              display_name: z.string().nullable(),
              protocol: z.enum(["tcp", "udp", "http", "https"]).nullable(),
              port: z.number().int().min(1).max(65535).nullable(),
              access_address: z.string().min(1).max(320).nullable(),
              accessibility: z
                .enum(["loopback", "network", "unknown"])
                .nullable(),
              lifecycle: z.enum(["active", "stopped"]).nullable(),
              state: z.enum([
                "available",
                "degraded",
                "unavailable",
                "stopped",
                "unknown",
              ]),
              source,
              evidence_at: optionalTimestamp,
              freshness,
            })
            .strict(),
        ),
      })
      .strict(),
    incidents: z
      .object({
        ...section,
        items: z.array(
          z
            .object({
              incident_id: incidentId,
              event_type: incidentEventType,
              object_kind: z.enum(["node", "service"]),
              object_id: z.string(),
              severity: z.enum(["info", "warning", "critical"]),
              status: incidentStatus,
              first_observed_at: timestamp,
              last_observed_at: timestamp,
              conclusion: z.string().nullable(),
            })
            .strict(),
        ),
      })
      .strict(),
  })
  .strict();

export type ResourceOverview = z.infer<typeof resourceOverviewSchema>;

const evidenceReference = z
  .object({
    snapshot_id: snapshotId.nullable(),
    tool_run_id: toolRunId.nullable(),
    observed_at: timestamp,
    summary: z.string(),
  })
  .strict();

export const incidentDetailSchema = z
  .object({
    incident: z
      .object({
        schema_version: z.literal("incident/v1"),
        incident_id: incidentId,
        dedup_key: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        event: z
          .object({
            event_type: incidentEventType,
            object_kind: z.enum(["node", "service"]),
            object_id: z.string(),
            target_node_id: nodeId,
            baseline_snapshot_id: snapshotId,
            current_snapshot_id: snapshotId,
            baseline_revision: z.number().int().nonnegative(),
            current_revision: z.number().int().nonnegative(),
            observed_at: timestamp,
            source,
            before_state: z.string().nullable(),
            after_state: z.string().nullable(),
            dedup_key: z.string().regex(/^sha256:[0-9a-f]{64}$/),
          })
          .strict(),
        status: incidentStatus,
        created_at: timestamp,
        last_observed_at: timestamp,
        run_id: z
          .string()
          .regex(/^run_[0-9a-f]{32}$/)
          .nullable(),
        hypotheses: z.array(
          z
            .object({
              hypothesis_id: z.string().regex(/^hypothesis_[0-9a-f]{16}$/),
              summary: z.string(),
              status: z.enum(["candidate", "supported", "rejected", "unknown"]),
              evidence: z.array(evidenceReference),
            })
            .strict(),
        ),
        trace: z.array(
          z
            .object({
              occurred_at: timestamp,
              kind: z.enum([
                "status",
                "hypothesis",
                "tool",
                "evidence",
                "report",
              ]),
              summary: z.string(),
              tool_name: z.string().nullable(),
              evidence: z.array(evidenceReference),
            })
            .strict(),
        ),
        report: z
          .object({
            facts: z.array(z.string()),
            candidate_explanations: z.array(z.string()),
            unknowns: z.array(z.string()),
            conclusion: z.string().nullable(),
            stop_reason: stopReason,
            evidence: z.array(evidenceReference),
          })
          .strict()
          .nullable(),
      })
      .strict(),
    suggested_questions: z.array(z.string()).max(3),
    thread_id: threadId.nullable(),
  })
  .strict();

export type IncidentDetail = z.infer<typeof incidentDetailSchema>;
