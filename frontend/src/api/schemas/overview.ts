import { z } from "zod";

const timestamp = z.string().datetime({ offset: true });
const optionalTimestamp = timestamp.nullable();
const nodeId = z.string().regex(/^node_[0-9a-f]{32}$/);
const serviceId = z.string().regex(/^service_[0-9a-f]{32}$/);
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
  })
  .strict();

export type ResourceOverview = z.infer<typeof resourceOverviewSchema>;
