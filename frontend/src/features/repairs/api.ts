import { z } from "zod";

import { requestJson } from "../../api/client";
import { operationStatusSchema } from "../operations/schemas";

const timestamp = z.string().datetime({ offset: true });
export const remoteRepairSchema = z
  .object({
    repair_id: z.string().regex(/^operation_[0-9a-f]{32}$/),
    service_name: z.string().min(1).max(120),
    action: z.string().min(1).max(300),
    status: z.string().min(1).max(40),
    how_to_approve: z.string().min(1).max(500),
    expires_at: timestamp,
  })
  .strict();
export type RemoteRepair = z.infer<typeof remoteRepairSchema>;
export const repairSchema = z.object({
  repair_id: z.string().regex(/^operation_[0-9a-f]{32}$/),
  node_id: z.string().regex(/^node_[0-9a-f]{32}$/),
  service_key: z.string(),
  service_name: z.string(),
  kind: z.enum([
    "restart_containers",
    "relaunch_python",
    "restart_launch_agent",
  ]),
  status: operationStatusSchema,
  action_summary: z.string(),
  reason: z.string(),
  created_at: timestamp,
  approval_expires_at: timestamp.nullable(),
  verification_passed: z.boolean().nullable(),
  error: z
    .object({
      code: z.string(),
      message: z.string(),
      next_step: z.string().nullable(),
    })
    .nullable(),
  origin: z.object({
    kind: z.enum(["conversation", "delegation", "local_cli", "patrol"]),
    thread_id: z.string().nullable(),
    run_id: z.string().nullable(),
    delegation_id: z.string().nullable(),
    evidence: z.array(z.string()),
  }),
});

export const repairDetailSchema = repairSchema.extend({
  impact_summary: z.string(),
  verification_summary: z.string(),
  failure_summary: z.string(),
  advanced: z.union([
    z.object({ commands: z.array(z.string()) }),
    z.object({
      interpreter: z.string(),
      arguments: z.array(z.string()),
      working_directory: z.string(),
      ports: z.array(z.number()),
    }),
    z.object({
      command: z.string(),
      plist_path: z.string(),
      ports: z.array(z.number()),
    }),
  ]),
  verification: z
    .object({
      passed: z.boolean(),
      checks: z.array(
        z.object({ name: z.string(), passed: z.boolean(), detail: z.string() }),
      ),
      log_excerpt: z.string().nullable(),
    })
    .nullable(),
  cleanup: z.object({ detail: z.string() }).nullable(),
});

export type Repair = z.infer<typeof repairSchema>;
export type RepairDetail = z.infer<typeof repairDetailSchema>;
export const repairsQueryKey = ["repairs"] as const;
export const repairQueryKey = (id: string) => ["repair", id] as const;

export function loadRepairs({ signal }: { signal?: AbortSignal }) {
  return requestJson(
    "/api/repairs",
    z.object({ repairs: z.array(repairSchema) }),
    { signal },
  );
}

export function loadRepair(id: string, signal?: AbortSignal) {
  return requestJson(
    `/api/repairs/${encodeURIComponent(id)}`,
    repairDetailSchema,
    { signal },
  );
}

export function decideRepair(id: string, action: "approve" | "reject") {
  return requestJson(
    `/api/repairs/${encodeURIComponent(id)}/${action}`,
    repairDetailSchema,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    },
  );
}

export function isRepairExecuting(status: string) {
  return ["authorized", "executing", "verifying", "rolling_back"].includes(
    status,
  );
}

export const peerRepairSchema = z.object({
  repair_id: remoteRepairSchema.shape.repair_id,
  node_id: repairSchema.shape.node_id,
  service_name: z.string(),
  kind: z.string(),
  status: z.string(),
  action_summary: z.string(),
  reason: z.string(),
  impact_summary: z.string(),
  verification_summary: z.string(),
  failure_summary: z.string(),
  created_at: timestamp,
  updated_at: timestamp,
  approval_expires_at: timestamp.nullable(),
  approved_by_peer: z.boolean().nullable(),
  verification_passed: z.boolean().nullable(),
  error_code: z.string().nullable(),
  error_message: z.string().nullable(),
});

export const peerRepairAccessSchema = z.object({
  node_id: repairSchema.shape.node_id,
  repair_id: remoteRepairSchema.shape.repair_id,
  access: z.enum(["allowed", "not_allowed", "not_found", "unreachable"]),
  repair: peerRepairSchema.nullable(),
});
export type PeerRepair = z.infer<typeof peerRepairSchema>;

export function loadPeerRepair(
  nodeId: string,
  repairId: string,
  signal?: AbortSignal,
) {
  return requestJson(
    `/api/peers/${encodeURIComponent(nodeId)}/repairs/${encodeURIComponent(repairId)}`,
    peerRepairAccessSchema,
    { signal },
  );
}

export function decidePeerRepair(
  nodeId: string,
  repairId: string,
  action: "approve" | "reject",
) {
  return requestJson(
    `/api/peers/${encodeURIComponent(nodeId)}/repairs/${encodeURIComponent(repairId)}/${action}`,
    peerRepairAccessSchema,
    { method: "POST" },
  );
}

export function isRepairTerminal(status: string) {
  return [
    "succeeded",
    "rolled_back",
    "cleanup_failed",
    "rejected",
    "cancelled",
    "expired",
    "authorization_expired",
  ].includes(status);
}
