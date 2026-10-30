import { z } from "zod";

import { requestJson } from "../../api/client";
import { operationStatusSchema } from "../operations/schemas";

const timestamp = z.string().datetime({ offset: true });

/** 修不了时本机按固定模板生成的一步：只显示、不执行。 */
export const manualStepSchema = z
  .object({
    text: z.string().min(1),
    command: z.string().min(1).nullable(),
  })
  .strict();
export type ManualStep = z.infer<typeof manualStepSchema>;

export const repairKindSchema = z.enum([
  "restart_containers",
  "relaunch_python",
  "restart_launch_agent",
  "relaunch_program",
  "restart_stuck_program",
  "restart_windows_service",
]);
export type RepairKind = z.infer<typeof repairKindSchema>;
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
  kind: repairKindSchema,
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
      manual_steps: z.array(manualStepSchema).max(5),
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
  // 联合按从具体到宽泛排列：zod 取第一个能解析的分支，并丢掉它不认识的字段。
  advanced: z.union([
    // Windows 服务：sc.exe 命令和服务程序路径。
    z.object({
      commands: z.array(z.string()),
      binary_path: z.string(),
      ports: z.array(z.number()),
    }),
    // 后台服务：kickstart 命令和配置文件。
    z.object({
      command: z.string(),
      plist_path: z.string(),
      ports: z.array(z.number()),
    }),
    // 普通程序或卡住的程序：重新运行的命令，卡住时还有要先结束的进程。
    z.object({
      command: z.string(),
      ports: z.array(z.number()),
      end_process_id: z.number().int().nullable(),
    }),
    // 容器：docker 命令。
    z.object({ commands: z.array(z.string()) }),
    z.object({
      interpreter: z.string(),
      arguments: z.array(z.string()),
      working_directory: z.string(),
      ports: z.array(z.number()),
    }),
  ]),
  execution: z
    .object({
      // 卡住的程序：结束了哪个进程，以及是不是用了强制结束。
      ended_process_id: z.number().int().nullable().optional(),
      ended_forcibly: z.boolean().nullable().optional(),
    })
    .nullable()
    .optional(),
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
