import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import { requestJson } from "../../api/client";
import { isReadOnlyPreview } from "../../shared/previewMode";
import { manualStepSchema } from "../repairs/api";

const dateTime = z.string().datetime({ offset: true });

export const patrolServiceSchema = z
  .object({
    key: z.string().min(1),
    name: z.string().min(1),
    status: z.enum(["ok", "suspect", "down", "acknowledged"]),
    reason: z
      .enum([
        "container_exited",
        "script_exited",
        "agent_exited",
        "program_exited",
        "service_stopped",
        "port_closed",
        "web_failed",
        "stuck",
      ])
      .nullable(),
    reason_text: z.string().nullable(),
    down_since: dateTime.nullable(),
    confirmed_at: dateTime.nullable(),
    thread_id: z.string().nullable(),
    repair_id: z.string().nullable(),
    // 巡检想提修法却被拒绝的原因，以及本机生成、只显示不执行的现成步骤。
    repair_refusal: z.string().nullable(),
    manual_steps: z.array(manualStepSchema).max(5),
    auto_repair: z
      .object({
        available: z.boolean(),
        kind: z
          .enum([
            "restart_containers",
            "relaunch_python",
            "restart_launch_agent",
            "relaunch_program",
            "restart_stuck_program",
            "restart_windows_service",
          ])
          .nullable(),
        enabled: z.boolean(),
        enabled_on: z.string().date().nullable(),
        paused: z.boolean(),
        last_attempt_at: dateTime.nullable(),
        last_result: z.enum(["succeeded", "failed"]).nullable(),
        // 卡住时有没有现成修法，以及"卡住了也自动修"是否单独打开。
        stuck_available: z.boolean(),
        stuck_enabled: z.boolean(),
      })
      .strict(),
    // 主人标过的 Windows 服务：实际的服务名、程序路径，是否允许 Agent 启停它；
    // allowed 为假时只能撤回（没标成“是我的服务”，或是系统、受保护的软件）。
    windows_service: z
      .object({
        name: z.string().min(1),
        display_name: z.string(),
        binary_path: z.string(),
        granted: z.boolean(),
        allowed: z.boolean(),
      })
      .strict()
      .nullable(),
  })
  .strict();

export const patrolSchema = z
  .object({
    checked_at: dateTime.nullable(),
    investigations_left_today: z.number().int().nonnegative(),
    services: z.array(patrolServiceSchema),
  })
  .strict();

export type PatrolService = z.infer<typeof patrolServiceSchema>;
export type Patrol = z.infer<typeof patrolSchema>;
export const patrolQueryKey = ["patrol"] as const;

export function loadPatrol({ signal }: { signal?: AbortSignal }) {
  return requestJson("/api/patrol", patrolSchema, { signal });
}

/** stuck 不给时后端保持"卡住了也自动修"原样；关掉 enabled 时后端一并关掉 stuck。 */
export function setAutoRepair({
  key,
  enabled,
  stuck,
}: {
  key: string;
  enabled: boolean;
  stuck?: boolean;
}) {
  return requestJson(
    `/api/patrol/services/${encodeURIComponent(key)}/auto-repair`,
    patrolSchema,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        stuck === undefined ? { enabled } : { enabled, stuck },
      ),
    },
  );
}

/** 允许或撤回 Agent 启停这个 Windows 服务；会在本机弹一次管理员确认，可能要等几十秒。 */
export function setWindowsServiceGrant({
  key,
  granted,
}: {
  key: string;
  granted: boolean;
}) {
  return requestJson(
    `/api/patrol/services/${encodeURIComponent(key)}/windows-service`,
    patrolSchema,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ granted }),
    },
  );
}

export function acknowledgeDown(key: string) {
  return requestJson(
    `/api/patrol/services/${encodeURIComponent(key)}/acknowledge`,
    patrolSchema,
    { method: "POST" },
  );
}

/** 把已停止的服务从地图上移除，不再追踪；正在运行的服务后端会拒绝。 */
export function forgetService(key: string) {
  return requestJson(
    `/api/patrol/services/${encodeURIComponent(key)}/forget`,
    patrolSchema,
    { method: "POST" },
  );
}

/** "2026-10-29" → "2026年10月29日"。 */
export function chineseDate(value: string) {
  const [year, month, day] = value.split("-").map(Number);
  return `${year}年${month}月${day}日`;
}

/** 巡检状态按服务身份索引；只读预览没有巡检。 */
export function usePatrol() {
  const query = useQuery({
    queryKey: patrolQueryKey,
    queryFn: loadPatrol,
    refetchInterval: 15_000,
    enabled: !isReadOnlyPreview(),
    retry: false,
  });
  const byKey: Record<string, PatrolService> = {};
  for (const service of query.data?.services ?? [])
    byKey[service.key] = service;
  const down = (query.data?.services ?? []).filter(
    (service) => service.status === "down",
  );
  return { ...query, byKey, down };
}
