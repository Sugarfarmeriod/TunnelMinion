import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import { requestJson } from "../../api/client";
import { isReadOnlyPreview } from "../../shared/previewMode";

const dateTime = z.string().datetime({ offset: true });

export const patrolServiceSchema = z
  .object({
    key: z.string().min(1),
    name: z.string().min(1),
    status: z.enum(["ok", "suspect", "down", "acknowledged"]),
    reason: z
      .enum(["container_exited", "script_exited", "port_closed", "web_failed"])
      .nullable(),
    reason_text: z.string().nullable(),
    down_since: dateTime.nullable(),
    confirmed_at: dateTime.nullable(),
    thread_id: z.string().nullable(),
    repair_id: z.string().nullable(),
    auto_repair: z
      .object({
        available: z.boolean(),
        kind: z.enum(["restart_containers", "relaunch_python"]).nullable(),
        enabled: z.boolean(),
        enabled_on: z.string().date().nullable(),
        paused: z.boolean(),
        last_attempt_at: dateTime.nullable(),
        last_result: z.enum(["succeeded", "failed"]).nullable(),
      })
      .strict(),
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

export function setAutoRepair({
  key,
  enabled,
}: {
  key: string;
  enabled: boolean;
}) {
  return requestJson(
    `/api/patrol/services/${encodeURIComponent(key)}/auto-repair`,
    patrolSchema,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
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
