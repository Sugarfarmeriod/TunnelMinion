import { z } from "zod";

import { requestJson } from "../../api/client";

export const serviceEndpointSchema = z
  .object({
    protocol: z.enum(["tcp", "udp"]),
    address: z.string(),
    port: z.number().int().min(1).max(65535),
    has_web_page: z.boolean().nullable(),
  })
  .strict();

export const serviceEntrySchema = z
  .object({
    key: z.string().min(1).max(160),
    name: z.string().min(1).max(80),
    kind: z.enum(["docker", "python", "program"]),
    tier: z.enum(["show", "review", "hidden"]),
    state: z.enum(["running", "stopped"]).optional(),
    mark: z.enum(["mine", "hidden"]).nullable(),
    web_title: z.string().nullable(),
    endpoints: z.array(serviceEndpointSchema),
  })
  .strict();

export const localServicesSchema = z
  .object({
    node_id: z.string().regex(/^node_[0-9a-f]{32}$/),
    observed_at: z.string().datetime({ offset: true }).nullable(),
    services: z.array(serviceEntrySchema),
  })
  .strict();

export type ServiceEntry = z.infer<typeof serviceEntrySchema>;
export type LocalServices = z.infer<typeof localServicesSchema>;
export const localServicesQueryKey = ["local-services"] as const;

export function loadLocalServices({ signal }: { signal?: AbortSignal }) {
  return requestJson("/api/services/local", localServicesSchema, { signal });
}

export function updateServiceMark({
  key,
  mark,
}: {
  key: string;
  mark: "mine" | "hidden" | null;
}) {
  return requestJson(
    `/api/services/marks/${encodeURIComponent(key)}`,
    localServicesSchema,
    mark === null
      ? { method: "DELETE" }
      : {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mark }),
        },
  );
}
