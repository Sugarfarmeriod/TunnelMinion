import { z } from "zod";

import { requestJson } from "../../api/client";
import { remoteRepairSchema } from "../repairs/api";

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

export const peerSchema = z
  .object({
    node_id: localServicesSchema.shape.node_id,
    relationship: z.enum(["mine", "friend", "legacy"]).optional(),
    display_name: z.string(),
    platform: z.enum(["windows", "macos", "linux"]).nullable(),
    is_local: z.boolean(),
    source: z.enum(["local", "gateway", "coordinator"]),
    reachable: z.boolean().nullable(),
    auth_rejected: z.boolean().default(false),
    last_seen_at: z.string().datetime({ offset: true }).nullable(),
    services_visible: z.boolean(),
    service_count: z.number().int().nonnegative(),
    pending_repairs: z.array(remoteRepairSchema).max(3).default([]),
  })
  .strict();

/** 对方巡检确认挂了的服务附带的摘要；旧版本的对方不带。 */
export const peerPatrolSchema = z
  .object({
    status: z.string(),
    reason: z.string().nullable(),
    reason_text: z.string().nullable(),
    confirmed_at: z.string().datetime({ offset: true }).nullable(),
    auto_repair: z.boolean(),
  })
  .strict();

export const peersSchema = z.object({ peers: z.array(peerSchema) }).strict();
export const peerServicesSchema = z
  .object({
    node_id: localServicesSchema.shape.node_id,
    display_name: z.string(),
    host: z.string().nullable(),
    observed_at: z.string().datetime({ offset: true }).nullable(),
    fetched_at: z.string().datetime({ offset: true }).nullable(),
    outcome: z
      .enum(["ok", "unreachable", "rejected", "forbidden", "error"])
      .nullable(),
    services: z.array(
      serviceEntrySchema.omit({ tier: true, endpoints: true }).extend({
        state: z.enum(["running", "stopped"]).default("running"),
        ports: z.array(serviceEndpointSchema.omit({ address: true })),
        patrol: peerPatrolSchema.nullable().default(null),
      }),
    ),
  })
  .strict();

export type Peer = z.infer<typeof peerSchema>;
export type PeerServices = z.infer<typeof peerServicesSchema>;
export type PeerPatrol = z.infer<typeof peerPatrolSchema>;
export const peersQueryKey = ["map-peers"] as const;
export const peerServicesQueryKey = (id: string) =>
  ["peer-services", id] as const;

export function loadPeers({ signal }: { signal?: AbortSignal }) {
  return requestJson("/api/peers", peersSchema, { signal });
}

export function loadPeerServices(id: string, signal?: AbortSignal) {
  return requestJson(
    `/api/peers/${encodeURIComponent(id)}/services`,
    peerServicesSchema,
    { signal },
  );
}

/** 对方报来、确认挂了的服务，按服务身份索引。 */
export function peerPatrol(view?: PeerServices): Record<string, PeerPatrol> {
  const values: Record<string, PeerPatrol> = {};
  for (const service of view?.services ?? [])
    if (service.patrol?.status === "down") values[service.key] = service.patrol;
  return values;
}

export function peerServiceEntries(view?: PeerServices): ServiceEntry[] {
  return (
    view?.services.map(({ ports, patrol: _patrol, ...service }) => ({
      ...service,
      tier: "show",
      endpoints: ports.map((port) => ({ ...port, address: view.host ?? "" })),
    })) ?? []
  );
}
