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
    display_name: z.string(),
    platform: z.enum(["windows", "macos", "linux"]).nullable(),
    is_local: z.boolean(),
    source: z.enum(["local", "gateway", "coordinator"]),
    reachable: z.boolean().nullable(),
    last_seen_at: z.string().datetime({ offset: true }).nullable(),
    services_visible: z.boolean(),
    service_count: z.number().int().nonnegative(),
    pending_repairs: z.array(remoteRepairSchema).max(3).default([]),
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
    outcome: z.enum(["ok", "unreachable", "forbidden", "error"]).nullable(),
    services: z.array(
      serviceEntrySchema.omit({ tier: true, endpoints: true }).extend({
        state: z.enum(["running", "stopped"]).default("running"),
        ports: z.array(serviceEndpointSchema.omit({ address: true })),
      }),
    ),
  })
  .strict();

export type Peer = z.infer<typeof peerSchema>;
export type PeerServices = z.infer<typeof peerServicesSchema>;
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

export function peerServiceEntries(view?: PeerServices): ServiceEntry[] {
  return (
    view?.services.map(({ ports, ...service }) => ({
      ...service,
      tier: "show",
      endpoints: ports.map((port) => ({ ...port, address: view.host ?? "" })),
    })) ?? []
  );
}
