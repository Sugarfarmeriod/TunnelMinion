import { z } from "zod";

import { requestJson, requestNoContent } from "../../api/client";

const nodeId = z.string().regex(/^node_[0-9a-f]{32}$/);
const platform = z.enum(["windows", "macos", "linux"]).nullable();
const timestamp = z.string().datetime({ offset: true });

const ownDeviceSchema = z
  .object({
    node_id: nodeId,
    display_name: z.string(),
    platform,
    host: z.string(),
    port: z.number().int(),
    is_local: z.boolean(),
    permissions: z
      .object({
        allow_delegation: z.boolean(),
        allow_model_borrowing: z.boolean(),
        allow_proxy_repair_approval: z.boolean(),
      })
      .strict(),
  })
  .strict();

const friendSchema = z
  .object({
    owner_fingerprint: z.string(),
    display_name: z.string(),
    allow_model_borrowing: z.boolean(),
    devices: z.array(
      z
        .object({ node_id: nodeId, display_name: z.string(), platform })
        .strict(),
    ),
    conflicting_devices: z.array(z.string()),
  })
  .strict();

const legacyPeerSchema = z
  .object({
    node_id: nodeId,
    display_name: z.string(),
    platform,
    host: z.string(),
    port: z.number().int(),
    allow_proxy_repair_approval: z.boolean(),
  })
  .strict();

export const identitySchema = z
  .object({
    initialized: z.boolean(),
    local_display_name: z.string(),
    owner_fingerprint: z.string().nullable(),
    has_owner_key: z.boolean(),
    removed: z.boolean(),
    roster_version: z.number().int().nullable(),
    trust_list_version: z.number().int().nullable(),
    bind: z
      .object({ host: z.string(), port: z.number().int() })
      .strict()
      .nullable(),
    address_candidates: z.array(z.string()),
    devices: z.array(ownDeviceSchema),
    friends: z.array(friendSchema),
    legacy_peers: z.array(legacyPeerSchema),
  })
  .strict();

export const inspectionSchema = z
  .object({
    kind: z.enum(["owner", "friend"]),
    owner_fingerprint: z.string(),
    inviter_host: z.string(),
    inviter_port: z.number().int(),
    expires_at: timestamp,
    expired: z.boolean(),
    suggested_host: z.string().nullable(),
    suggested_port: z.number().int(),
    bind_locked: z.boolean(),
  })
  .strict();

const setupSchema = z
  .object({
    setup_id: z.string().min(1),
    recovery_code: z.string().min(1),
    expires_at: timestamp,
  })
  .strict();

const issuedSchema = z
  .object({ code: z.string().min(1), expires_at: timestamp })
  .strict();

const pushSchema = z.object({ unreached: z.array(z.string()) }).strict();

export type Identity = z.infer<typeof identitySchema>;
export type OwnDevice = z.infer<typeof ownDeviceSchema>;
export type Friend = z.infer<typeof friendSchema>;
export type Inspection = z.infer<typeof inspectionSchema>;
export type Setup = z.infer<typeof setupSchema>;
export type IssuedCode = z.infer<typeof issuedSchema>;
export type PushResult = z.infer<typeof pushSchema>;
export type DevicePermissionName = keyof OwnDevice["permissions"];

export const identityQueryKey = ["identity"] as const;

function send(method: string, body?: unknown): RequestInit {
  return body === undefined
    ? { method }
    : {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      };
}

export function loadIdentity() {
  return requestJson("/api/identity", identitySchema);
}

export function inspectCode(code: string) {
  return requestJson(
    "/api/identity/codes:inspect",
    inspectionSchema,
    send("POST", { code }),
  );
}

export function startSetup(body: {
  host?: string;
  port?: number;
  display_name?: string;
}) {
  return requestJson("/api/identity/setup", setupSchema, send("POST", body));
}

export function confirmSetup(setupId: string, recoveryCode: string) {
  return requestJson(
    `/api/identity/setup/${encodeURIComponent(setupId)}:confirm`,
    identitySchema,
    send("POST", { recovery_code: recoveryCode }),
  );
}

export function cancelSetup(setupId: string) {
  return requestNoContent(
    `/api/identity/setup/${encodeURIComponent(setupId)}`,
    send("DELETE"),
  );
}

export function joinOwner(body: {
  code: string;
  host?: string;
  port?: number;
}) {
  return requestJson(
    "/api/identity/owner:join",
    identitySchema,
    send("POST", body),
  );
}

export function joinFriend(body: { code: string; display_name?: string }) {
  return requestJson(
    "/api/identity/friends:join",
    identitySchema,
    send("POST", body),
  );
}

export function inviteDevice() {
  return requestJson("/api/identity/owner:invite", issuedSchema, send("POST"));
}

export function inviteFriend(displayName?: string) {
  return requestJson(
    "/api/identity/friends:invite",
    issuedSchema,
    send(
      "POST",
      displayName === undefined ? {} : { display_name: displayName },
    ),
  );
}

export function removeDevice(nodeId: string) {
  return requestJson(
    `/api/identity/devices/${encodeURIComponent(nodeId)}`,
    pushSchema,
    send("DELETE"),
  );
}

export function closeDevicePermission(
  nodeId: string,
  name: DevicePermissionName,
) {
  return requestJson(
    `/api/identity/devices/${encodeURIComponent(nodeId)}/permissions`,
    identitySchema,
    send("PUT", { [name]: false }),
  );
}

export function renameFriend(fingerprint: string, displayName: string) {
  return requestJson(
    `/api/identity/friends/${encodeURIComponent(fingerprint)}`,
    pushSchema,
    send("PATCH", { display_name: displayName }),
  );
}

export function setFriendBorrowing(fingerprint: string, allowed: boolean) {
  return requestJson(
    `/api/identity/friends/${encodeURIComponent(fingerprint)}/permissions`,
    pushSchema,
    send("PUT", { allow_model_borrowing: allowed }),
  );
}

export function removeFriend(fingerprint: string) {
  return requestJson(
    `/api/identity/friends/${encodeURIComponent(fingerprint)}`,
    pushSchema,
    send("DELETE"),
  );
}

export function setLegacyProxyApproval(nodeId: string, allowed: boolean) {
  return requestJson(
    `/api/identity/legacy-peers/${encodeURIComponent(nodeId)}/proxy-approval`,
    identitySchema,
    send("PUT", { allowed }),
  );
}

/** 指纹太长，界面上只显示前 8 位。 */
export function shortFingerprint(value: string | null): string {
  return value === null ? "" : value.replace(/^sha256:/, "").slice(0, 8);
}
