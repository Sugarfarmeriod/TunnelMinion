import { z } from "zod";

import { requestJson, requestNoContent } from "../../api/client";

const timestamp = z.string().datetime({ offset: true });
export const nodeIdSchema = z.string().regex(/^node_[0-9a-f]{32}$/);
export const memoryIdSchema = z.string().regex(/^memory_[0-9a-f]{32}$/);

export const memoryScopeSchema = z
  .object({
    user: z.string().min(1).max(128),
    network: z.string().min(1).max(128),
    node_id: nodeIdSchema,
    task_type: z.literal("local-conversation"),
    security_scope: z.literal("read-only-agent"),
  })
  .strict();

export const longTermMemorySchema = z
  .object({
    memory_id: memoryIdSchema,
    namespace: memoryScopeSchema,
    kind: z.enum([
      "node-alias",
      "preference",
      "security-constraint",
      "stable-service-fact",
    ]),
    content: z.string().min(1).max(20_000),
    source: z.string().min(1).max(2_000),
    user_confirmed: z.literal(true),
    updated_at: timestamp,
    valid_until: timestamp.nullable(),
    revision_of: memoryIdSchema.nullable(),
    superseded_by: memoryIdSchema.nullable(),
    deleted_at: timestamp.nullable(),
  })
  .strict();

export const longTermMemoryListSchema = z.array(longTermMemorySchema);

export type LongTermMemory = z.infer<typeof longTermMemorySchema>;

export interface MemoryScope {
  user: string;
  network: string;
  nodeId: string;
}

export interface ReviseMemoryInput {
  content: string;
  source: string;
}

function memoryListPath(scope: MemoryScope): `/api/${string}` {
  const query = new URLSearchParams({
    user: scope.user,
    network: scope.network,
    node_id: scope.nodeId,
  });
  return `/api/memories?${query.toString()}`;
}

export function getMemories(scope: MemoryScope): Promise<LongTermMemory[]> {
  nodeIdSchema.parse(scope.nodeId);
  const scopedListSchema = longTermMemoryListSchema.superRefine(
    (memories, context) => {
      memories.forEach((memory, index) => {
        if (
          memory.namespace.user !== scope.user ||
          memory.namespace.network !== scope.network ||
          memory.namespace.node_id !== scope.nodeId
        ) {
          context.addIssue({
            code: "custom",
            message: "服务返回了请求作用域之外的长期记忆",
            path: [index, "namespace"],
          });
        }
      });
    },
  );
  return requestJson(memoryListPath(scope), scopedListSchema);
}

export function reviseMemory(
  memoryId: string,
  input: ReviseMemoryInput,
): Promise<LongTermMemory> {
  return requestJson(
    `/api/memories/${encodeURIComponent(memoryId)}`,
    longTermMemorySchema,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    },
  );
}

export function deleteMemory(memoryId: string): Promise<void> {
  memoryIdSchema.parse(memoryId);
  return requestNoContent(`/api/memories/${encodeURIComponent(memoryId)}`, {
    method: "DELETE",
  });
}

export function clearMemoryScope(scope: MemoryScope): Promise<void> {
  nodeIdSchema.parse(scope.nodeId);
  const query = new URLSearchParams({
    user: scope.user,
    network: scope.network,
    node_id: scope.nodeId,
  });
  return requestNoContent(`/api/memories/scope?${query.toString()}`, {
    method: "DELETE",
  });
}
