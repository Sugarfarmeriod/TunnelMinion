import { ApiError, requestJson } from "../../api/client";

import {
  runSchema,
  threadDetailSchema,
  threadListSchema,
  threadSchema,
} from "./contracts";

export const allowedToolNames = [
  "get_node_summary",
  "get_wireguard_status",
  "list_network_listeners",
  "get_process_summary",
  "list_docker_services",
  "probe_service_reachability",
] as const;

export type AllowedToolName = (typeof allowedToolNames)[number];

export function listThreads(signal?: AbortSignal) {
  return requestJson("/api/threads", threadListSchema, { signal });
}

export function createThread(signal?: AbortSignal) {
  return requestJson("/api/threads", threadSchema, {
    method: "POST",
    signal,
  });
}

export function getThread(threadId: string, signal?: AbortSignal) {
  return requestJson(
    `/api/threads/${encodeURIComponent(threadId)}`,
    threadDetailSchema,
    { signal },
  );
}

export function startRun(
  threadId: string,
  question: string,
  toolName: AllowedToolName,
  signal?: AbortSignal,
) {
  return requestJson(
    `/api/threads/${encodeURIComponent(threadId)}/runs`,
    runSchema,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, tool_names: [toolName] }),
      signal,
    },
  );
}

export function getRun(runId: string, signal?: AbortSignal) {
  return requestJson(`/api/runs/${encodeURIComponent(runId)}`, runSchema, {
    signal,
  });
}

export function cancelRun(runId: string, signal?: AbortSignal) {
  return requestJson(
    `/api/runs/${encodeURIComponent(runId)}/cancel`,
    runSchema,
    {
      method: "POST",
      signal,
    },
  );
}

export async function deleteThread(threadId: string, signal?: AbortSignal) {
  const response = await fetch(`/api/threads/${encodeURIComponent(threadId)}`, {
    method: "DELETE",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "X-TunnelMinion-Request": "same-origin",
    },
    signal,
  });
  if (!response.ok) {
    throw new ApiError(
      response.status,
      "thread_delete_failed",
      "删除线程失败，请重新读取线程列表后再决定是否重试",
    );
  }
}
