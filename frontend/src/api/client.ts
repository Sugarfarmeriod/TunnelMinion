import type { ZodType } from "zod";

const unsafeMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function requestJson<T>(
  path: `/api/${string}`,
  schema: ZodType<T>,
  init: RequestInit = {},
): Promise<T> {
  const response = await request(path, init);
  return schema.parse(await response.json());
}

export async function requestNoContent(
  path: `/api/${string}`,
  init: RequestInit = {},
): Promise<void> {
  const response = await request(path, init);
  if (response.status !== 204) {
    throw new ApiError(
      response.status,
      "unexpected_response",
      "服务返回了无法确认的成功结果",
    );
  }
}

async function request(
  path: `/api/${string}`,
  init: RequestInit,
): Promise<Response> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (unsafeMethods.has(method)) {
    headers.set("X-TunnelMinion-Request", "same-origin");
  }

  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers,
  });
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail = getErrorDetail(payload);
    throw new ApiError(response.status, detail.code, detail.message);
  }
  return response;
}

function getErrorDetail(payload: unknown): { code: string; message: string } {
  if (typeof payload !== "object" || payload === null) {
    return { code: "unexpected_response", message: "服务返回了无法识别的错误" };
  }
  const record = payload as Record<string, unknown>;
  const detail =
    typeof record.detail === "object" && record.detail !== null
      ? record.detail
      : record;
  const values = detail as Record<string, unknown>;
  return {
    code: typeof values.code === "string" ? values.code : "request_failed",
    message:
      typeof values.message === "string"
        ? values.message
        : "请求失败，请刷新状态后重试",
  };
}
