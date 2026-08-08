import { z } from "zod";

import { requestJson, requestNoContent } from "../../api/client";

export const modelConfigurationSchema = z
  .object({
    endpoint: z.string().nullable(),
    model: z.string().nullable(),
    timeout_seconds: z.number().min(0.1).max(600).nullable(),
    api_key_configured: z.boolean(),
    status: z.enum(["unconfigured", "available", "unavailable"]),
    error_code: z.string().nullable(),
    error_message: z.string().nullable(),
  })
  .strict();

export type ModelConfiguration = z.infer<typeof modelConfigurationSchema>;

export interface ModelConfigurationInput {
  endpoint: string;
  model: string;
  timeout_seconds: number;
  api_key?: string;
}

export function getModelConfiguration(): Promise<ModelConfiguration> {
  return requestJson("/api/model-config", modelConfigurationSchema);
}

export function saveModelConfiguration(
  input: ModelConfigurationInput,
): Promise<ModelConfiguration> {
  return requestJson("/api/model-config", modelConfigurationSchema, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function validateModelConfiguration(): Promise<ModelConfiguration> {
  return requestJson("/api/model-config/validate", modelConfigurationSchema, {
    method: "POST",
  });
}

export function deleteModelConfiguration(): Promise<void> {
  return requestNoContent("/api/model-config", { method: "DELETE" });
}
