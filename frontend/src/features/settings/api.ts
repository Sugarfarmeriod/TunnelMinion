import { z } from "zod";

import { requestJson, requestNoContent } from "../../api/client";

const modelConfigurationProfileSchema = z
  .object({
    endpoint: z.string(),
    model: z.string(),
    timeout_seconds: z.number().min(0.1).max(600),
    disable_thinking: z.boolean().default(false),
    api_key_configured: z.boolean(),
  })
  .strict();

export const modelConfigurationSchema = z
  .object({
    endpoint: z.string().nullable(),
    model: z.string().nullable(),
    timeout_seconds: z.number().min(0.1).max(600).nullable(),
    disable_thinking: z.boolean().default(false),
    api_key_configured: z.boolean(),
    profiles: z.array(modelConfigurationProfileSchema),
    borrowed_from: z
      .string()
      .regex(/^node_[0-9a-f]{32}$/)
      .nullable(),
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
  disable_thinking: boolean;
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
