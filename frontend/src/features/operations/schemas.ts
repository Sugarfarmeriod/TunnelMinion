import { z } from "zod";

const timestampSchema = z.string().datetime({ offset: true });

function identifierSchema(prefix: string) {
  return z.string().regex(new RegExp(`^${prefix}_[0-9a-f]{32}$`));
}

const operationIdSchema = identifierSchema("operation");
const threadIdSchema = identifierSchema("thread");
const runIdSchema = identifierSchema("run");
const toolRunIdSchema = identifierSchema("toolrun");
const nodeIdSchema = identifierSchema("node");
const resourceIdSchema = identifierSchema("resource");

export const operationStatusSchema = z.enum([
  "planned",
  "awaiting_authorization",
  "authorized",
  "executing",
  "verifying",
  "succeeded",
  "expiring",
  "expired",
  "rolling_back",
  "rolled_back",
  "cleanup_failed",
  "rejected",
  "cancelled",
  "authorization_expired",
]);

export const operationActionSchema = z.enum([
  "approve",
  "reject",
  "cancel",
  "revoke",
]);

const verificationResultSchema = z.enum([
  "passed",
  "failed",
  "timeout",
  "requester_offline",
]);

const cleanupResultSchema = z.enum([
  "succeeded",
  "failed",
  "ownership_mismatch",
]);

const operationErrorSchema = z
  .object({
    code: z.enum([
      "invalid_plan",
      "version_incompatible",
      "authorization_required",
      "authorization_rejected",
      "authorization_expired",
      "state_conflict",
      "service_changed",
      "execution_failed",
      "verification_failed",
      "cleanup_failed",
      "protocol_not_supported",
    ]),
    message: z.string(),
    retryable: z.boolean(),
    correlation_id: z.string(),
  })
  .strict();

export const operationSummarySchema = z
  .object({
    operation_id: operationIdSchema,
    thread_id: threadIdSchema,
    run_id: runIdSchema,
    tool_run_ids: z.array(toolRunIdSchema),
    request_node_id: nodeIdSchema,
    target_node_id: nodeIdSchema,
    tool_name: z.string(),
    level: z.number().int().min(0).max(4),
    status: operationStatusSchema,
    authorization_kind: z.enum(["one_time", "preauthorization"]).nullable(),
    authorization_basis: z.string().nullable(),
    bind_host: z.string(),
    bind_port: z.number().int().min(1024).max(65535),
    absolute_expires_at: timestampSchema.nullable(),
    resource_ids: z.array(resourceIdSchema),
    verification_results: z.array(verificationResultSchema),
    cleanup_result: cleanupResultSchema.nullable(),
    error: operationErrorSchema.nullable(),
    updated_at: timestampSchema,
  })
  .strict();

export const operationListSchema = z.array(operationSummarySchema);

const ownedResourceSchema = z
  .object({
    resource_id: resourceIdSchema,
    kind: z.string(),
    bind_host: z.string(),
    bind_port: z.number().int().min(1024).max(65535),
    created_at: timestampSchema,
  })
  .strict();

const verificationSummarySchema = z
  .object({
    verifier_node_id: nodeIdSchema,
    result: verificationResultSchema,
    status_code: z.number().int().min(100).max(599).nullable(),
    evidence_summary: z.string(),
    verified_at: timestampSchema,
  })
  .strict();

const cleanupRecordSchema = z
  .object({
    result: cleanupResultSchema,
    reason: z.string(),
    completed_at: timestampSchema,
  })
  .strict();

const operationTransitionSchema = z
  .object({
    from_status: operationStatusSchema.or(z.literal("none")),
    to_status: operationStatusSchema,
    reason: z.string(),
    occurred_at: timestampSchema,
  })
  .strict();

export const operationDetailSchema = z
  .object({
    summary: operationSummarySchema,
    state: operationStatusSchema,
    allowed_actions: z.array(operationActionSchema),
    service_id: z.string(),
    service_endpoint: z.string(),
    service_process_or_container: z.string(),
    service_fingerprint: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    expected_change: z.string(),
    risk_summary: z.string(),
    verification_method: z.string(),
    rollback_method: z.string(),
    duration_seconds: z.number().int().min(1).max(86_400),
    created_at: timestampSchema,
    owned_resources: z.array(ownedResourceSchema),
    verification_summaries: z.array(verificationSummarySchema),
    cleanup_record: cleanupRecordSchema.nullable(),
    manual_action: z.string().nullable(),
    transitions: z.array(operationTransitionSchema),
  })
  .strict()
  .superRefine((detail, context) => {
    if (detail.state !== detail.summary.status) {
      context.addIssue({
        code: "custom",
        message: "详情 state 与 summary.status 不一致",
        path: ["state"],
      });
    }
    if (
      detail.cleanup_record !== null &&
      detail.cleanup_record.result !== "succeeded" &&
      detail.manual_action === null
    ) {
      context.addIssue({
        code: "custom",
        message: "清理失败时必须提供人工处理建议",
        path: ["manual_action"],
      });
    }
  });

export type OperationStatus = z.infer<typeof operationStatusSchema>;
export type OperationAction = z.infer<typeof operationActionSchema>;
export type OperationSummary = z.infer<typeof operationSummarySchema>;
export type OperationDetail = z.infer<typeof operationDetailSchema>;
