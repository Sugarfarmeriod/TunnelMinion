import { z } from "zod";

const timestampSchema = z.string().datetime({ offset: true });
const identifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[0-9a-f]{32}$`));

export const threadIdSchema = identifierSchema("thread");
export const runIdSchema = identifierSchema("run");
export const nodeIdSchema = identifierSchema("node");
export const toolRunIdSchema = identifierSchema("toolrun");

export const runStatusSchema = z.enum([
  "running",
  "completed",
  "cancelled",
  "failed",
  "interrupted",
]);

export const stopReasonSchema = z.enum([
  "completed",
  "model-limit",
  "tool-limit",
  "timeout",
  "cancelled",
]);

export const threadSchema = z
  .object({
    thread_id: threadIdSchema,
    created_at: timestampSchema,
    updated_at: timestampSchema,
    message_count: z.number().int().nonnegative(),
  })
  .strict();

export const threadMessageSchema = z
  .object({
    role: z.enum(["user", "assistant"]),
    content: z.string(),
    created_at: timestampSchema,
    run_id: runIdSchema,
  })
  .strict();

export const threadDetailSchema = z
  .object({
    thread: threadSchema,
    messages: z.array(threadMessageSchema),
  })
  .strict();

const failureSchema = z
  .object({
    category: z.string(),
    phase: z.string(),
    reason: z.string(),
    retryable: z.boolean(),
    occurred_at: timestampSchema,
    source_refs: z.array(z.string()),
  })
  .strict();

const evidenceReferenceSchema = z
  .object({
    tool_run_id: toolRunIdSchema,
    tool_name: z.string(),
    status: z.string(),
  })
  .strict();

const runResultSchema = z
  .object({
    answer: z.string(),
    model_rounds: z.number().int().nonnegative(),
    tool_calls: z.number().int().nonnegative(),
    tool_run_ids: z.array(toolRunIdSchema),
    selected_tools: z.array(z.string()),
    stop_reason: stopReasonSchema,
    elapsed_ms: z.number().nonnegative(),
    usage: z
      .object({
        input_tokens: z.number().int().nonnegative(),
        output_tokens: z.number().int().nonnegative(),
        total_tokens: z.number().int().nonnegative(),
        estimated_cost: z.null(),
      })
      .strict(),
    limits: z
      .object({
        max_model_rounds: z.number().int().positive(),
        max_tool_calls: z.number().int().positive(),
        timeout_seconds: z.number().positive(),
      })
      .strict(),
    evidence_answer: z
      .object({
        summary: z.string(),
        confirmed_facts: z.array(
          z
            .object({
              statement: z.string(),
              evidence_refs: z.array(toolRunIdSchema).min(1),
            })
            .strict(),
        ),
        inferences: z.array(z.string()),
        unknowns: z.array(z.string()),
        evidence: z.array(evidenceReferenceSchema),
        stop_reason: stopReasonSchema,
      })
      .strict(),
    context_records: z.array(z.unknown()),
    failures: z.array(failureSchema),
  })
  .strict();

export const runSchema = z
  .object({
    run_id: runIdSchema,
    thread_id: threadIdSchema,
    status: runStatusSchema,
    created_at: timestampSchema,
    finished_at: timestampSchema.nullable(),
    result: runResultSchema.nullable(),
    error_code: z.string().nullable(),
    error_message: z.string().nullable(),
    failure: failureSchema.nullable(),
  })
  .strict();

export const runEventSchema = z
  .object({
    sequence: z.number().int().positive(),
    event_type: z.enum(["goal", "tool", "finished", "failed", "interrupted"]),
    created_at: timestampSchema,
    run_id: runIdSchema,
    target_node_id: nodeIdSchema.nullable(),
    tool_name: z.string().nullable(),
    tool_status: z.string().nullable(),
    elapsed_ms: z.number().nonnegative().nullable(),
    tool_run_id: toolRunIdSchema.nullable(),
    stop_reason: stopReasonSchema.nullable(),
    message: z.string().nullable(),
  })
  .strict();

export const threadListSchema = z.array(threadSchema);

export type ThreadSummary = z.infer<typeof threadSchema>;
export type ThreadMessage = z.infer<typeof threadMessageSchema>;
export type ThreadDetail = z.infer<typeof threadDetailSchema>;
export type RunStatus = z.infer<typeof runStatusSchema>;
export type RunView = z.infer<typeof runSchema>;
export type RunEvent = z.infer<typeof runEventSchema>;
