import { z } from "zod";

import { requestJson } from "../../api/client";

const dateTime = z.string().datetime({ offset: true });

export const updateViewSchema = z
  .object({
    supported: z.boolean(),
    unsupported_reason: z
      .enum([
        "read_only_preview",
        "source_run",
        "no_runtime_profile",
        "unsupported_platform",
      ])
      .nullable(),
    current: z
      .object({
        package_id: z.string().nullable(),
        source_revision: z.string().nullable(),
        release_tag: z.string().nullable(),
      })
      .strict(),
    latest: z
      .object({
        tag: z.string(),
        source_revision: z.string(),
        published_at: dateTime.nullable(),
        size: z.number().int().positive(),
      })
      .strict()
      .nullable(),
    availability: z
      .enum([
        "update_available",
        "up_to_date",
        "unreleased_build",
        "diverged",
        "unknown",
      ])
      .nullable(),
    checked_at: dateTime.nullable(),
    check_error: z.string().nullable(),
    job: z
      .object({
        phase: z.enum([
          "idle",
          "downloading",
          "installing",
          "restarting",
          "failed",
        ]),
        release_tag: z.string().nullable(),
        downloaded_bytes: z.number().int().nonnegative(),
        total_bytes: z.number().int().nonnegative(),
        error_code: z.string().nullable(),
      })
      .strict(),
    last_result: z
      .object({
        outcome: z.enum(["updated", "rolled_back", "failed"]),
        from_package_id: z.string(),
        to_package_id: z.string(),
        release_tag: z.string().nullable(),
        error_code: z.string().nullable(),
        finished_at: dateTime,
      })
      .strict()
      .nullable(),
  })
  .strict();

export type UpdateView = z.infer<typeof updateViewSchema>;

export const updateQueryKey = ["update"] as const;

export function getUpdate(): Promise<UpdateView> {
  return requestJson("/api/update", updateViewSchema);
}

export function checkUpdate(): Promise<UpdateView> {
  return requestJson("/api/update/check", updateViewSchema, {
    method: "POST",
  });
}

export function applyUpdate(releaseTag: string): Promise<UpdateView> {
  return requestJson("/api/update/apply", updateViewSchema, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ release_tag: releaseTag }),
  });
}
