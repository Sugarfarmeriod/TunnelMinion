import { describe, expect, it } from "vitest";

import {
  runEventSchema,
  runSchema,
  threadSchema,
  toolRunIdSchema,
} from "./contracts";

const timestamp = "2026-08-08T10:00:00+08:00";
const threadId = "thread_f8ba7a45920b4f2b8f16309c993680b1";
const runId = "run_1220d96035cc487ab102491376c665e7";
const nodeId = "node_a93279a30fbd4597b9e2b755cd36629c";
const toolRunId = "toolrun_00000000000000000000000000000003";

describe("聊天标识符契约", () => {
  it("接受 Python identifiers.py 定义的前缀加 32 位小写十六进制格式", () => {
    expect(
      threadSchema.safeParse({
        thread_id: threadId,
        created_at: timestamp,
        updated_at: timestamp,
        message_count: 0,
      }).success,
    ).toBe(true);
    expect(toolRunIdSchema.safeParse(toolRunId).success).toBe(true);
    expect(
      runEventSchema.safeParse({
        sequence: 1,
        event_type: "tool",
        created_at: timestamp,
        run_id: runId,
        target_node_id: nodeId,
        tool_name: "get_node_summary",
        tool_status: "success",
        elapsed_ms: 12,
        tool_run_id: toolRunId,
        stop_reason: null,
        message: null,
      }).success,
    ).toBe(true);
  });

  it.each([
    "f8ba7a45-920b-4f2b-8f16-309c993680b1",
    "thread_F8BA7A45920B4F2B8F16309C993680B1",
    "run_f8ba7a45920b4f2b8f16309c993680b1",
    "thread_f8ba7a45920b4f2b8f16309c993680b",
  ])("拒绝错误 ThreadId：%s", (invalidId) => {
    expect(
      threadSchema.safeParse({
        thread_id: invalidId,
        created_at: timestamp,
        updated_at: timestamp,
        message_count: 0,
      }).success,
    ).toBe(false);
  });

  it("分别拒绝错误 RunId、NodeId 与 ToolRunId", () => {
    expect(
      runSchema.safeParse({
        run_id: `thread_${"1".repeat(32)}`,
        thread_id: threadId,
        status: "running",
        created_at: timestamp,
        finished_at: null,
        result: null,
        error_code: null,
        error_message: null,
        failure: null,
      }).success,
    ).toBe(false);
    expect(
      runEventSchema.safeParse({
        sequence: 1,
        event_type: "tool",
        created_at: timestamp,
        run_id: runId,
        target_node_id: `service_${"2".repeat(32)}`,
        tool_name: "get_node_summary",
        tool_status: "success",
        elapsed_ms: 12,
        tool_run_id: `run_${"3".repeat(32)}`,
        stop_reason: null,
        message: null,
      }).success,
    ).toBe(false);
  });
});
