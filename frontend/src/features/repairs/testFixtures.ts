import type { RepairDetail, RemoteRepair } from "./api";

export function makeRemoteRepair(
  overrides: Partial<RemoteRepair> = {},
): RemoteRepair {
  return {
    repair_id: "operation_" + "b".repeat(32),
    service_name: "远端相册",
    action: "重启远端相册",
    status: "awaiting_authorization",
    how_to_approve: "tunnelminion repair-approve operation_" + "b".repeat(32),
    expires_at: new Date(Date.now() + 9 * 60_000).toISOString(),
    ...overrides,
  };
}

export function makeRepair(
  overrides: Partial<RepairDetail> = {},
): RepairDetail {
  return {
    repair_id: "operation_" + "a".repeat(32),
    node_id: "node_0123456789abcdef0123456789abcdef",
    service_key: "docker:photos",
    service_name: "相册",
    kind: "restart_containers",
    status: "awaiting_authorization",
    action_summary: "重启相册容器",
    reason: "容器已退出，服务打不开",
    created_at: new Date(Date.now() - 60_000).toISOString(),
    approval_expires_at: new Date(Date.now() + 9 * 60_000).toISOString(),
    verification_passed: null,
    error: null,
    origin: {
      kind: "conversation",
      thread_id: "thread_" + "a".repeat(32),
      run_id: "run_" + "a".repeat(32),
      delegation_id: null,
      evidence: ["容器已停止"],
    },
    impact_summary: "重启期间相册暂时打不开",
    verification_summary: "重新检查容器、端口和相册首页",
    failure_summary: "停下来说明原因，不会反复重启",
    advanced: { commands: ["docker start fake-photos"] },
    verification: null,
    cleanup: null,
    ...overrides,
  };
}

export function finishedRepair(
  status: "succeeded" | "rolled_back" = "succeeded",
): RepairDetail {
  const passed = status === "succeeded";
  return makeRepair({
    status,
    approval_expires_at: null,
    verification_passed: passed,
    verification: {
      passed,
      checks: [
        {
          name: "web_page",
          passed,
          detail: passed ? "相册首页能打开" : "相册首页还是打不开",
        },
      ],
      log_excerpt: passed ? null : "startup failed",
    },
    error: passed
      ? null
      : {
          code: "verification_failed",
          message: "容器重启了，但服务还是没起来。",
          next_step: "看看日志要点，不会自动重试。",
        },
  });
}
