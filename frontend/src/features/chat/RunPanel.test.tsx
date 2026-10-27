import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DelegationPhase } from "./contracts";
import { emptyRunEventState, runEventReducer } from "./eventReducer";
import { RunPanel } from "./RunPanel";
import { makeEvent, makeRun } from "./testFixtures";

const nodeId = `node_${"b".repeat(32)}`;

afterEach(cleanup);

describe("委派进度", () => {
  it.each([
    ["submitted", "已交给"],
    ["investigating", "正在查"],
    ["answered", "已交回"],
    ["failed", "没查成"],
    ["cancelled", "已取消"],
  ] satisfies [DelegationPhase, string][])(
    "显示 %s 的单行进度",
    (phase, label) => {
      const run = makeRun();
      const delegationId = `delegation_${"1".repeat(32)}`;
      let eventState = runEventReducer(emptyRunEventState, {
        type: "activate",
        run,
      });
      eventState = runEventReducer(eventState, {
        type: "event",
        event: makeEvent(1, "delegation", {
          delegation_id: delegationId,
          peer_node_id: nodeId,
          phase: "submitted",
        }),
      });
      eventState = runEventReducer(eventState, {
        type: "event",
        event: makeEvent(2, "delegation", {
          delegation_id: delegationId,
          peer_node_id: nodeId,
          phase,
        }),
      });
      const { rerender } = render(
        <RunPanel
          compact
          activeRun={run}
          effectiveStatus="running"
          eventState={eventState}
          cancelling={false}
          confirmingCancel={false}
          continuationBlocked={false}
          onRequestCancel={vi.fn()}
          onDismissCancel={vi.fn()}
          onConfirmCancel={vi.fn()}
          onRefresh={vi.fn()}
        />,
      );
      expect(screen.getAllByText(`交给 ${nodeId} · ${label}`)).toHaveLength(1);
      expect(screen.queryByText("检查未完成")).not.toBeInTheDocument();
      rerender(
        <RunPanel
          compact
          activeRun={run}
          effectiveStatus="running"
          eventState={eventState}
          peerName={(id) => (id === nodeId ? "测试电脑" : undefined)}
          cancelling={false}
          confirmingCancel={false}
          continuationBlocked={false}
          onRequestCancel={vi.fn()}
          onDismissCancel={vi.fn()}
          onConfirmCancel={vi.fn()}
          onRefresh={vi.fn()}
        />,
      );
      expect(screen.getByText(`交给 测试电脑 · ${label}`)).toBeVisible();
    },
  );
});
