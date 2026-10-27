import { useState, type CSSProperties } from "react";

import type { DelegationProgress } from "../chat/eventReducer";

export const delegationStatus = {
  submitted: "已交给",
  investigating: "正在查……",
  answered: "已交回",
  failed: "没查成",
  cancelled: "已取消",
};

export function DelegationActivity({
  delegations,
  local,
  peer,
  list,
}: {
  delegations: DelegationProgress[];
  local: { x: number; y: number };
  peer: { x: number; y: number };
  list: boolean;
}) {
  const [finished, setFinished] = useState<string[]>([]);
  const reducedMotion =
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  if (list) return null;
  const thinking = delegations.some(
    (item) =>
      item.phase === "investigating" ||
      (item.phase === "answered" &&
        !reducedMotion &&
        !finished.includes(`${item.delegation_id}:answered`)),
  );
  return (
    <>
      {delegations.map((item) => {
        const key = `${item.delegation_id}:${item.phase}`;
        if (
          !["submitted", "answered"].includes(item.phase) ||
          finished.includes(key)
        )
          return null;
        const returning = item.phase === "answered";
        const start = returning ? peer : local;
        const end = returning ? local : peer;
        return (
          <span
            key={key}
            aria-hidden="true"
            data-peer={item.peer_node_id}
            data-phase={item.phase}
            className={`map-packet${returning ? " is-returning" : ""}`}
            style={
              {
                "--packet-start-x": `${start.x}%`,
                "--packet-start-y": `${start.y}px`,
                "--packet-end-x": `${end.x}%`,
                "--packet-end-y": `${end.y}px`,
                left: `${(local.x + peer.x) / 2}%`,
                top: (local.y + peer.y) / 2,
                animation: reducedMotion ? "none" : undefined,
              } as CSSProperties
            }
            onAnimationEnd={() => setFinished((items) => [...items, key])}
          />
        );
      })}
      {thinking ? (
        <svg
          className="map-thought"
          aria-hidden="true"
          viewBox="0 0 56 32"
          shapeRendering="crispEdges"
          style={{ left: `${peer.x}%`, top: peer.y - 148 }}
        >
          <path
            d="M4 0H52V4H56V20H52V24H16V30H10V24H4V20H0V4H4Z"
            fill="var(--map-white)"
          />
          <path
            d="M12 8H18V14H12ZM25 8H31V14H25ZM38 8H44V14H38Z"
            fill="var(--map-ink)"
          />
        </svg>
      ) : null}
    </>
  );
}
