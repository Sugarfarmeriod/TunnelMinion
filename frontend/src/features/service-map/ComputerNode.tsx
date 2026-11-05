import type { Ref } from "react";

const sprites = {
  desktop: [
    "................",
    ".FFFFFFFFFFFFFF.",
    ".FSSSSSSSSSSSSF.",
    ".FSHHSSSSSSSSSF.",
    ".FSHSSSSSSSSSSF.",
    ".FSSSSSSSSSSSSF.",
    ".FSSSSSSSSSSSSF.",
    ".FSSSSSSSSSSSSF.",
    ".FSSSSSSSSSSSSF.",
    ".FFFFFFFFFFFFFF.",
    ".FFFFFFFFFFFFLF.",
    "......DDDD......",
    "......DDDD......",
    "...DDDDDDDDDD...",
  ],
  mini: [
    "................",
    "................",
    "................",
    "................",
    "................",
    "................",
    "..WWWWWWWWWWWW..",
    ".WBBBBBBBBBBBBW.",
    "WBBBBBBBBBBBBBBW",
    "WBBBBBBBBBBBBBBW",
    "DDDDDDDDDDDDDDDD",
    "DKKKKKKKKKKKKLKD",
    "DDDDDDDDDDDDDDDD",
    ".DDDDDDDDDDDDDD.",
  ],
};
const colors: Record<string, string> = {
  F: "var(--map-fog)",
  S: "var(--map-blue)",
  H: "var(--map-cyan)",
  L: "var(--map-lime)",
  D: "var(--map-steel)",
  B: "var(--map-fog)",
  K: "var(--map-deep)",
  W: "var(--map-white)",
};

export function platformName(platform: string | null): string {
  return (
    { windows: "Windows", macos: "macOS", linux: "Linux" }[platform ?? ""] ??
    "平台待确认"
  );
}

interface ComputerNodeProps {
  name: string;
  /** 本机在别的电脑上显示的名字，写在“这台电脑”下面 */
  alias?: string;
  platform: string | null;
  online: boolean;
  serviceCount: number | null;
  /** 服务清单读取失败；没有它时 serviceCount 为空表示还在读 */
  serviceError?: boolean;
  selected: boolean;
  buttonRef: Ref<HTMLButtonElement>;
  onClick: () => void;
  repairing?: boolean;
  pendingCount?: number;
  downCount?: number;
  status?: string;
}

export function ComputerNode({
  name,
  alias,
  platform,
  online,
  serviceCount,
  serviceError = false,
  selected,
  buttonRef,
  onClick,
  repairing = false,
  pendingCount = 0,
  downCount = 0,
  status,
}: ComputerNodeProps) {
  const kind = platform === "macos" ? "mini" : "desktop";
  const services =
    serviceCount !== null
      ? `${serviceCount} 个服务`
      : serviceError
        ? "暂时读不到服务"
        : "正在查看服务";
  const state = online ? "在线" : "离线";
  const plain = `${state} · ${services}`;
  const summary = repairing
    ? "正在修……"
    : (status ??
      (pendingCount
        ? `! 有 ${pendingCount} 件事要你批准`
        : downCount
          ? `! ${downCount} 个服务挂了`
          : plain));
  // 读屏和画面说同一件事：画面上显示的提醒（挂了、待批准、离线多久）也念出来，不重复在线状态。
  const detail = summary.replace(/^! /, "").replace(`${state}，`, "");
  const label = `${name}，${state}，${services}${summary === plain ? "" : `，${detail}`}`;
  return (
    <button
      ref={buttonRef}
      type="button"
      className={`map-node${selected ? " is-selected" : ""}${online ? "" : " is-offline"}${repairing ? " is-repairing" : ""}`}
      aria-label={label}
      aria-haspopup="dialog"
      aria-expanded={selected}
      aria-controls={selected ? "local-services-dialog" : undefined}
      onClick={onClick}
    >
      <svg
        className="map-computer"
        viewBox="-3 -3 22 20"
        shapeRendering="crispEdges"
        aria-hidden="true"
        data-platform={kind}
      >
        <path
          className="map-selection"
          d="M-1 2V-1h3 M14-1h3v3 M17 12v3h-3 M2 15h-3v-3"
        />
        <g className="map-sprite">
          {sprites[kind].flatMap((row, y) =>
            [...row].map((pixel, x) =>
              pixel === "." ? null : (
                <rect
                  key={`${x}-${y}`}
                  x={x}
                  y={y}
                  width="1"
                  height="1"
                  fill={colors[pixel]}
                  className={pixel === "L" && online ? "map-blink" : undefined}
                />
              ),
            ),
          )}
          {online && kind === "desktop" ? (
            <rect
              className="map-blink"
              x="4"
              y="7"
              width="1"
              height="1"
              fill="var(--map-cyan)"
            />
          ) : null}
        </g>
      </svg>
      <span className="map-node-name">{name}</span>
      {alias ? <span className="map-node-alias">{alias}</span> : null}
      <span
        // 以“!”开头的是要人处理的事（待批准、挂了），用醒目的红色，不和“在线”的绿色混在一起。
        className={`map-node-summary${summary.startsWith("!") ? " is-alert" : ""}`}
        aria-live="polite"
        aria-atomic="true"
      >
        {summary}
      </span>
    </button>
  );
}
