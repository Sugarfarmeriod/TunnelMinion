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
  platform: string | null;
  online: boolean;
  serviceCount: number | null;
  selected: boolean;
  buttonRef: Ref<HTMLButtonElement>;
  onClick: () => void;
}

export function ComputerNode({
  name,
  platform,
  online,
  serviceCount,
  selected,
  buttonRef,
  onClick,
}: ComputerNodeProps) {
  const kind = platform === "macos" ? "mini" : "desktop";
  return (
    <button
      ref={buttonRef}
      type="button"
      className={`map-node${selected ? " is-selected" : ""}${online ? "" : " is-offline"}`}
      aria-label={`${name}，${online ? "在线" : "离线"}，${serviceCount === null ? "正在查看服务" : `${serviceCount} 个服务`}`}
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
      <span className="map-node-summary">
        {online ? "在线" : "离线"}
        {serviceCount === null
          ? " · 正在查看服务"
          : ` · ${serviceCount} 个服务`}
      </span>
    </button>
  );
}
