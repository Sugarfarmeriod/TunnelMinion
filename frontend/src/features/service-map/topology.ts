/** 画布上的一个点：x 是画布宽度的百分比，y 是像素。 */
export interface MapPoint {
  x: number;
  y: number;
}

export interface Box {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

interface Pixel {
  x: number;
  y: number;
}

export interface MapLayout {
  height: number;
  list: boolean;
  /** 电脑多、窗口矮时图标画小一点，保证一屏看全 */
  compact: boolean;
  /** 对端电脑节点半高（像素），用来把气泡放在电脑头上 */
  peerHalf: number;
  local: MapPoint;
  peers: MapPoint[];
  /** 每条连线的组网标签中心；贴在线旁边，不压线、不压电脑 */
  labels: MapPoint[];
}

export interface MapViewport {
  narrow: boolean;
  /** 画布内宽（像素） */
  width: number;
  /** 不滚动整页时画布最多能有多高（像素） */
  available: number;
}

// 节点在布局里占的大小（像素），按样式表里电脑图标、名字和状态行估算，本机多一行别名。
// 感叹号浮在电脑头上，所有电脑都给它留出位置。
const NODE_WIDTH = 160;
const BANG = 46;
const GAP = 12;
export const nodeHeights = {
  full: { local: 218, peer: 200 },
  compact: { local: 134, peer: 116 },
} as const;
// 组网标签按最长的“WireGuard”估算，留一点余量。
const LABEL_HALF = { x: 38, y: 10 };
const MIN_HEIGHT = 420;
const MAX_HEIGHT = 800;

// 对端从右上方起排：两台斜对，三四台占四个角，五六台围成六边形，七八台再补正上方和正下方。
// 不从正上方起排，免得正好压在本机头上的感叹号上。
function slotAngles(count: number): number[] {
  const slots =
    count <= 2
      ? [-60, 120]
      : count <= 4
        ? [-60, 30, 120, 210]
        : count <= 6
          ? [-60, 0, 60, 120, 180, 240]
          : [-60, 0, 60, 120, 180, 240, -90, 90];
  return slots.slice(0, count).map((degree) => (degree * Math.PI) / 180);
}

export function boxesOverlap(a: Box, b: Box) {
  return (
    a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom
  );
}

/** 线段是否穿过矩形（Liang-Barsky 裁剪）。 */
export function segmentHitsBox(a: Pixel, b: Pixel, box: Box) {
  let start = 0;
  let end = 1;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  for (const [p, q] of [
    [-dx, a.x - box.left],
    [dx, box.right - a.x],
    [-dy, a.y - box.top],
    [dy, box.bottom - a.y],
  ] as const) {
    if (p === 0) {
      if (q <= 0) return false;
      continue;
    }
    const t = q / p;
    if (p < 0) start = Math.max(start, t);
    else end = Math.min(end, t);
    if (start >= end) return false;
  }
  return true;
}

function nodeBox(point: Pixel, height: number, bang: boolean): Box {
  return {
    left: point.x - NODE_WIDTH / 2,
    top: point.y - height / 2 - (bang ? BANG : 0),
    right: point.x + NODE_WIDTH / 2,
    bottom: point.y + height / 2,
  };
}

/** 连线露在两台电脑之间的那一段；电脑盖住了线的两头。 */
function visibleSegment(
  from: Pixel,
  fromHeight: number,
  to: Pixel,
  toHeight: number,
): [Pixel, Pixel] | null {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const exit = (height: number) =>
    Math.min(
      dx ? NODE_WIDTH / 2 / Math.abs(dx) : Infinity,
      dy ? height / 2 / Math.abs(dy) : Infinity,
    );
  const head = exit(fromHeight);
  const tail = 1 - exit(toHeight);
  if (head >= tail) return null;
  return [
    { x: from.x + dx * head, y: from.y + dy * head },
    { x: from.x + dx * tail, y: from.y + dy * tail },
  ];
}

/** 在线段旁边找一处放标签：先试中点，再往两头挪，线的两侧都试。 */
function labelCandidates([a, b]: [Pixel, Pixel]): Box[] {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const length = Math.hypot(dx, dy);
  const nx = -dy / length;
  const ny = dx / length;
  // 标签中心离线的距离刚好让整个标签让开这条线。
  const offset = LABEL_HALF.x * Math.abs(nx) + LABEL_HALF.y * Math.abs(ny) + 4;
  return [0.5, 0.35, 0.65, 0.2, 0.8].flatMap((t) =>
    [1, -1].map((side) => {
      const x = a.x + dx * t + side * nx * offset;
      const y = a.y + dy * t + side * ny * offset;
      return {
        left: x - LABEL_HALF.x,
        top: y - LABEL_HALF.y,
        right: x + LABEL_HALF.x,
        bottom: y + LABEL_HALF.y,
      };
    }),
  );
}

function ringLayout(
  count: number,
  width: number,
  height: number,
  compact: boolean,
): { layout: MapLayout; fits: boolean } {
  const sizes = nodeHeights[compact ? "compact" : "full"];
  const top = sizes.peer / 2 + BANG + 4;
  const bottom = sizes.peer / 2 + 4;
  const center = { x: width / 2, y: (top + height - bottom) / 2 };
  const radius = {
    x: width / 2 - NODE_WIDTH / 2 - 8,
    y: (height - top - bottom) / 2,
  };
  const peers = slotAngles(count).map((angle) => ({
    x: center.x + radius.x * Math.cos(angle),
    y: center.y + radius.y * Math.sin(angle),
  }));
  const inside = (box: Box) =>
    box.left >= 0 && box.top >= 0 && box.right <= width && box.bottom <= height;
  const boxes = [
    nodeBox(center, sizes.local, true),
    ...peers.map((point) => nodeBox(point, sizes.peer, true)),
  ];
  let fits = boxes.every(inside);
  boxes.forEach((box, index) => {
    const padded = {
      left: box.left - GAP,
      top: box.top - GAP,
      right: box.right + GAP,
      bottom: box.bottom + GAP,
    };
    if (boxes.slice(index + 1).some((other) => boxesOverlap(padded, other)))
      fits = false;
  });
  const segments = peers.map((point) =>
    visibleSegment(center, sizes.local, point, sizes.peer),
  );
  const visible = segments.filter(
    (segment): segment is [Pixel, Pixel] => segment !== null,
  );
  if (visible.length < segments.length) fits = false;
  // 每条线只连两台电脑，不能从别的电脑底下穿过去。
  segments.forEach((segment, index) => {
    if (
      segment &&
      peers.some(
        (point, other) =>
          other !== index &&
          segmentHitsBox(...segment, nodeBox(point, sizes.peer, false)),
      )
    )
      fits = false;
  });
  const placed: Box[] = [];
  const labels = segments.map((segment, index) => {
    if (!segment) return peers[index]!;
    const spot = labelCandidates(segment).find(
      (box) =>
        inside(box) &&
        !boxes.some((node) => boxesOverlap(box, node)) &&
        !placed.some((label) => boxesOverlap(box, label)) &&
        !visible.some((line) => segmentHitsBox(...line, box)),
    );
    if (!spot) {
      fits = false;
      return {
        x: (segment[0].x + segment[1].x) / 2,
        y: (segment[0].y + segment[1].y) / 2,
      };
    }
    placed.push(spot);
    return { x: (spot.left + spot.right) / 2, y: (spot.top + spot.bottom) / 2 };
  });
  const percent = (point: Pixel) => ({
    x: (point.x / width) * 100,
    y: point.y,
  });
  return {
    fits,
    layout: {
      height,
      list: false,
      compact,
      peerHalf: sizes.peer / 2,
      local: percent(center),
      peers: peers.map(percent),
      labels: labels.map(percent),
    },
  };
}

/**
 * 地图布局。宽屏围成一圈，画布高度跟着窗口走，不让电脑落到第一屏下面；
 * 放不下时先把图标画小，再不行才加高画布（这时需要滚动）。窄屏或超过 8 台时排成竖列。
 */
export function mapLayout(count: number, viewport: MapViewport): MapLayout {
  if (viewport.narrow || count > 8) {
    const height = count === 0 ? MIN_HEIGHT : (count + 1) * 240 + 40;
    const peers = Array.from({ length: count }, (_, index) => ({
      x: 55,
      y: 400 + index * 240,
    }));
    return {
      height,
      list: true,
      compact: false,
      peerHalf: nodeHeights.full.peer / 2,
      // 列表布局里本机排在最上面，头上还要留出感叹号的位置，不能顶出地图上沿。
      local: { x: 50, y: count > 0 ? 160 : height / 2 },
      peers,
      // 横向支线太短放不下字，标签竖着贴在通往这台电脑的那段主干上。
      labels: peers.map((point) => ({ x: 10, y: point.y - 64 })),
    };
  }
  if (count === 0) {
    return {
      height: MIN_HEIGHT,
      list: false,
      compact: false,
      peerHalf: nodeHeights.full.peer / 2,
      local: { x: 50, y: MIN_HEIGHT / 2 },
      peers: [],
      labels: [],
    };
  }
  const target = Math.round(
    Math.min(MAX_HEIGHT, Math.max(MIN_HEIGHT, viewport.available)),
  );
  let last = ringLayout(count, viewport.width, target, false);
  if (last.fits) return last.layout;
  for (let height = target; height <= 1600; height += 20) {
    last = ringLayout(count, viewport.width, height, true);
    if (last.fits) return last.layout;
  }
  return last.layout;
}

export function relativeTime(value: string | null) {
  if (value === null) return "时间未知";
  const minutes = Math.max(
    0,
    Math.floor((Date.now() - Date.parse(value)) / 60_000),
  );
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)} 小时前`;
  return `${Math.floor(minutes / 1440)} 天前`;
}

// 连线上标出本机去对端走的组网；后端认不出具体类型时是“其他网卡”。
export const networkLabels = {
  wireguard: "WireGuard",
  n2n: "n2n",
  other: "其他网卡",
} as const;
