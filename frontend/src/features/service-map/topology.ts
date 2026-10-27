export function mapLayout(count: number, narrow: boolean) {
  const list = narrow || count > 8;
  const height =
    count === 0 ? 420 : list ? (count + 1) * 240 : count > 3 ? 900 : 800;
  const local = { x: 50, y: list && count > 0 ? 120 : height / 2 };
  const peers = Array.from({ length: count }, (_, index) => {
    // 从正上方偏 30 度起排，避免对端正好压在本机头上的感叹号上。
    const angle = -Math.PI / 3 + (index * Math.PI * 2) / count;
    return list
      ? { x: 55, y: 360 + index * 240 }
      : {
          x: 50 + 36 * Math.cos(angle),
          y: height / 2 + (height / 2 - 168) * Math.sin(angle),
        };
  });
  return { height, local, peers, list };
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
