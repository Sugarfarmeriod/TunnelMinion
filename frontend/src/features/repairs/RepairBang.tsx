export function RepairBang({
  name,
  count,
  onClick,
}: {
  name: string;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="map-repair-bang"
      aria-label={`${name}有 ${count} 个待批准的修复`}
      onClick={onClick}
    >
      <svg viewBox="0 0 20 22" shapeRendering="crispEdges" aria-hidden="true">
        <path d="M2 0H18V2H20V17H12L8 22V17H0V2H2Z" fill="currentColor" />
        <path d="M8 4H12V10H8ZM8 12H12V15H8Z" fill="var(--map-ink)" />
      </svg>
    </button>
  );
}
