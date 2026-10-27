import { useEffect, useRef, useState } from "react";

import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { type RemoteRepair, isRepairTerminal } from "./api";
import "./repairs.css";

export function RemoteRepairDialog({
  repair,
  name,
  onClose,
}: {
  repair: RemoteRepair;
  name: string;
  onClose: () => void;
}) {
  const [now, setNow] = useState(Date.now);
  const closeRef = useRef<HTMLButtonElement>(null);
  const opener = useRef(
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null,
  );
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    initialFocusRef: closeRef,
    returnFocus: [
      opener.current,
      document.querySelector<HTMLButtonElement>(".map-node"),
    ],
    onEscape: onClose,
  });
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const seconds = Math.max(
    0,
    Math.ceil((Date.parse(repair.expires_at) - now) / 1_000),
  );
  const expired = seconds === 0 || isRepairTerminal(repair.status);
  return (
    <div className="repair-mask">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="repair-title"
        tabIndex={-1}
        className="repair-dialog"
        onKeyDown={handleKeyDown}
      >
        <header>
          <h2 id="repair-title">要修好“{repair.service_name}”吗？</h2>
          <button
            ref={closeRef}
            type="button"
            className="map-close"
            aria-label="关闭修复"
            onClick={onClose}
          >
            ×
          </button>
        </header>
        <div
          className="repair-body map-scroll"
          tabIndex={0}
          aria-label="修复详情"
        >
          <dl>
            <div>
              <dt>要做什么</dt>
              <dd>{repair.action}</dd>
            </div>
          </dl>
          <p>请到 {name} 的地图上批准</p>
          <p className="repair-expiry" role="status">
            10 分钟内有效 ·{" "}
            {expired
              ? "已过期"
              : `还剩 ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`}
          </p>
          <details>
            <summary>高级</summary>
            <pre>{repair.how_to_approve}</pre>
          </details>
        </div>
        <footer>
          <button type="button" className="map-button" onClick={onClose}>
            知道了
          </button>
        </footer>
      </div>
    </div>
  );
}
