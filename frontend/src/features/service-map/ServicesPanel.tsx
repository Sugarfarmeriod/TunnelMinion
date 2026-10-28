import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { CSSProperties, RefObject } from "react";

import type { Peer, ServiceEntry } from "./api";
import { platformName } from "./ComputerNode";
import { serviceUrl } from "./serviceUrl";
import type { Repair } from "../repairs/api";
import { relativeTime } from "./topology";

const kindNames = { docker: "Docker", python: "Python", program: "程序" };
const tierNames = { show: "直接显示", review: "可能是服务", hidden: "已隐藏" };

interface ServicesPanelProps {
  panelRef: RefObject<HTMLDivElement | null>;
  stageRef: RefObject<HTMLDivElement | null>;
  nodeRef: RefObject<HTMLButtonElement | null>;
  platform: string | null;
  services: ServiceEntry[];
  loading: boolean;
  loadError: boolean;
  onRetry: () => void;
  onClose: () => void;
  onMark: (key: string, mark: "mine" | "hidden" | null) => void;
  busy: boolean;
  markError: boolean;
  onAsk: (service?: ServiceEntry) => void;
  askDisabled: boolean;
  pendingRepairs?: Pick<Repair, "repair_id" | "action_summary">[];
  onRepair?: (id: string) => void;
  peer?: Peer;
  remoteHost?: string | null;
  reportedAt?: string | null;
}

export function ServicesPanel({
  panelRef,
  stageRef,
  nodeRef,
  platform,
  services,
  loading,
  loadError,
  onRetry,
  onClose,
  onMark,
  busy,
  markError,
  onAsk,
  askDisabled,
  pendingRepairs = [],
  onRepair,
  peer,
  remoteHost,
  reportedAt = null,
}: ServicesPanelProps) {
  const name = peer?.display_name ?? "这台电脑";
  const message = peer?.auth_rejected
    ? "对方不认这台电脑，请检查两边是否还在同一份名单里。"
    : peer?.reachable === false
      ? `离线，上次在线 ${relativeTime(peer.last_seen_at)}`
      : peer?.reachable === null
        ? "尚未确认能否连上这台电脑。"
        : peer?.source === "coordinator"
          ? `只能看到数量：${peer.service_count} 个服务。`
          : peer?.services_visible === false
            ? "这台电脑不分享服务清单。"
            : null;
  const [query, setQuery] = useState("");
  const [hiddenOpen, setHiddenOpen] = useState(false);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(6);
  const [narrow, setNarrow] = useState(() => window.innerWidth <= 760);
  const [position, setPosition] = useState<CSSProperties>({});
  const [side, setSide] = useState("right");
  const [below, setBelow] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const compact = services.length > 8;
  const hiddenCount = services.filter(
    (service) => service.tier === "hidden",
  ).length;
  const search = query.trim().toLowerCase();
  const stateOrder = (service: ServiceEntry) =>
    service.state === "stopped"
      ? 1
      : service.endpoints.some((endpoint) => endpoint.has_web_page === false)
        ? 0
        : 2;
  const filtered = services
    .filter(
      (service) =>
        (service.tier !== "hidden" || hiddenOpen) &&
        (!search ||
          [
            service.name,
            service.kind,
            kindNames[service.kind],
            ...service.endpoints.map((endpoint) => endpoint.port),
          ]
            .join(" ")
            .toLowerCase()
            .includes(search)),
    )
    .sort(
      (a, b) =>
        Number(a.tier === "hidden") - Number(b.tier === "hidden") ||
        stateOrder(a) - stateOrder(b),
    );
  const pages = compact
    ? Math.max(1, Math.ceil(filtered.length / pageSize))
    : 1;
  const currentPage = Math.min(page, pages - 1);
  const shown = compact
    ? filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize)
    : filtered;

  useEffect(() => {
    closeRef.current?.focus();
  }, []);

  useLayoutEffect(() => {
    function placePanel() {
      const stage = stageRef.current?.getBoundingClientRect();
      const node = nodeRef.current?.getBoundingClientRect();
      const panel = panelRef.current;
      if (!stage || !node || !panel) return;
      const isNarrow = window.innerWidth <= 760;
      setNarrow(isNarrow);
      const maxHeight = Math.max(
        180,
        Math.min(stage.height - 24, window.innerHeight - stage.top - 24),
      );
      setPageSize(
        Math.max(
          3,
          Math.min(
            6,
            Math.floor(
              (isNarrow ? window.innerHeight - 240 : maxHeight - 210) / 48,
            ),
          ),
        ),
      );
      if (isNarrow) {
        setPosition({});
        return;
      }
      const width = Math.min(380, stage.width - 24);
      const right = node.right - stage.left + 16;
      const fitsRight = right + width <= stage.width - 12;
      const left = Math.max(
        12,
        fitsRight ? right : node.left - stage.left - width - 16,
      );
      const height = Math.min(panel.scrollHeight, maxHeight);
      const top = Math.max(
        12,
        Math.min(
          node.top - stage.top - 32,
          stage.height - height - 12,
          window.innerHeight - stage.top - height - 16,
        ),
      );
      setSide(fitsRight ? "right" : "left");
      setPosition({
        left,
        top,
        width,
        maxHeight,
        "--map-tail-top": `${Math.max(20, Math.min(node.top - stage.top + 54 - top, height - 24))}px`,
      } as CSSProperties);
    }
    placePanel();
    window.addEventListener("resize", placePanel);
    const observer = new ResizeObserver(placePanel);
    if (stageRef.current) observer.observe(stageRef.current);
    return () => {
      window.removeEventListener("resize", placePanel);
      observer.disconnect();
    };
  }, [
    panelRef,
    stageRef,
    nodeRef,
    compact,
    hiddenOpen,
    services,
    query,
    currentPage,
    markError,
    loading,
    loadError,
  ]);

  useLayoutEffect(() => {
    const scroll = scrollRef.current;
    if (!scroll) return;
    scroll.scrollTop = 0;
  }, [currentPage, query, hiddenOpen]);

  useLayoutEffect(() => {
    const scroll = scrollRef.current;
    if (!scroll) return;
    function updateHint() {
      if (scroll)
        setBelow(
          scroll.scrollHeight - scroll.scrollTop > scroll.clientHeight + 2,
        );
    }
    updateHint();
    scroll.addEventListener("scroll", updateHint);
    const observer = new ResizeObserver(updateHint);
    observer.observe(scroll);
    return () => {
      scroll.removeEventListener("scroll", updateHint);
      observer.disconnect();
    };
  }, [shown.length, currentPage, query, hiddenOpen, position]);

  function turnPage(delta: number) {
    setPage(Math.max(0, Math.min(currentPage + delta, pages - 1)));
  }

  return (
    <div
      id="local-services-dialog"
      ref={panelRef}
      role="dialog"
      aria-labelledby="local-services-title"
      tabIndex={-1}
      className={`map-panel ${compact ? "is-compact" : ""} ${narrow ? "is-inline" : `is-floating tail-${side}`}`}
      style={position}
      onKeyDown={(event) => {
        if (
          event.target instanceof HTMLInputElement ||
          event.altKey ||
          event.ctrlKey ||
          event.metaKey
        )
          return;
        if (compact && ["ArrowLeft", "ArrowRight"].includes(event.key)) {
          event.preventDefault();
          turnPage(event.key === "ArrowRight" ? 1 : -1);
        }
      }}
    >
      <header className="map-panel-head">
        <div>
          <h3 id="local-services-title">{name}上的服务</h3>
          <p>{platformName(platform)}</p>
        </div>
        <button
          ref={closeRef}
          type="button"
          className="map-close"
          aria-label="关闭服务框"
          onClick={onClose}
        >
          ×
        </button>
      </header>
      {compact ? (
        <div className="map-tools">
          <input
            type="search"
            aria-label="搜索服务"
            placeholder="按名字、类型、端口搜索"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(0);
            }}
          />
          <nav className="map-pager" aria-label="服务分页">
            <button
              type="button"
              className="map-button"
              aria-label="上一页"
              disabled={currentPage === 0}
              onClick={() => turnPage(-1)}
            >
              ◀
            </button>
            <span aria-live="polite">
              第 {currentPage + 1} / {pages} 页
            </span>
            <button
              type="button"
              className="map-button"
              aria-label="下一页"
              disabled={currentPage === pages - 1}
              onClick={() => turnPage(1)}
            >
              ▶
            </button>
          </nav>
        </div>
      ) : null}
      {pendingRepairs.length ? (
        <div className="map-repair-box">
          <strong>需要处理的事</strong>
          {pendingRepairs.map((repair) => (
            <div key={repair.repair_id}>
              <p title={repair.action_summary}>{repair.action_summary}</p>
              <button
                type="button"
                className="map-button"
                onClick={() => onRepair?.(repair.repair_id)}
              >
                看看怎么修
              </button>
            </div>
          ))}
        </div>
      ) : null}
      {markError ? (
        <p className="map-error" role="alert">
          标记没有保存，请再试一次。
        </p>
      ) : null}
      <div
        className="map-scroll"
        ref={scrollRef}
        tabIndex={0}
        aria-label="服务清单"
      >
        {message ? (
          <p className="map-empty">{message}</p>
        ) : loading ? (
          <p role="status">正在查看{name}上的程序……</p>
        ) : loadError ? (
          <p role="alert">
            暂时无法查看{name}上的服务。{" "}
            <button type="button" className="map-button" onClick={onRetry}>
              重试
            </button>
          </p>
        ) : !shown.length ? (
          <p className="map-empty">
            {search ? "没有找到匹配的服务。" : "还没有可显示的服务。"}
          </p>
        ) : (
          <ul className="map-services" aria-label={`${name}上的服务`}>
            {shown.map((service, index) => {
              const url = serviceUrl(service, remoteHost);
              const groupStart =
                index === 0 || shown[index - 1]!.tier !== service.tier;
              return (
                <li
                  key={service.key}
                  className={`map-service tier-${service.tier}`}
                >
                  {groupStart ? (
                    <h4 className="map-group">{tierNames[service.tier]}</h4>
                  ) : null}
                  <div className="map-service-row">
                    <div className="map-service-info">
                      <span className="map-service-name" title={service.name}>
                        {service.name}
                      </span>
                      <span
                        className={`map-service-state state-${service.state ?? "running"}`}
                      >
                        {service.state === "stopped"
                          ? "已停止"
                          : service.endpoints.some(
                                (endpoint) => endpoint.has_web_page === false,
                              )
                            ? "打不开"
                            : "正常"}
                      </span>
                      <span
                        className="map-service-meta"
                        title={service.endpoints
                          .map(
                            (endpoint) =>
                              `${endpoint.protocol} ${endpoint.port}`,
                          )
                          .join("、")}
                      >
                        {kindNames[service.kind]} ·{" "}
                        {service.endpoints
                          .map((endpoint) => endpoint.port)
                          .join(" / ") || "无端口"}
                      </span>
                    </div>
                    <div className="map-service-actions">
                      {service.tier !== "hidden" ? (
                        <button
                          type="button"
                          className="map-button map-ask"
                          disabled={askDisabled}
                          aria-label={`问问 ${service.name}`}
                          onClick={() => onAsk(service)}
                        >
                          问问
                        </button>
                      ) : null}
                      {service.tier === "show" ? (
                        <>
                          {url && service.state !== "stopped" ? (
                            <a
                              className="map-button map-go"
                              href={url}
                              target="_blank"
                              rel="noopener noreferrer"
                              aria-label={`打开 ${service.name}`}
                            >
                              打开
                            </a>
                          ) : null}
                          {!peer ? (
                            <button
                              type="button"
                              className="map-button"
                              disabled={busy}
                              onClick={() => onMark(service.key, "hidden")}
                              aria-label={`不再显示 ${service.name}`}
                            >
                              不再显示
                            </button>
                          ) : null}
                        </>
                      ) : service.tier === "review" ? (
                        <>
                          <button
                            type="button"
                            className="map-button map-go"
                            disabled={busy}
                            onClick={() => onMark(service.key, "mine")}
                            aria-label={`是我的服务 ${service.name}`}
                          >
                            是我的服务
                          </button>
                          <button
                            type="button"
                            className="map-button"
                            disabled={busy}
                            onClick={() => onMark(service.key, "hidden")}
                            aria-label={`隐藏 ${service.name}`}
                          >
                            隐藏
                          </button>
                        </>
                      ) : (
                        <button
                          type="button"
                          className="map-button"
                          disabled={busy}
                          onClick={() => onMark(service.key, null)}
                          aria-label={`恢复 ${service.name}`}
                        >
                          恢复
                        </button>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
        {hiddenCount > 0 ? (
          <div className="map-hidden">
            <button
              type="button"
              className="map-button"
              aria-expanded={hiddenOpen}
              onClick={() => {
                setHiddenOpen(!hiddenOpen);
                setPage(0);
              }}
            >
              {hiddenOpen ? "收起" : "已隐藏的"} {hiddenCount} 个
            </button>
          </div>
        ) : null}
      </div>
      {/* 常驻占位，滚到底时只隐藏，避免内容跳动 */}
      <div
        className={below ? "map-scroll-hint" : "map-scroll-hint is-idle"}
        aria-hidden="true"
      >
        ▼ 下面还有
      </div>
      <footer className="map-panel-footer">
        {peer && !message && reportedAt ? (
          <p>
            清单由 {name} 报来 · {relativeTime(reportedAt)}
          </p>
        ) : null}
        {!peer || peer.reachable === true ? (
          <button
            type="button"
            className="map-button map-ask"
            disabled={askDisabled}
            onClick={() => onAsk()}
          >
            问问 {name} 的 Agent
          </button>
        ) : null}
      </footer>
    </div>
  );
}
