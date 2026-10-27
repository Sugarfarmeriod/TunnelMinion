import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import {
  loadProgramOverview,
  programOverviewQueryKey,
} from "../../api/overview";
import { isReadOnlyPreview } from "../../shared/previewMode";
import {
  loadLocalServices,
  localServicesQueryKey,
  updateServiceMark,
  type ServiceEntry,
} from "./api";
import {
  ConversationDrawer,
  type ChatRequest,
} from "../chat/ConversationDrawer";
import { ComputerNode, platformName } from "./ComputerNode";
import { ServicesPanel } from "./ServicesPanel";
import "./service-map.css";

export function ServiceMapPage() {
  const client = useQueryClient();
  const services = useQuery({
    queryKey: localServicesQueryKey,
    queryFn: loadLocalServices,
    refetchInterval: (query) =>
      query.state.data?.observed_at === null ? 5_000 : false,
  });
  const overview = useQuery({
    queryKey: programOverviewQueryKey,
    queryFn: loadProgramOverview,
  });
  const mark = useMutation({
    mutationFn: updateServiceMark,
    onMutate: () => client.cancelQueries({ queryKey: localServicesQueryKey }),
    onSuccess: (data) => client.setQueryData(localServicesQueryKey, data),
  });
  const [open, setOpen] = useState(false);
  const [params] = useSearchParams();
  const linkedThread = params.get("thread");
  const [drawerOpen, setDrawerOpen] = useState(Boolean(linkedThread));
  const [chatRequest, setChatRequest] = useState<ChatRequest | null>(
    linkedThread ? { key: 0, threadId: linkedThread } : null,
  );
  const requestKey = useRef(0);
  const [unread, setUnread] = useState<string[]>([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [globalQuestion, setGlobalQuestion] = useState("");
  const toggleRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const [hovered, setHovered] = useState(false);
  const [tipPosition, setTipPosition] = useState({ left: 0, top: 0 });
  const stageRef = useRef<HTMLDivElement>(null);
  const nodeRef = useRef<HTMLButtonElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const platform = overview.data?.local.platform ?? null;
  const nodeId =
    services.data?.node_id ??
    overview.data?.nodes.items.find((node) => node.state === "local")?.node_id;
  const observed = services.data?.observed_at != null;
  const count = observed
    ? services.data!.services.filter((service) => service.tier !== "hidden")
        .length
    : null;

  function close(restoreFocus = true) {
    setOpen(false);
    if (restoreFocus) nodeRef.current?.focus();
  }

  function openChat(request: Omit<ChatRequest, "key">) {
    setChatRequest({ ...request, key: ++requestKey.current });
    setDrawerOpen(true);
    setMenuOpen(false);
  }

  function askService(service?: ServiceEntry) {
    if (!nodeId || isReadOnlyPreview()) return;
    openChat({
      about: { node_id: nodeId, service_key: service?.key ?? null },
      question:
        service?.state === "stopped"
          ? `${service.name}怎么打不开？`
          : undefined,
    });
  }

  useEffect(() => {
    if (linkedThread) openChat({ threadId: linkedThread });
  }, [linkedThread]);
  useEffect(() => {
    if (!menuOpen) return;
    function dismiss(event: PointerEvent) {
      if (
        event.target instanceof Node &&
        !menuRef.current?.contains(event.target)
      )
        setMenuOpen(false);
    }
    document.addEventListener("pointerdown", dismiss);
    return () => document.removeEventListener("pointerdown", dismiss);
  }, [menuOpen]);

  useEffect(() => {
    if (!open || drawerOpen) return;
    function onOutsideClick(event: MouseEvent) {
      if (
        event.target instanceof Node &&
        !panelRef.current?.contains(event.target) &&
        !nodeRef.current?.contains(event.target)
      ) {
        // 等这次点击完成再收起：按下时就收起会让窄屏页面变短、滚动，点击落到别处。
        // 点到可操作的元素时焦点留给它，点到空白处才回到电脑。
        close(
          !(event.target instanceof Element) ||
            event.target.closest(
              'button, a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])',
            ) === null,
        );
      }
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    }
    document.addEventListener("click", onOutsideClick);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("click", onOutsideClick);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open, drawerOpen]);

  useLayoutEffect(() => {
    if (!hovered || open) return;
    function placeTip() {
      const stage = stageRef.current?.getBoundingClientRect();
      const node = nodeRef.current?.getBoundingClientRect();
      const tip = tipRef.current?.getBoundingClientRect();
      if (!stage || !node || !tip) return;
      const right = node.right - stage.left + 12;
      setTipPosition({
        left: Math.max(
          8,
          Math.min(
            right + tip.width <= stage.width - 8
              ? right
              : node.left - stage.left - tip.width - 12,
            stage.width - tip.width - 8,
          ),
        ),
        top: Math.max(
          8,
          Math.min(node.top - stage.top, stage.height - tip.height - 8),
        ),
      });
    }
    placeTip();
    window.addEventListener("resize", placeTip);
    return () => window.removeEventListener("resize", placeTip);
  }, [hovered, open, platform, count]);

  return (
    <section
      className={`service-map${drawerOpen ? " drawer-open" : ""}`}
      aria-labelledby="service-map-title"
    >
      <div className="map-workspace">
        <header className="map-heading">
          <div>
            <h2 id="service-map-title">我的服务网络</h2>
            <p>
              这台电脑在线 ·{" "}
              {count === null ? "正在查看服务" : `${count} 个服务`} ·
              点电脑查看服务
            </p>
          </div>
          <div className="map-heading-actions">
            <button
              type="button"
              ref={toggleRef}
              className="map-button"
              aria-expanded={drawerOpen}
              aria-controls="drawer-title"
              onClick={() => {
                if (drawerOpen) setDrawerOpen(false);
                else {
                  const latest = unread.at(-1);
                  if (latest) openChat({ threadId: latest });
                  else setDrawerOpen(true);
                  setUnread([]);
                }
              }}
            >
              对话
              {unread.length ? (
                <span
                  className="map-unread"
                  aria-label={`${unread.length} 条未读回答`}
                >
                  {unread.length}
                </span>
              ) : null}
            </button>
            <div
              className="map-menu-wrap"
              ref={menuRef}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                  setMenuOpen(false);
                  menuButtonRef.current?.focus();
                }
                if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                  event.preventDefault();
                  const items = Array.from(
                    menuRef.current?.querySelectorAll<HTMLAnchorElement>("a") ??
                      [],
                  );
                  const index = items.indexOf(
                    document.activeElement as HTMLAnchorElement,
                  );
                  items[
                    (index +
                      (event.key === "ArrowDown" ? 1 : items.length - 1)) %
                      items.length
                  ]?.focus();
                }
              }}
            >
              <button
                type="button"
                ref={menuButtonRef}
                className="map-button"
                aria-expanded={menuOpen}
                aria-controls="map-more-menu"
                onClick={() => setMenuOpen(!menuOpen)}
              >
                更多 ▾
              </button>
              {menuOpen ? (
                <nav
                  id="map-more-menu"
                  className="map-more-menu"
                  aria-label="更多"
                >
                  <Link to="/app/operations">请求记录</Link>
                  <Link to="/app/incidents">最近事件</Link>
                  <Link to="/app/memories">记忆</Link>
                  <Link to="/app/settings">设置</Link>
                </nav>
              ) : null}
            </div>
          </div>
        </header>
        <div className="map-stage" ref={stageRef}>
          <div className="map-canvas" aria-label="电脑拓扑图">
            <div
              className="map-node-position"
              onMouseEnter={() => setHovered(true)}
              onMouseLeave={() => setHovered(false)}
              onFocus={() => setHovered(true)}
              onBlur={() => setHovered(false)}
            >
              <ComputerNode
                name="这台电脑"
                platform={platform}
                online
                serviceCount={count}
                selected={open}
                buttonRef={nodeRef}
                onClick={() => (open ? close() : setOpen(true))}
              />
            </div>
          </div>
          {hovered && !open ? (
            <div
              className="map-tip"
              ref={tipRef}
              role="tooltip"
              style={tipPosition}
            >
              <strong>这台电脑 · {platformName(platform)}</strong>
              <span>{count === null ? "正在查看服务" : `${count} 个服务`}</span>
              <span>点一下查看</span>
            </div>
          ) : null}
          {open ? (
            <ServicesPanel
              panelRef={panelRef}
              stageRef={stageRef}
              nodeRef={nodeRef}
              platform={platform}
              services={observed ? services.data!.services : []}
              loading={!observed && !services.isError}
              loadError={services.isError}
              onRetry={() => void services.refetch()}
              onClose={close}
              onMark={(key, value) => mark.mutate({ key, mark: value })}
              busy={mark.isPending || isReadOnlyPreview()}
              markError={mark.isError}
              onAsk={askService}
              askDisabled={!nodeId || isReadOnlyPreview()}
            />
          ) : null}
        </div>
        {!open && !observed && !services.isError ? (
          <p className="map-status" role="status">
            正在查看这台电脑上的程序……
          </p>
        ) : null}
        <form
          className="map-global-ask"
          onSubmit={(event) => {
            event.preventDefault();
            if (isReadOnlyPreview() || !globalQuestion.trim()) return;
            openChat({ question: globalQuestion });
            setGlobalQuestion("");
          }}
        >
          <label htmlFor="map-question">想问点什么？</label>
          <div>
            <input
              id="map-question"
              value={globalQuestion}
              maxLength={20_000}
              placeholder="例如：这台电脑上有哪些服务？"
              disabled={isReadOnlyPreview()}
              onChange={(event) => setGlobalQuestion(event.target.value)}
            />
            <button
              type="submit"
              className="map-button map-go"
              disabled={isReadOnlyPreview() || !globalQuestion.trim()}
            >
              问问 Agent
            </button>
          </div>
          <div className="map-examples">
            {[
              "这台电脑上有哪些服务？",
              "哪个程序最占内存？",
              "服务打不开时先查什么？",
            ].map((question) => (
              <button
                key={question}
                type="button"
                className="map-button"
                disabled={isReadOnlyPreview()}
                onClick={() => openChat({ question })}
              >
                {question}
              </button>
            ))}
          </div>
        </form>
      </div>
      <ConversationDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        toggleRef={toggleRef}
        request={chatRequest}
        nodeId={nodeId}
        services={services.data?.services ?? []}
        nodes={overview.data?.nodes.items ?? []}
        modelStatus={overview.data?.model.status}
        onUnread={(threadId) => setUnread((items) => [...items, threadId])}
      />
      {!open && services.isError ? (
        <p className="map-status" role="alert">
          暂时无法查看这台电脑上的服务。{" "}
          <button
            type="button"
            className="map-button"
            onClick={() => void services.refetch()}
          >
            重试
          </button>
        </p>
      ) : null}
    </section>
  );
}
