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
  loadPeers,
  loadPeerServices,
  peersQueryKey,
  peerServicesQueryKey,
  peerServiceEntries,
  peerPatrol,
  localServicesQueryKey,
  updateServiceMark,
  type ServiceEntry,
  type Peer,
} from "./api";
import {
  ConversationDrawer,
  type ChatRequest,
} from "../chat/ConversationDrawer";
import { ComputerNode, platformName } from "./ComputerNode";
import { ServicesPanel } from "./ServicesPanel";
import { mapLayout, relativeTime } from "./topology";
import {
  isRepairExecuting,
  isRepairTerminal,
  repairsQueryKey,
  type RepairDetail,
  type RemoteRepair,
} from "../repairs/api";
import { useRepairs } from "../repairs/useRepairs";
import { RepairDialog } from "../repairs/RepairDialog";
import { RemoteRepairDialog } from "../repairs/RemoteRepairDialog";
import { RepairBang } from "../repairs/RepairBang";
import type { RunEventState } from "../chat/eventReducer";
import { DelegationActivity, delegationStatus } from "./DelegationActivity";
import { WelcomeGate } from "../people/WelcomeGate";
import {
  acknowledgeDown,
  patrolQueryKey,
  setAutoRepair,
  usePatrol,
} from "../patrol/api";
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
  const patrol = usePatrol();
  const patrolChange = useMutation({
    mutationFn: (
      change: { key: string; enabled: boolean } | { key: string; ack: true },
    ) =>
      "ack" in change ? acknowledgeDown(change.key) : setAutoRepair(change),
    onSuccess: (data) => client.setQueryData(patrolQueryKey, data),
  });
  const downKeys = patrol.isSuccess
    ? patrol.down.map((service) => service.key).join(" ")
    : null;
  const seenDownKeys = useRef<string | null>(null);
  useEffect(() => {
    // 挂了或恢复（包括自动修好）时，服务清单和修复列表跟着刷新；第一次读到不算变化。
    const previous = seenDownKeys.current;
    seenDownKeys.current = downKeys;
    if (previous === null || downKeys === null || previous === downKeys) return;
    void client.invalidateQueries({ queryKey: localServicesQueryKey });
    void client.invalidateQueries({ queryKey: repairsQueryKey });
  }, [client, downKeys]);
  const peers = useQuery({
    queryKey: peersQueryKey,
    queryFn: loadPeers,
    refetchInterval: 60_000,
  });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const open = selectedId !== null;
  const selectedPeer = peers.data?.peers.find(
    (peer) => !peer.is_local && peer.node_id === selectedId,
  );
  const peerServices = useQuery({
    queryKey: peerServicesQueryKey(selectedPeer?.node_id ?? ""),
    queryFn: ({ signal }) => loadPeerServices(selectedPeer!.node_id, signal),
    enabled:
      selectedPeer?.source === "gateway" &&
      selectedPeer.reachable === true &&
      selectedPeer.services_visible,
    refetchInterval: 60_000,
  });
  const [delegations, setDelegations] = useState<RunEventState["delegations"]>(
    {},
  );
  const remotePeers = (peers.data?.peers ?? [])
    .filter((peer) => !peer.is_local)
    .map((peer) => ({
      ...peer,
      pending_repairs: peer.pending_repairs.filter(
        (repair) =>
          !isRepairTerminal(repair.status) &&
          Date.parse(repair.expires_at) > Date.now(),
      ),
    }));
  const [narrowMap, setNarrowMap] = useState(window.innerWidth <= 760);
  const layout = mapLayout(remotePeers.length, narrowMap);
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
  const repairs = useRepairs(nodeId);
  const [repairId, setRepairId] = useState<string | null>(null);
  const [remoteRepair, setRemoteRepair] = useState<{
    peer: Peer;
    repair: RemoteRepair;
  } | null>(null);
  const [repairProgress, setRepairProgress] = useState<RepairDetail | null>(
    null,
  );
  const repairing =
    repairs.local.some((repair) => isRepairExecuting(repair.status)) ||
    (repairProgress !== null && isRepairExecuting(repairProgress.status));
  const count = observed
    ? services.data!.services.filter((service) => service.tier !== "hidden")
        .length
    : null;

  function close(restoreFocus = true) {
    setSelectedId(null);
    if (restoreFocus) nodeRef.current?.focus();
  }

  function openChat(request: Omit<ChatRequest, "key">) {
    setChatRequest({ ...request, key: ++requestKey.current });
    setDrawerOpen(true);
    setMenuOpen(false);
  }

  function askService(service?: ServiceEntry) {
    const targetId = selectedPeer?.node_id ?? nodeId;
    if (
      !targetId ||
      isReadOnlyPreview() ||
      (selectedPeer && selectedPeer.reachable !== true)
    )
      return;
    openChat({
      about: { node_id: targetId, service_key: service?.key ?? null },
      service,
      question:
        service &&
        (service.state === "stopped" ||
          (selectedPeer
            ? peerPatrol(peerServices.data)[service.key] !== undefined
            : patrol.byKey[service.key]?.status === "down") ||
          service.endpoints.some((endpoint) => endpoint.has_web_page === false))
          ? `${service.name}怎么打不开？`
          : undefined,
    });
  }

  useLayoutEffect(() => {
    function measure() {
      const width = stageRef.current?.getBoundingClientRect().width;
      setNarrowMap(
        window.innerWidth <= 760 ||
          (width !== undefined && width > 0 && width < 680),
      );
    }
    measure();
    const observer = new ResizeObserver(measure);
    if (stageRef.current) observer.observe(stageRef.current);
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, []);

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
    if (!open || drawerOpen || repairId || remoteRepair) return;
    function onOutsideClick(event: MouseEvent) {
      if (
        event.target instanceof Node &&
        !panelRef.current?.contains(event.target) &&
        !(event.target instanceof Element && event.target.closest(".map-node"))
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
  }, [open, drawerOpen, repairId, remoteRepair]);

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
              {1 + remotePeers.filter((peer) => peer.reachable === true).length}{" "}
              台在线 · {count === null ? "正在查看服务" : `${count} 个服务`} ·
              点电脑查看服务
            </p>
          </div>
          <div className="map-heading-actions">
            <Link className="map-button" to="/app/people">
              电脑与朋友
            </Link>
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
                  <Link to="/app/people">电脑与朋友</Link>
                  <Link to="/app/settings">设置</Link>
                </nav>
              ) : null}
            </div>
          </div>
        </header>
        <WelcomeGate />
        <div className="map-stage" ref={stageRef}>
          <div
            className="map-canvas"
            aria-label="电脑拓扑图"
            style={{ height: layout.height }}
          >
            {remotePeers.map((peer, index) =>
              peer.reachable === true ? (
                <DelegationActivity
                  key={peer.node_id}
                  delegations={Object.values(delegations).filter(
                    (item) => item.peer_node_id === peer.node_id,
                  )}
                  local={layout.local}
                  peer={layout.peers[index]!}
                  list={layout.list}
                />
              ) : null,
            )}
            <svg
              className="map-links"
              viewBox={`0 0 100 ${layout.height}`}
              preserveAspectRatio="none"
              role="group"
              aria-label="电脑之间的连接"
            >
              {remotePeers.map((peer, index) => {
                const point = layout.peers[index]!;
                return (
                  <path
                    key={peer.node_id}
                    role="img"
                    aria-label={`这台电脑到${peer.display_name}：${peer.reachable === true ? "能连上" : "连不上"}`}
                    data-from={nodeId}
                    data-to={peer.node_id}
                    className={`map-link${peer.reachable === true ? "" : " is-unreachable"}`}
                    d={
                      layout.list
                        ? `M${layout.local.x},${layout.local.y} H10 V${point.y} H${point.x}`
                        : `M${layout.local.x},${layout.local.y} L${point.x},${point.y}`
                    }
                  />
                );
              })}
            </svg>
            <div
              className="map-node-position"
              style={{ left: `${layout.local.x}%`, top: layout.local.y }}
              onMouseEnter={() => setHovered(true)}
              onMouseLeave={() => setHovered(false)}
              onFocus={() => setHovered(true)}
              onBlur={() => setHovered(false)}
            >
              {repairs.pending.length > 0 && !repairing ? (
                <RepairBang
                  name="这台电脑"
                  count={repairs.pending.length}
                  onClick={() => setRepairId(repairs.pending[0]!.repair_id)}
                />
              ) : null}
              <ComputerNode
                name="这台电脑"
                platform={platform}
                online
                serviceCount={count}
                selected={selectedId === "local"}
                buttonRef={(element) => {
                  if (!selectedPeer) nodeRef.current = element;
                }}
                onClick={() =>
                  selectedId === "local" ? close() : setSelectedId("local")
                }
                repairing={repairing}
                pendingCount={repairs.pending.length}
                downCount={patrol.down.length}
              />
            </div>
            {remotePeers.map((peer, index) => {
              const progress = Object.values(delegations).filter(
                (item) =>
                  peer.reachable === true && item.peer_node_id === peer.node_id,
              );
              const phase =
                progress.find((item) => item.phase === "investigating")
                  ?.phase ??
                progress.find((item) => item.phase === "submitted")?.phase ??
                progress.at(-1)?.phase;
              const status =
                phase === "investigating" || phase === "submitted"
                  ? delegationStatus[phase]
                  : peer.pending_repairs.length
                    ? `! 有 ${peer.pending_repairs.length} 件事要在 ${peer.display_name} 上批准`
                    : peer.auth_rejected
                      ? "对方不认这台电脑"
                      : peer.reachable === false
                        ? `离线，上次在线 ${relativeTime(peer.last_seen_at)}`
                        : peer.reachable === null
                          ? "尚未确认能否连上"
                          : phase
                            ? delegationStatus[phase]
                            : undefined;
              return (
                <div
                  className={`map-node-position${phase === "investigating" || phase === "answered" ? " is-delegating" : ""}`}
                  key={peer.node_id}
                  style={{
                    left: `${layout.peers[index]!.x}%`,
                    top: layout.peers[index]!.y,
                  }}
                >
                  {peer.pending_repairs.length ? (
                    <RepairBang
                      name={peer.display_name}
                      count={peer.pending_repairs.length}
                      onClick={() =>
                        setRemoteRepair({
                          peer,
                          repair: peer.pending_repairs[0]!,
                        })
                      }
                    />
                  ) : null}
                  <ComputerNode
                    name={peer.display_name}
                    platform={peer.platform}
                    online={peer.reachable === true}
                    serviceCount={peer.service_count}
                    selected={selectedId === peer.node_id}
                    status={status}
                    buttonRef={(element) => {
                      if (selectedId === peer.node_id)
                        nodeRef.current = element;
                    }}
                    onClick={() =>
                      selectedId === peer.node_id
                        ? close()
                        : setSelectedId(peer.node_id)
                    }
                  />
                </div>
              );
            })}
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
              key={selectedId}
              peer={selectedPeer}
              remoteHost={
                selectedPeer ? (peerServices.data?.host ?? null) : undefined
              }
              reportedAt={peerServices.data?.observed_at}
              panelRef={panelRef}
              stageRef={stageRef}
              nodeRef={nodeRef}
              platform={selectedPeer?.platform ?? platform}
              services={
                selectedPeer
                  ? selectedPeer.reachable === true &&
                    selectedPeer.services_visible
                    ? peerServiceEntries(peerServices.data)
                    : []
                  : observed
                    ? services.data!.services
                    : []
              }
              loading={
                selectedPeer
                  ? peerServices.isPending
                  : !observed && !services.isError
              }
              loadError={selectedPeer ? peerServices.isError : services.isError}
              onRetry={() => {
                void (selectedPeer
                  ? peerServices.refetch()
                  : services.refetch());
              }}
              onClose={close}
              onMark={(key, value) => mark.mutate({ key, mark: value })}
              busy={mark.isPending || isReadOnlyPreview()}
              markError={!selectedPeer && mark.isError}
              onAsk={askService}
              askDisabled={!nodeId || isReadOnlyPreview()}
              pendingRepairs={
                selectedPeer
                  ? remotePeers
                      .find((peer) => peer.node_id === selectedPeer.node_id)
                      ?.pending_repairs.map((repair) => ({
                        repair_id: repair.repair_id,
                        action_summary: repair.action,
                      }))
                  : repairs.pending
              }
              patrol={selectedPeer ? undefined : patrol.byKey}
              remotePatrol={
                selectedPeer ? peerPatrol(peerServices.data) : undefined
              }
              patrolBusy={patrolChange.isPending || isReadOnlyPreview()}
              patrolError={!selectedPeer && patrolChange.isError}
              onAutoRepair={(key, enabled) =>
                patrolChange.mutate({ key, enabled })
              }
              onAcknowledge={(key) => patrolChange.mutate({ key, ack: true })}
              onOpenThread={(threadId) => openChat({ threadId })}
              onRepair={(id) => {
                if (selectedPeer) {
                  const repair = selectedPeer.pending_repairs.find(
                    (repair) => repair.repair_id === id,
                  );
                  if (repair) setRemoteRepair({ peer: selectedPeer, repair });
                } else setRepairId(id);
              }}
            />
          ) : null}
        </div>
        {!open && !observed && !services.isError ? (
          <p className="map-status" role="status">
            正在查看这台电脑上的程序……
          </p>
        ) : null}
        {peers.isError ? (
          <p className="map-status" role="alert">
            暂时无法读取其他电脑。
            <button
              type="button"
              className="map-button"
              onClick={() => void peers.refetch()}
            >
              重试
            </button>
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
        open={drawerOpen && repairId === null && remoteRepair === null}
        onClose={() => setDrawerOpen(false)}
        toggleRef={toggleRef}
        request={chatRequest}
        nodeId={nodeId}
        services={services.data?.services ?? []}
        nodes={[...remotePeers, ...(overview.data?.nodes.items ?? [])]}
        peerServices={
          selectedPeer && peerServices.data
            ? {
                node_id: selectedPeer.node_id,
                services: peerServiceEntries(peerServices.data),
              }
            : undefined
        }
        modelStatus={overview.data?.model.status}
        onUnread={(threadId) => setUnread((items) => [...items, threadId])}
        pendingRepairs={repairs.pending}
        onRepair={setRepairId}
        onDelegationsChange={setDelegations}
      />
      {repairId ? (
        <RepairDialog
          key={repairId}
          repairId={repairId}
          onClose={() => {
            setRepairId(null);
            setRepairProgress(null);
          }}
          onStatus={setRepairProgress}
        />
      ) : null}
      {remoteRepair ? (
        <RemoteRepairDialog
          nodeId={remoteRepair.peer.node_id}
          repair={remoteRepair.repair}
          name={remoteRepair.peer.display_name}
          onClose={() => setRemoteRepair(null)}
        />
      ) : null}
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
