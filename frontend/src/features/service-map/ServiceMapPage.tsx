import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useLayoutEffect, useRef, useState } from "react";

import {
  loadProgramOverview,
  programOverviewQueryKey,
} from "../../api/overview";
import { isReadOnlyPreview } from "../../shared/previewMode";
import {
  loadLocalServices,
  localServicesQueryKey,
  updateServiceMark,
} from "./api";
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
  const [hovered, setHovered] = useState(false);
  const [tipPosition, setTipPosition] = useState({ left: 0, top: 0 });
  const stageRef = useRef<HTMLDivElement>(null);
  const nodeRef = useRef<HTMLButtonElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const platform = overview.data?.local.platform ?? null;
  const observed = services.data?.observed_at != null;
  const count = observed
    ? services.data!.services.filter((service) => service.tier !== "hidden")
        .length
    : null;

  function close() {
    setOpen(false);
    nodeRef.current?.focus();
  }

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: PointerEvent) {
      if (
        event.target instanceof Node &&
        !panelRef.current?.contains(event.target) &&
        !nodeRef.current?.contains(event.target)
      ) {
        event.preventDefault();
        close();
      }
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

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
    <section className="service-map" aria-labelledby="service-map-title">
      <header className="map-heading">
        <h2 id="service-map-title">服务地图</h2>
        <p>点一下电脑，看看上面有哪些服务。</p>
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
          />
        ) : null}
      </div>
      {!open && !observed && !services.isError ? (
        <p className="map-status" role="status">
          正在查看这台电脑上的程序……
        </p>
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
