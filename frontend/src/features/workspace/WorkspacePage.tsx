import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  Link,
  Outlet,
  useLocation,
  useNavigate,
  useSearchParams,
} from "react-router-dom";

import {
  loadProgramOverview,
  programOverviewQueryKey,
} from "../../api/overview";
import { requestJson } from "../../api/client";
import { incidentDetailSchema } from "../../api/schemas/overview";
import { getOperation, operationQueryKeys } from "../operations/operationsApi";
import { ChatPage } from "../chat";
import { OverviewPage, IncidentList } from "../overview/OverviewPage";
import "./workspace.css";

export function WorkspacePage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const overview = useQuery({
    queryKey: programOverviewQueryKey,
    queryFn: loadProgramOverview,
  });
  const isOperation = location.pathname.startsWith("/app/operations");
  const [programsOpen, setProgramsOpen] = useState(
    () => window.innerWidth >= 880,
  );
  const incidentId = params.get("incident_id");
  const showIncident =
    !isOperation &&
    (incidentId === "recent" ||
      /^#incident_[0-9a-f]{32}$/.test(location.hash) ||
      /^incident_[0-9a-f]{32}$/.test(incidentId ?? ""));
  const selectedIncidentId =
    !isOperation && /^incident_[0-9a-f]{32}$/.test(incidentId ?? "")
      ? incidentId
      : null;
  const incident = useQuery({
    queryKey: ["incident", selectedIncidentId],
    queryFn: () =>
      requestJson(
        `/api/incidents/${encodeURIComponent(selectedIncidentId ?? "")}`,
        incidentDetailSchema,
      ),
    enabled: selectedIncidentId !== null,
  });
  const operationId = /^\/app\/operations\/(operation_[0-9a-f]{32})$/.exec(
    location.pathname,
  )?.[1];
  const operation = useQuery({
    queryKey: operationQueryKeys.detail(operationId ?? "missing"),
    queryFn: () => getOperation(operationId ?? ""),
    enabled: operationId !== undefined,
  });
  const matching =
    overview.isError || isOperation
      ? []
      : (overview.data?.services.items.filter(
          (service) => service.service_id === params.get("service_id"),
        ) ?? []);
  const selected = matching.length === 1 ? matching[0] : undefined;
  const computers =
    overview.data?.nodes.items.filter(
      (node) => node.node_id === selected?.node_id,
    ) ?? [];
  const computerName =
    computers.length === 1 &&
    ["live", "fresh"].includes(computers[0]!.freshness)
      ? computers[0]!.display_name
      : undefined;
  useEffect(() => {
    if (isOperation && window.innerWidth < 880) setProgramsOpen(false);
  }, [isOperation]);
  useEffect(() => {
    if (selected) {
      if (document.activeElement?.closest(".chat-composer")) return;
      const heading = document.getElementById("chat-title");
      heading?.focus();
      heading?.scrollIntoView({ block: "start" });
    }
  }, [selected?.service_id]);

  return (
    <section aria-labelledby="workspace-title" className="workspace-page">
      <header className="workspace-heading">
        <h2 id="workspace-title">工作台</h2>
        <Link to="/app/operations">请求记录</Link>
      </header>
      <div className="workspace-layout">
        <details
          className="workspace-programs"
          open={programsOpen}
          onToggle={(event) => setProgramsOpen(event.currentTarget.open)}
        >
          <summary>程序与待办</summary>
          <OverviewPage
            workspace
            onAsk={(service) => {
              if (window.innerWidth < 880) setProgramsOpen(false);
              navigate(
                `/app/overview?service_id=${encodeURIComponent(service.service_id)}`,
              );
            }}
          />
        </details>
        <ChatPage
          workspace
          modelStatus={
            overview.isError ? undefined : overview.data?.model.status
          }
          serviceContext={selected}
          computerName={computerName}
          incidentId={
            incident.isError ? undefined : incident.data?.incident.incident_id
          }
          incidentThreadId={incident.data?.thread_id}
          operationContext={operation.isError ? undefined : operation.data}
          contextBlocked={
            (selectedIncidentId !== null &&
              (incident.isError || !incident.data)) ||
            (operationId !== undefined &&
              (operation.isError || !operation.data))
          }
        >
          {showIncident && overview.data ? (
            <IncidentList
              key={incidentId ?? "recent"}
              embedded
              data={overview.data.incidents}
              nodes={overview.data.nodes.items}
              services={overview.data.services.items}
            />
          ) : (
            <Outlet />
          )}
        </ChatPage>
      </div>
    </section>
  );
}
