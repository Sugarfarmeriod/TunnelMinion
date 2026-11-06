import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { requestJson } from "../../api/client";
import {
  loadProgramOverview,
  programOverviewQueryKey,
} from "../../api/overview";
import {
  incidentDetailSchema,
  type ResourceOverview,
} from "../../api/schemas/overview";
import { isReadOnlyPreview } from "../../shared/previewMode";
import { runSchema } from "../chat/contracts";
import {
  incidentOperationHandoff,
  serviceDisplayName,
} from "./overviewActions";
import { InvestigationDetails } from "./InvestigationDetails";
import {
  SectionCard,
  StatusBadge,
  collectionTone,
  formatTimestamp,
  stateTone,
} from "./OverviewCards";
import "./overview.css";

const incidentEventLabels: Record<
  ResourceOverview["incidents"]["items"][number]["event_type"],
  string
> = {
  service_added: "新出现了一个服务",
  service_removed: "服务不见了",
  node_offline: "电脑离线了",
  state_stale: "很久没收到它的最新状态",
  local_only: "只能在它自己那台电脑上打开",
  remote_unreachable: "从别的电脑打不开",
};

const incidentStatusLabels: Record<
  ResourceOverview["incidents"]["items"][number]["status"],
  string
> = {
  pending: "等着调查",
  investigating: "正在调查",
  confirmed: "查清楚了",
  insufficient_evidence: "线索不够，没查清",
  budget_exhausted: "查到次数上限，没查清",
  cancelled: "调查取消了",
  failed: "调查出错了",
  interrupted: "调查被打断了",
  investigation_unavailable: "模型用不了，没法自动调查",
  closed: "已结束",
};

type IncidentItem = ResourceOverview["incidents"]["items"][number];

interface IncidentGroup {
  key: string;
  latest: IncidentItem;
  count: number;
  firstObservedAt: string;
}

/** 同一个对象上的同一类事件合并成一行，代表项取最近一次。 */
export function groupIncidents(
  items: readonly IncidentItem[],
): IncidentGroup[] {
  const groups = new Map<string, IncidentGroup>();
  for (const item of items) {
    const key = `${item.event_type}|${item.object_kind}|${item.object_id}`;
    const group = groups.get(key);
    if (group === undefined) {
      groups.set(key, {
        key,
        latest: item,
        count: 1,
        firstObservedAt: item.first_observed_at,
      });
      continue;
    }
    group.count += 1;
    if (item.last_observed_at > group.latest.last_observed_at) {
      group.latest = item;
    }
    if (item.first_observed_at < group.firstObservedAt) {
      group.firstObservedAt = item.first_observed_at;
    }
  }
  return [...groups.values()].sort((a, b) =>
    b.latest.last_observed_at.localeCompare(a.latest.last_observed_at),
  );
}

/**
 * 事件说的是哪台电脑、哪个服务；名字拿不准时如实说不知道，不凭端口猜用途。
 * 服务已不在清单里时用事件记下的端口说清是哪个服务。
 */
export function incidentSubject(
  item: Pick<IncidentItem, "object_kind" | "object_id"> &
    Partial<Pick<IncidentItem, "port">>,
  nodes: ResourceOverview["nodes"]["items"],
  services: ResourceOverview["services"]["items"],
): string {
  const nodeName = (nodeId: string | undefined) => {
    const matches = nodes.filter((node) => node.node_id === nodeId);
    return matches.length === 1 && matches[0]?.display_name.trim()
      ? matches[0].display_name.trim()
      : undefined;
  };
  if (item.object_kind === "node") {
    return nodeName(item.object_id) ?? "一台电脑";
  }
  const matches = services.filter(
    (service) => service.service_id === item.object_id,
  );
  const service = matches.length === 1 ? matches[0] : undefined;
  const name =
    serviceDisplayName(service) ??
    (service?.port === null || service?.port === undefined
      ? item.port === null || item.port === undefined
        ? "一个已不在清单里的服务"
        : `端口 ${item.port} 上的服务（已不在清单里）`
      : `端口 ${service.port} 上的服务`);
  const computer = nodeName(service?.node_id);
  return computer === undefined ? name : `${computer} · ${name}`;
}

export function IncidentList({
  data,
  nodes,
  services,
}: {
  data: ResourceOverview["incidents"];
  nodes: ResourceOverview["nodes"]["items"];
  services: ResourceOverview["services"]["items"];
}) {
  const navigate = useNavigate();
  const titleRef = useRef<HTMLHeadingElement>(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const linkedIncidentId = searchParams.get("incident_id");
  const selectedId =
    linkedIncidentId !== null &&
    /^incident_[0-9a-f]{32}$/.test(linkedIncidentId)
      ? linkedIncidentId
      : null;
  const [question, setQuestion] = useState("");
  useEffect(() => {
    if (selectedId !== null) titleRef.current?.focus();
  }, [selectedId]);
  const detail = useQuery({
    queryKey: ["incident", selectedId],
    queryFn: () =>
      requestJson(
        `/api/incidents/${encodeURIComponent(selectedId ?? "")}`,
        incidentDetailSchema,
      ),
    enabled: selectedId !== null,
  });
  const followUp = useMutation({
    mutationFn: (value: string) =>
      requestJson(
        `/api/incidents/${encodeURIComponent(selectedId ?? "")}/follow-up`,
        runSchema,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question: value }),
        },
      ),
  });

  function openIncident(incidentId: string) {
    setSearchParams((previous) => {
      const next = new URLSearchParams(previous);
      next.set("incident_id", incidentId);
      return next;
    });
    setQuestion("");
    followUp.reset();
  }

  function submitFollowUp(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = question.trim();
    if (!isReadOnlyPreview() && value !== "") {
      followUp.mutate(value);
    }
  }

  const groups = groupIncidents(data.items);
  const handoff =
    detail.data === undefined
      ? null
      : incidentOperationHandoff(
          {
            incidentId: detail.data.incident.incident_id,
            status: detail.data.incident.status,
            eventType: detail.data.incident.event.event_type,
            objectKind: detail.data.incident.event.object_kind,
            objectId: detail.data.incident.event.object_id,
            targetNodeId: detail.data.incident.event.target_node_id,
          },
          nodes,
          services,
        );

  const event = detail.data?.incident.event;
  const matchingServices =
    event?.object_kind === "service"
      ? services.filter((service) => service.service_id === event.object_id)
      : [];
  const service =
    matchingServices.length === 1 &&
    matchingServices[0]?.node_id === event?.target_node_id
      ? matchingServices[0]
      : undefined;
  const matchingNodes = nodes.filter(
    (node) => node.node_id === event?.target_node_id,
  );
  const node = matchingNodes.length === 1 ? matchingNodes[0] : undefined;

  return (
    <SectionCard
      id="overview-incidents"
      meta={data}
      summary={
        data.items.length === 0
          ? "最近一切平静"
          : `${groups.length} 件事${groups.length === data.items.length ? "" : `（共 ${data.items.length} 次）`}`
      }
      title="发生了什么"
      tone={collectionTone(
        data,
        data.items.map((item) =>
          item.severity === "critical"
            ? "danger"
            : item.severity === "warning"
              ? "warning"
              : "neutral",
        ),
      )}
    >
      {data.items.length === 0 ? (
        <p className="overview-empty">
          最近没有服务或电脑出状况。有变化时会记在这里。
        </p>
      ) : (
        <ul className="overview-resource-list" hidden={selectedId !== null}>
          {groups.map(({ key, latest: incident, count, firstObservedAt }) => (
            <li key={key}>
              <div className="overview-resource-list__heading">
                <strong>
                  {incidentSubject(incident, nodes, services)}：
                  {incidentEventLabels[incident.event_type]}
                </strong>
                <StatusBadge
                  tone={
                    incident.severity === "critical"
                      ? "danger"
                      : incident.severity === "warning"
                        ? "warning"
                        : "neutral"
                  }
                >
                  {incidentStatusLabels[incident.status]}
                </StatusBadge>
              </div>
              <p>{incident.conclusion ?? "还没查出原因。"}</p>
              <p className="incident-when">
                {count > 1
                  ? `出现 ${count} 次 · 第一次 ${formatTimestamp(firstObservedAt)} · 最近 ${formatTimestamp(incident.last_observed_at)}`
                  : `最近一次：${formatTimestamp(incident.last_observed_at)}`}
              </p>
              <button
                id={incident.incident_id}
                aria-expanded={selectedId === incident.incident_id}
                type="button"
                onClick={() => openIncident(incident.incident_id)}
              >
                查看调查详情
              </button>
            </li>
          ))}
        </ul>
      )}

      {selectedId !== null ? (
        <section aria-live="polite" className="incident-detail">
          <button
            className="incident-back"
            type="button"
            onClick={() => navigate(`/app/incidents#${selectedId}`)}
          >
            ← 返回最近事件
          </button>
          <h4 ref={titleRef} tabIndex={-1}>
            调查结果
          </h4>
          {detail.isPending ? <p>正在读取调查详情……</p> : null}
          {detail.isError ? <p role="alert">调查详情暂时无法读取。</p> : null}
          {detail.data !== undefined ? (
            <>
              <p className="incident-context" aria-label="正在查看的服务">
                {node && ["live", "fresh"].includes(node.freshness)
                  ? node.display_name
                  : "电脑名称待确认"}{" "}
                ·{" "}
                {event?.object_kind === "service"
                  ? serviceDisplayName(service) || "服务名称待确认"
                  : "电脑本身的变化"}
              </p>
              {service?.application &&
              serviceDisplayName(service) &&
              service.port !== null ? (
                <p className="overview-empty">连接入口 {service.port}</p>
              ) : null}
              {service ? (
                <Link className="incident-service-return" to="/app/map">
                  返回这项服务
                </Link>
              ) : event?.object_kind === "service" ? (
                <p className="overview-empty">
                  当前清单中找不到唯一的同一服务；下面保留此前的调查记录。
                </p>
              ) : null}
              <StatusBadge
                tone={stateTone(detail.data.incident.status, data.freshness)}
              >
                {incidentStatusLabels[detail.data.incident.status]}
              </StatusBadge>
              <p>
                <strong>结论：</strong>
                {detail.data.incident.status === "confirmed" &&
                detail.data.incident.event.event_type === "local_only" &&
                detail.data.incident.report !== null
                  ? "这项服务只接受所属电脑的连接，其他电脑不能直接使用。"
                  : (detail.data.incident.report?.conclusion ??
                    "还没有查清原因。")}
              </p>
              <h5>下一步</h5>
              {handoff?.available ? (
                <div className="incident-operation-handoff">
                  <p>
                    先查看方案。只有你发出请求、对方批准并确认执行后，才会开始临时访问。
                  </p>
                  <Link className="incident-operation-link" to={handoff.href}>
                    查看临时访问方案
                  </Link>
                </div>
              ) : (
                <p className="overview-empty">
                  {handoff?.message ?? "当前没有可安全生成的候选处理入口。"}
                </p>
              )}
              <details className="incident-technical">
                <summary>高级：调查过程与证据</summary>
                <p>
                  <strong>原始报告结论：</strong>
                  {detail.data.incident.report?.conclusion ?? "未记录"}
                </p>
                <InvestigationDetails incident={detail.data.incident} />
              </details>
              {
                <details className="incident-question-disclosure">
                  <summary>继续问一下（会使用模型额度）</summary>
                  <form
                    className="incident-follow-up"
                    onSubmit={submitFollowUp}
                  >
                    <label htmlFor="incident-question">针对这个事件追问</label>
                    <textarea
                      id="incident-question"
                      maxLength={2000}
                      value={question}
                      onChange={(event) => setQuestion(event.target.value)}
                    />
                    <div className="incident-suggestions">
                      {detail.data.suggested_questions.map((item) => (
                        <button
                          key={item}
                          type="button"
                          onClick={() => setQuestion(item)}
                        >
                          {item}
                        </button>
                      ))}
                    </div>
                    <button
                      disabled={
                        isReadOnlyPreview() ||
                        question.trim() === "" ||
                        followUp.isPending
                      }
                      type="submit"
                    >
                      {followUp.isPending
                        ? "正在开始追问……"
                        : "开始追问（只查看，不改动）"}
                    </button>
                  </form>
                  {followUp.isError ? (
                    <p role="alert">现在没法追问；原来的调查记录没有变。</p>
                  ) : null}
                  {followUp.data !== undefined ? (
                    <p role="status">
                      已经开始追问。{" "}
                      <Link to={`/app/map?thread=${followUp.data.thread_id}`}>
                        打开对应聊天线程
                      </Link>
                    </p>
                  ) : null}
                </details>
              }
            </>
          ) : null}
        </section>
      ) : null}
    </SectionCard>
  );
}

export function IncidentsPage() {
  const query = useQuery({
    queryKey: programOverviewQueryKey,
    queryFn: loadProgramOverview,
  });
  return (
    <section
      className="overview-page surface"
      aria-labelledby="incidents-title"
    >
      <h2 id="incidents-title">最近事件</h2>
      <p className="page-lead">
        服务或电脑有了变化（不见了、打不开、新出现），TunnelMinion
        会记在这里并自动调查原因。同一件事反复出现只算一行，点开看查到了什么。
      </p>
      {query.isPending ? <p role="status">正在读取最近事件……</p> : null}
      {query.isError ? (
        <p role="alert">
          最近事件暂时无法读取。
          <button type="button" onClick={() => void query.refetch()}>
            重试
          </button>
        </p>
      ) : null}
      {query.data ? (
        <IncidentList
          data={query.data.incidents}
          nodes={query.data.nodes.items}
          services={query.data.services.items}
        />
      ) : null}
    </section>
  );
}
