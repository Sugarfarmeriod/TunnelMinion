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
  service_added: "发现新增服务",
  service_removed: "服务已经消失",
  node_offline: "节点已经离线",
  state_stale: "状态证据已经陈旧",
  local_only: "服务只能从本机访问",
  remote_unreachable: "远端无法访问服务",
};

const incidentStatusLabels: Record<
  ResourceOverview["incidents"]["items"][number]["status"],
  string
> = {
  pending: "等待调查",
  investigating: "正在调查",
  confirmed: "已查明原因",
  insufficient_evidence: "证据不足",
  budget_exhausted: "调查预算已用完",
  cancelled: "调查已取消",
  failed: "调查失败",
  interrupted: "调查被中断",
  investigation_unavailable: "模型调查不可用",
  closed: "已关闭",
};

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
          ? "没有检测到重要变化"
          : `${data.items.length} 个近期事件`
      }
      title="事件与自主调查"
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
        <p className="overview-empty">暂无需要调查的异常或重要变化。</p>
      ) : (
        <ul className="overview-resource-list" hidden={selectedId !== null}>
          {data.items.map((incident) => (
            <li key={incident.incident_id}>
              <div className="overview-resource-list__heading">
                <strong>{incidentEventLabels[incident.event_type]}</strong>
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
              <p>{incident.conclusion ?? "尚无证据充分的结论"}</p>
              <p>最后观测：{formatTimestamp(incident.last_observed_at)}</p>
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
            返回最近变化
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
                  : "设备名称待确认"}{" "}
                ·{" "}
                {event?.object_kind === "service"
                  ? serviceDisplayName(service) || "服务名称待确认"
                  : "设备变化"}
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
                <summary>查看技术过程与证据</summary>
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
                      {followUp.isPending ? "正在开始追问……" : "开始只读追问"}
                    </button>
                  </form>
                  {followUp.isError ? (
                    <p role="alert">
                      追问当前不可用；原 incident 证据没有改变。
                    </p>
                  ) : null}
                  {followUp.data !== undefined ? (
                    <p role="status">
                      追问已在原有聊天能力中开始。{" "}
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
