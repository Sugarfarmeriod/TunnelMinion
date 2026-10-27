import type { RepairDetail } from "./api";

export function RepairFacts({
  repair,
}: {
  repair: Pick<
    RepairDetail,
    | "action_summary"
    | "reason"
    | "impact_summary"
    | "verification_summary"
    | "failure_summary"
  >;
}) {
  return (
    <dl>
      {[
        ["要做什么", repair.action_summary],
        ["为什么", repair.reason],
        ["会有什么影响", repair.impact_summary],
        ["怎么确认修好", repair.verification_summary],
        ["没修好怎么办", repair.failure_summary],
      ].map(([title, text]) => (
        <div key={title}>
          <dt>{title}</dt>
          <dd>{text}</dd>
        </div>
      ))}
    </dl>
  );
}

function repairStep(status: string) {
  return status === "authorized" ? 0 : status === "executing" ? 1 : 2;
}

const steps = ["再核对一次", "正在执行", "正在确认"];

export function RepairProgress({
  status,
  prefix,
}: {
  status: string;
  prefix?: string;
}) {
  const step = repairStep(status);
  return (
    <>
      {prefix ? (
        <p role="status">
          {prefix}
          {steps[step]}
        </p>
      ) : null}
      <ol className="repair-steps" aria-label="修复进度" aria-live="polite">
        {steps.map((text, index) => (
          <li
            key={text}
            className={index < step ? "done" : index === step ? "doing" : ""}
            aria-current={index === step ? "step" : undefined}
          >
            {text}
          </li>
        ))}
      </ol>
    </>
  );
}

export function repairResultTitle(status: string) {
  if (status === "succeeded") return "修好了";
  if (["authorization_expired", "expired"].includes(status)) return "已过期";
  if (["rejected", "cancelled"].includes(status)) return "已取消";
  return "没修好";
}
