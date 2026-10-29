import { useEffect, useRef, useState } from "react";

import type { ManualStep } from "./api";
import "./repairs.css";

/**
 * 修不了时给主人照着做的现成步骤。
 * 步骤由本机代码按固定模板生成；这里只显示和复制，绝不执行。
 */
export function ManualSteps({ steps }: { steps: ManualStep[] }) {
  if (!steps.length) return null;
  return (
    <section className="manual-steps" aria-label="可以照着做">
      <strong>可以照着做</strong>
      <ol>
        {steps.map((step, index) => (
          <li key={index}>
            <p>{step.text}</p>
            {step.command ? <CopyableCommand command={step.command} /> : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

function CopyableCommand({ command }: { command: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  async function copy() {
    window.clearTimeout(timer.current);
    try {
      // 剪贴板在非安全上下文或被浏览器拦截时不可用，统一按失败处理。
      if (!navigator.clipboard) throw new Error("剪贴板不可用");
      await navigator.clipboard.writeText(command);
      setState("copied");
      timer.current = window.setTimeout(() => setState("idle"), 2_000);
    } catch {
      setState("failed");
    }
  }

  return (
    <div className="manual-steps-command">
      <pre>
        <code>{command}</code>
      </pre>
      <button type="button" className="map-button" onClick={() => void copy()}>
        {state === "copied" ? "已复制" : "复制"}
      </button>
      {state === "failed" ? (
        <span role="alert">复制失败，请手动选中</span>
      ) : null}
    </div>
  );
}
