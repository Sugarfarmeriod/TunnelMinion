import type { FormEvent, ReactNode } from "react";
import { useRef, useState } from "react";

import { ApiError } from "../../api/client";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import {
  cancelSetup,
  confirmSetup,
  inspectCode,
  joinFriend,
  joinOwner,
  shortFingerprint,
  startSetup,
} from "./api";
import type { Identity, Inspection } from "./api";

export type Route = "first" | "join" | "friend";
type Step =
  | { name: "choose" | "paste" | "address" | "pair" }
  | { name: "show"; setupId: string; code: string }
  | { name: "confirm"; setupId: string }
  | { name: "done"; message: string };

const routeTitles: Record<Route, string> = {
  first: "这是我的第一台电脑",
  join: "加入我的电脑",
  friend: "我是朋友，粘贴配对码",
};

export function readableError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "没能完成，请确认本机 TunnelMinion 仍在运行后再试。";
}

function expiresText(value: string): string {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

/**
 * 没有机主身份时的三选一，以及已有身份时"粘贴朋友的配对码"。
 * 恢复码只在"抄写"这一步留在页面状态里，点"我已抄好"后立即丢掉。
 */
export function OnboardingDialog({
  identity: initial,
  start,
  onClose,
  onChanged,
}: {
  identity: Identity;
  start?: Route;
  onClose: () => void;
  onChanged: (identity: Identity) => void;
}) {
  // 用打开时的身份；流程中途身份建好、列表刷新，也不改变这次走的路线。
  const [identity] = useState(initial);
  const pairOnly = identity.initialized;
  const [route, setRoute] = useState<Route>(start ?? "first");
  const [step, setStep] = useState<Step>(
    start === undefined
      ? { name: "choose" }
      : { name: start === "first" ? "address" : "paste" },
  );
  const [code, setCode] = useState("");
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [host, setHost] = useState(
    identity.bind?.host ?? identity.address_candidates[0] ?? "",
  );
  const [port, setPort] = useState(String(identity.bind?.port ?? 8787));
  const [name, setName] = useState(identity.local_display_name);
  const [myName, setMyName] = useState("");
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const firstRef = useRef<HTMLButtonElement>(null);
  const locked = identity.bind !== null || inspection?.bind_locked === true;

  async function close() {
    if (step.name === "show" || step.name === "confirm") {
      // 关掉就作废，内存里的密钥不会写入。
      await cancelSetup(step.setupId).catch(() => undefined);
    }
    onClose();
  }

  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    escapeDisabled: busy,
    initialFocusRef: firstRef,
    onEscape: () => void close(),
    returnFocus: [],
  });

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (failure) {
      setError(readableError(failure));
    } finally {
      setBusy(false);
    }
  }

  function choose(next: Route) {
    setRoute(next);
    setError(null);
    setStep({ name: next === "first" ? "address" : "paste" });
  }

  function submitCode(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      const result = await inspectCode(code.trim());
      const expected = route === "join" ? "owner" : "friend";
      if (result.kind !== expected) {
        setError(
          result.kind === "owner"
            ? "这是加入“我的电脑”用的加入码（tmo1_ 开头），请回到上一步选“加入我的电脑”。"
            : "这是朋友的配对码（tmf1_ 开头），请回到上一步选“我是朋友”。",
        );
        return;
      }
      if (result.expired) {
        setError("这个码已经过期了，请让对方重新生成一个。");
        return;
      }
      setInspection(result);
      if (!locked && result.suggested_host !== null)
        setHost(result.suggested_host);
      if (!locked) setPort(String(result.suggested_port));
      if (pairOnly) {
        setStep({ name: "pair" });
      } else {
        setStep({ name: "address" });
      }
    });
  }

  function addressBody() {
    return locked ? {} : { host: host.trim(), port: Number(port) };
  }

  function submitAddress(event: FormEvent) {
    event.preventDefault();
    if (!locked && (host.trim() === "" || !Number.isInteger(Number(port)))) {
      setError("请填写本机组网地址和端口。");
      return;
    }
    void run(async () => {
      if (route === "join") {
        const joined = await joinOwner({ code: code.trim(), ...addressBody() });
        onChanged(joined);
        setStep({
          name: "done",
          message: "已加入我的电脑。",
        });
        return;
      }
      const started = await startSetup({
        ...addressBody(),
        display_name: name.trim() === "" ? undefined : name.trim(),
      });
      setStep({
        name: "show",
        setupId: started.setup_id,
        code: started.recovery_code,
      });
    });
  }

  async function pair(): Promise<void> {
    const paired = await joinFriend({
      code: code.trim(),
      display_name: myName.trim() === "" ? undefined : myName.trim(),
    });
    onChanged(paired);
    setStep({ name: "done", message: "已经和朋友配好对了。" });
  }

  function submitConfirm(event: FormEvent) {
    event.preventDefault();
    if (step.name !== "confirm") return;
    void run(async () => {
      const created = await confirmSetup(step.setupId, typed);
      setTyped("");
      onChanged(created);
      if (route === "friend") {
        setStep({ name: "pair" });
        try {
          await pair();
        } catch (failure) {
          setError(
            `身份已经建好，但这次没配上对：${readableError(failure)} 可以在“电脑与朋友”页面重新粘贴配对码。`,
          );
          setStep({ name: "done", message: "已建立你的机主身份。" });
        }
        return;
      }
      setStep({ name: "done", message: "已建立你的机主身份。" });
    });
  }

  let title = pairOnly ? "粘贴朋友的配对码" : "欢迎使用 TunnelMinion";
  let body: ReactNode;
  if (step.name === "choose") {
    body = (
      <>
        <p>这台电脑还没有加入任何人的电脑。选一个最符合你的情况：</p>
        <div className="people-choices">
          {(["first", "join", "friend"] as const).map((item, index) => (
            <button
              key={item}
              ref={index === 0 ? firstRef : undefined}
              type="button"
              className="people-choice"
              onClick={() => choose(item)}
            >
              <strong>{routeTitles[item]}</strong>
              <span>
                {item === "first"
                  ? "建立你的机主身份。以后加电脑、邀请朋友都在这台电脑上操作。"
                  : item === "join"
                    ? "你已经有一台装好 TunnelMinion 的电脑，在那台电脑上点了“加一台我的电脑”，把加入码粘贴到这里。"
                    : "朋友发给你一串 tmf1_ 开头的配对码。会先替你建立自己的身份，然后和朋友配对。"}
              </span>
            </button>
          ))}
        </div>
        <div className="people-dialog__actions">
          <button type="button" onClick={() => void close()}>
            以后再说
          </button>
        </div>
      </>
    );
  } else if (step.name === "paste") {
    title = pairOnly ? title : routeTitles[route];
    body = (
      <form onSubmit={submitCode} className="people-form">
        <label>
          {route === "join" ? "加入码（tmo1_ 开头）" : "配对码（tmf1_ 开头）"}
          <textarea
            autoComplete="off"
            spellCheck={false}
            rows={4}
            value={code}
            onChange={(event) => setCode(event.currentTarget.value)}
          />
        </label>
        {pairOnly ? (
          <label>
            你的名字（朋友那边看到的，可不填）
            <input
              maxLength={40}
              value={myName}
              onChange={(event) => setMyName(event.currentTarget.value)}
            />
          </label>
        ) : null}
        <div className="people-dialog__actions">
          <button
            type="button"
            onClick={() =>
              pairOnly ? void close() : setStep({ name: "choose" })
            }
          >
            {pairOnly ? "取消" : "上一步"}
          </button>
          <button
            type="submit"
            disabled={busy || code.trim() === ""}
            ref={firstRef}
          >
            {busy ? "正在核对……" : "下一步"}
          </button>
        </div>
      </form>
    );
  } else if (step.name === "address") {
    title = routeTitles[route];
    body = (
      <form onSubmit={submitAddress} className="people-form">
        {inspection !== null ? (
          <p className="people-note">
            对方电脑：{inspection.inviter_host}:{inspection.inviter_port}
            （机主 {shortFingerprint(inspection.owner_fingerprint)}），
            {expiresText(inspection.expires_at)} 前有效。
          </p>
        ) : null}
        <p className="people-note">
          组网地址是这台电脑在 WireGuard 或 n2n
          里的地址，别的电脑靠它找到这台，一般是 10. 或 192.168.
          开头。端口一般不用改，同一台电脑上跑多个 TunnelMinion 时才换一个。
        </p>
        {locked ? (
          <p className="people-note" role="status">
            已按本机现有网关配置：{identity.bind?.host ?? host}:
            {identity.bind?.port ?? port}
          </p>
        ) : (
          <>
            <label>
              本机组网地址
              <input
                list="people-address-candidates"
                value={host}
                onChange={(event) => setHost(event.currentTarget.value)}
                placeholder="例如 10.0.0.2"
              />
              <datalist id="people-address-candidates">
                {identity.address_candidates.map((item) => (
                  <option key={item} value={item} />
                ))}
              </datalist>
            </label>
            <label>
              端口
              <input
                inputMode="numeric"
                value={port}
                onChange={(event) => setPort(event.currentTarget.value)}
              />
            </label>
          </>
        )}
        {route === "join" ? null : (
          <label>
            这台电脑叫什么
            <input
              maxLength={40}
              value={name}
              onChange={(event) => setName(event.currentTarget.value)}
            />
          </label>
        )}
        {route === "friend" ? (
          <label>
            你的名字（朋友那边看到的，可不填）
            <input
              maxLength={40}
              value={myName}
              onChange={(event) => setMyName(event.currentTarget.value)}
            />
          </label>
        ) : null}
        <div className="people-dialog__actions">
          <button
            type="button"
            onClick={() =>
              setStep({ name: route === "first" ? "choose" : "paste" })
            }
          >
            上一步
          </button>
          <button type="submit" disabled={busy} ref={firstRef}>
            {busy ? "请稍候……" : route === "join" ? "加入" : "下一步"}
          </button>
        </div>
      </form>
    );
  } else if (step.name === "show") {
    title = "抄下你的恢复码";
    body = (
      <>
        <p>
          这台电脑坏了或丢了，靠这串恢复码找回你的机主身份。它
          <strong>只显示这一次</strong>
          ，请抄在纸上或存进密码管理器。
        </p>
        <p className="people-code people-code--recovery" aria-label="恢复码">
          {step.code}
        </p>
        <div className="people-dialog__actions">
          <button
            type="button"
            onClick={() => void navigator.clipboard?.writeText(step.code)}
          >
            复制
          </button>
          <button
            type="button"
            ref={firstRef}
            onClick={() => setStep({ name: "confirm", setupId: step.setupId })}
          >
            我已抄好
          </button>
        </div>
      </>
    );
  } else if (step.name === "confirm") {
    title = "再输一遍恢复码";
    body = (
      <form onSubmit={submitConfirm} className="people-form">
        <p>
          为了确认你已经抄好，请把恢复码完整输入一遍（大小写、空格和连字符不影响）。
        </p>
        <label>
          恢复码
          <input
            autoComplete="off"
            spellCheck={false}
            value={typed}
            onChange={(event) => setTyped(event.currentTarget.value)}
          />
        </label>
        <div className="people-dialog__actions">
          <button type="button" onClick={() => void close()}>
            放弃
          </button>
          <button
            type="submit"
            disabled={busy || typed.trim() === ""}
            ref={firstRef}
          >
            {busy ? "正在保存……" : "确认"}
          </button>
        </div>
      </form>
    );
  } else if (step.name === "pair") {
    title = "和朋友配对";
    body = pairOnly ? (
      <>
        <p className="people-note">
          朋友电脑：{inspection?.inviter_host}:{inspection?.inviter_port}（机主{" "}
          {shortFingerprint(inspection?.owner_fingerprint ?? null)}）
        </p>
        <div className="people-dialog__actions">
          <button type="button" onClick={() => void close()}>
            取消
          </button>
          <button
            type="button"
            ref={firstRef}
            disabled={busy}
            onClick={() => void run(pair)}
          >
            {busy ? "正在配对……" : "配对"}
          </button>
        </div>
      </>
    ) : (
      <p role="status">正在和朋友配对……</p>
    );
  } else if (step.name === "done") {
    title = "完成";
    body = (
      <>
        <p role="status">{step.message}</p>
        <p className="people-note">
          要让别的电脑找到这台，本机网关需要运行；如果它已经在运行，请重启一次。
        </p>
        <div className="people-dialog__actions">
          <button type="button" ref={firstRef} onClick={onClose}>
            好的
          </button>
        </div>
      </>
    );
  }

  return (
    <div className="people-dialog-backdrop">
      <div
        aria-labelledby="people-dialog-title"
        aria-modal="true"
        className="people-dialog"
        onKeyDown={handleKeyDown}
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
      >
        <h3 id="people-dialog-title">{title}</h3>
        {body}
        {error === null ? null : (
          <p className="people-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
