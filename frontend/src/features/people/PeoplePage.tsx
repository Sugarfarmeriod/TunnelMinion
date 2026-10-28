import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useRef, useState } from "react";

import { isReadOnlyPreview } from "../../shared/previewMode";
import { useDialogFocusTrap } from "../../shared/useDialogFocusTrap";
import { peersQueryKey } from "../service-map/api";
import {
  closeDevicePermission,
  identityQueryKey,
  inviteDevice,
  inviteFriend,
  loadIdentity,
  removeDevice,
  removeFriend,
  renameFriend,
  setFriendBorrowing,
  setLegacyProxyApproval,
  shortFingerprint,
} from "./api";
import type {
  DevicePermissionName,
  Identity,
  IssuedCode,
  OwnDevice,
  PushResult,
} from "./api";
import { OnboardingDialog, readableError } from "./OnboardingDialog";
import "./people.css";

const permissionLabels: Record<DevicePermissionName, string> = {
  allow_delegation: "允许提问",
  allow_model_borrowing: "允许借模型",
  allow_proxy_repair_approval: "允许替我批准修复",
};

const platformLabels = { windows: "Windows", macos: "macOS", linux: "Linux" };

type Confirm = {
  title: string;
  description: string;
  label: string;
  action: () => Promise<PushResult | Identity>;
};

function Dialog({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const { dialogRef, handleKeyDown } = useDialogFocusTrap<HTMLDivElement>({
    escapeDisabled: false,
    initialFocusRef: closeRef,
    onEscape: onClose,
    returnFocus: [],
  });
  return (
    <div className="people-dialog-backdrop">
      <div
        aria-labelledby="people-small-dialog-title"
        aria-modal="true"
        className="people-dialog"
        onKeyDown={handleKeyDown}
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
      >
        <h3 id="people-small-dialog-title">{title}</h3>
        {children}
        <div className="people-dialog__actions">
          <button type="button" ref={closeRef} onClick={onClose}>
            关闭
          </button>
        </div>
      </div>
    </div>
  );
}

function CodeView({
  issued,
  kind,
}: {
  issued: IssuedCode;
  kind: "owner" | "friend";
}) {
  const [copied, setCopied] = useState(false);
  return (
    <>
      <p>
        {kind === "owner"
          ? "在新电脑上打开 TunnelMinion 网页，选“加入我的电脑”，把下面这串加入码粘贴进去。"
          : "把下面这串配对码发给朋友。朋友打开 TunnelMinion 网页，选“我是朋友，粘贴配对码”。"}
      </p>
      <p
        className="people-code"
        aria-label={kind === "owner" ? "加入码" : "配对码"}
      >
        {issued.code}
      </p>
      <p className="people-note">
        24 小时内有效，只能用一次（
        {new Date(issued.expires_at).toLocaleString("zh-CN", {
          hour12: false,
        })}{" "}
        前）。
      </p>
      <button
        type="button"
        onClick={() =>
          void navigator.clipboard
            ?.writeText(issued.code)
            .then(() => setCopied(true))
            .catch(() => setCopied(false))
        }
      >
        {copied ? "已复制" : "复制"}
      </button>
    </>
  );
}

export function PeoplePage() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: identityQueryKey,
    queryFn: loadIdentity,
    retry: false,
  });
  const [issued, setIssued] = useState<{
    kind: "owner" | "friend";
    value: IssuedCode;
  } | null>(null);
  const [friendName, setFriendName] = useState("");
  const [onboarding, setOnboarding] = useState<"welcome" | "pair" | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [renaming, setRenaming] = useState<{
    fingerprint: string;
    name: string;
  } | null>(null);
  const [notice, setNotice] = useState<{
    kind: "ok" | "error";
    text: string;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const preview = isReadOnlyPreview();

  function refresh(identity?: Identity) {
    if (identity !== undefined)
      queryClient.setQueryData(identityQueryKey, identity);
    void queryClient.invalidateQueries({ queryKey: identityQueryKey });
    void queryClient.invalidateQueries({ queryKey: peersQueryKey });
  }

  async function run(
    action: () => Promise<PushResult | Identity | void>,
    done: string,
  ) {
    setBusy(true);
    setNotice(null);
    try {
      const result = await action();
      const unreached =
        result !== undefined && "unreached" in result ? result.unreached : [];
      setNotice({
        kind: "ok",
        text:
          unreached.length === 0
            ? done
            : `${done} 这次没推到 ${unreached.join("、")}，下次接触时会同步。`,
      });
      refresh(
        result !== undefined && "initialized" in result ? result : undefined,
      );
    } catch (failure) {
      setNotice({ kind: "error", text: readableError(failure) });
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  }

  async function issue(kind: "owner" | "friend") {
    setBusy(true);
    setNotice(null);
    try {
      const value =
        kind === "owner"
          ? await inviteDevice()
          : await inviteFriend(
              friendName.trim() === "" ? undefined : friendName.trim(),
            );
      setIssued({ kind, value });
    } catch (failure) {
      setNotice({ kind: "error", text: readableError(failure) });
    } finally {
      setBusy(false);
    }
  }

  const identity = query.data;
  if (identity === undefined) {
    return (
      <section className="people-page surface" aria-labelledby="people-title">
        <h2 id="people-title">电脑与朋友</h2>
        {query.isPending ? (
          <p role="status">正在读取……</p>
        ) : (
          <div role="alert">
            <p>{readableError(query.error)}</p>
            <button type="button" onClick={() => void query.refetch()}>
              重新读取
            </button>
          </div>
        )}
      </section>
    );
  }

  const canManage = identity.initialized && identity.has_owner_key && !preview;
  const ownerOnly = identity.has_owner_key
    ? null
    : "去持有机主密钥的那台电脑上操作。";

  function deviceRow(device: OwnDevice) {
    return (
      <li key={device.node_id} className="people-row">
        <div className="people-row__main">
          <strong>{device.display_name}</strong>
          {device.is_local ? (
            <span className="people-tag">这台电脑</span>
          ) : null}
          <span className="people-muted">
            {device.platform === null
              ? ""
              : `${platformLabels[device.platform]} · `}
            {device.host}:{device.port}
          </span>
        </div>
        {device.is_local ? null : (
          <div className="people-row__actions">
            {(Object.keys(permissionLabels) as DevicePermissionName[]).map(
              (name) => (
                <label key={name} className="people-switch">
                  <input
                    type="checkbox"
                    checked={device.permissions[name]}
                    disabled={busy || preview || !device.permissions[name]}
                    onChange={() =>
                      setConfirm({
                        title: `关掉“${permissionLabels[name]}”`,
                        description: `关掉后，${device.display_name} 在这台电脑上就不能再${permissionLabels[name].replace("允许", "")}。这个开关关掉后在网页和命令行都不能再打开。`,
                        label: "关掉",
                        action: () =>
                          closeDevicePermission(device.node_id, name),
                      })
                    }
                  />
                  {permissionLabels[name]}
                </label>
              ),
            )}
            <button
              type="button"
              className="people-danger"
              disabled={busy || !canManage}
              title={ownerOnly ?? undefined}
              onClick={() =>
                setConfirm({
                  title: `移除 ${device.display_name}`,
                  description:
                    "移除后，其他电脑一同步就不再信任它。被偷或丢失的电脑请改用命令行换机主密钥。",
                  label: "移除",
                  action: () => removeDevice(device.node_id),
                })
              }
            >
              移除
            </button>
          </div>
        )}
      </li>
    );
  }

  return (
    <section className="people-page surface" aria-labelledby="people-title">
      <header className="people-header">
        <div>
          <p className="eyebrow">只在这台电脑上操作</p>
          <h2 id="people-title">电脑与朋友</h2>
        </div>
        <button
          type="button"
          onClick={() => void query.refetch()}
          disabled={query.isFetching}
        >
          {query.isFetching ? "正在刷新……" : "刷新"}
        </button>
      </header>

      {notice === null ? null : (
        <p
          className={notice.kind === "ok" ? "people-ok" : "people-error"}
          role={notice.kind === "ok" ? "status" : "alert"}
        >
          {notice.text}
        </p>
      )}

      {!identity.initialized ? (
        <article className="people-card">
          <h3>这台电脑还没有机主身份</h3>
          <p>建立自己的身份、加入你已有的电脑，或者用朋友给的配对码加入。</p>
          <button
            type="button"
            disabled={preview}
            onClick={() => setOnboarding("welcome")}
          >
            开始设置
          </button>
        </article>
      ) : (
        <>
          <article className="people-card" aria-labelledby="people-me">
            <h3 id="people-me">我是谁</h3>
            {identity.removed ? (
              <p className="people-error" role="alert">
                这台电脑已经被移出“我的电脑”，不再和其他电脑互信。要重新加入，请在命令行运行
                <code> tunnelminion owner join &lt;加入码&gt; --reset</code>。
              </p>
            ) : null}
            <dl className="people-facts">
              <div>
                <dt>机主</dt>
                <dd>{shortFingerprint(identity.owner_fingerprint)}</dd>
              </div>
              <div>
                <dt>这台电脑持有机主密钥</dt>
                <dd>{identity.has_owner_key ? "是" : "否"}</dd>
              </div>
              <div>
                <dt>本机组网地址</dt>
                <dd>
                  {identity.bind === null
                    ? "未配置"
                    : `${identity.bind.host}:${identity.bind.port}`}
                </dd>
              </div>
            </dl>
          </article>

          <article className="people-card" aria-labelledby="people-invite">
            <h3 id="people-invite">加电脑、邀请朋友</h3>
            {ownerOnly === null ? null : (
              <p className="people-note">{ownerOnly}</p>
            )}
            <div className="people-actions">
              <button
                type="button"
                disabled={busy || !canManage}
                onClick={() => void issue("owner")}
              >
                加一台我的电脑
              </button>
              <label>
                朋友那边看到的我的名字（可不填）
                <input
                  maxLength={40}
                  value={friendName}
                  disabled={!canManage}
                  onChange={(event) => setFriendName(event.currentTarget.value)}
                />
              </label>
              <button
                type="button"
                disabled={busy || !canManage}
                onClick={() => void issue("friend")}
              >
                邀请朋友
              </button>
              <button
                type="button"
                disabled={busy || !canManage}
                onClick={() => setOnboarding("pair")}
              >
                粘贴朋友的配对码
              </button>
            </div>
          </article>

          <article className="people-card" aria-labelledby="people-devices">
            <h3 id="people-devices">
              我的电脑（{identity.devices.length} 台）
            </h3>
            <p className="people-note">
              三个开关是这台电脑对那台电脑的限制，只能关掉，不能再打开。
            </p>
            <ul className="people-list">{identity.devices.map(deviceRow)}</ul>
          </article>

          <article className="people-card" aria-labelledby="people-friends">
            <h3 id="people-friends">朋友（{identity.friends.length} 位）</h3>
            {identity.friends.length === 0 ? (
              <p className="people-muted">还没有朋友。点上面的“邀请朋友”。</p>
            ) : (
              <ul className="people-list">
                {identity.friends.map((friend) => (
                  <li key={friend.owner_fingerprint} className="people-row">
                    <div className="people-row__main">
                      <strong>{friend.display_name}</strong>
                      <span className="people-muted">
                        机主 {shortFingerprint(friend.owner_fingerprint)} ·{" "}
                        {friend.devices
                          .map((device) => device.display_name)
                          .join("、") || "暂时没有电脑"}
                      </span>
                      {friend.conflicting_devices.map((node) => (
                        <span key={node} className="people-error">
                          {node.slice(0, 13)}…：和其他朋友的电脑编号冲突，暂不认
                        </span>
                      ))}
                    </div>
                    <div className="people-row__actions">
                      <label className="people-switch">
                        <input
                          type="checkbox"
                          checked={friend.allow_model_borrowing}
                          disabled={busy || !canManage}
                          onChange={(event) => {
                            const allowed = event.currentTarget.checked;
                            void run(
                              () =>
                                setFriendBorrowing(
                                  friend.owner_fingerprint,
                                  allowed,
                                ),
                              allowed
                                ? "已允许借我的模型。"
                                : "已关闭借我的模型。",
                            );
                          }}
                        />
                        允许借我的模型
                      </label>
                      <button
                        type="button"
                        disabled={busy || !canManage}
                        onClick={() =>
                          setRenaming({
                            fingerprint: friend.owner_fingerprint,
                            name: friend.display_name,
                          })
                        }
                      >
                        改名
                      </button>
                      <button
                        type="button"
                        className="people-danger"
                        disabled={busy || !canManage}
                        onClick={() =>
                          setConfirm({
                            title: `移除朋友 ${friend.display_name}`,
                            description:
                              "移除后，他的电脑不能再向我的电脑提问。以后想再连，要重新邀请。",
                            label: "移除",
                            action: () =>
                              removeFriend(friend.owner_fingerprint),
                          })
                        }
                      >
                        移除
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <p className="people-note">
              朋友只能提问、看结论，永远不能替我批准修复。
            </p>
          </article>
        </>
      )}

      {identity.legacy_peers.length === 0 ? null : (
        <article className="people-card" aria-labelledby="people-legacy">
          <h3 id="people-legacy">旧式配对</h3>
          <p className="people-note">
            用老邀请码配过对的电脑。可以改用“邀请朋友”重新按人配对。开关改动后重启
            TunnelMinion 生效。
          </p>
          <ul className="people-list">
            {identity.legacy_peers.map((peer) => (
              <li key={peer.node_id} className="people-row">
                <div className="people-row__main">
                  <strong>{peer.display_name}</strong>
                  <span className="people-muted">
                    {peer.host}:{peer.port}
                  </span>
                </div>
                <label className="people-switch">
                  <input
                    type="checkbox"
                    checked={peer.allow_proxy_repair_approval}
                    disabled={busy || preview}
                    onChange={(event) => {
                      const allowed = event.currentTarget.checked;
                      void run(
                        () => setLegacyProxyApproval(peer.node_id, allowed),
                        "已保存，重启 TunnelMinion 后生效。",
                      );
                    }}
                  />
                  允许替我批准修复
                </label>
              </li>
            ))}
          </ul>
        </article>
      )}

      <article className="people-card" aria-labelledby="people-cli">
        <h3 id="people-cli">只在命令行做的事</h3>
        <ul className="people-cli">
          <li>
            持有机主密钥的电脑坏了或丢了：在任意一台我的电脑上运行
            <code>tunnelminion owner recover</code>
            ，输入恢复码换一把新的机主密钥。
          </li>
          <li>
            清掉这台电脑的身份重新开始：
            <code>tunnelminion owner init --reset</code>。
          </li>
          <li>
            把旧式配对逐条迁移：<code>tunnelminion peers migrate</code>。
          </li>
        </ul>
      </article>

      {onboarding === null ? null : (
        <OnboardingDialog
          identity={identity}
          start={onboarding === "pair" ? "friend" : undefined}
          onClose={() => {
            setOnboarding(null);
            refresh();
          }}
          onChanged={(value) => refresh(value)}
        />
      )}

      {issued === null ? null : (
        <Dialog
          title={issued.kind === "owner" ? "加入码" : "配对码"}
          onClose={() => setIssued(null)}
        >
          <CodeView issued={issued.value} kind={issued.kind} />
        </Dialog>
      )}

      {renaming === null ? null : (
        <Dialog title="给朋友改名" onClose={() => setRenaming(null)}>
          <form
            className="people-form"
            onSubmit={(event) => {
              event.preventDefault();
              const value = renaming;
              setRenaming(null);
              void run(
                () => renameFriend(value.fingerprint, value.name.trim()),
                "已改名。",
              );
            }}
          >
            <label>
              新名字
              <input
                maxLength={40}
                value={renaming.name}
                onChange={(event) =>
                  setRenaming({ ...renaming, name: event.currentTarget.value })
                }
              />
            </label>
            <button type="submit" disabled={renaming.name.trim() === ""}>
              保存
            </button>
          </form>
        </Dialog>
      )}

      {confirm === null ? null : (
        <Dialog title={confirm.title} onClose={() => setConfirm(null)}>
          <p>{confirm.description}</p>
          <button
            type="button"
            className="people-danger"
            disabled={busy}
            onClick={() => void run(confirm.action, "已完成。")}
          >
            {busy ? "请稍候……" : confirm.label}
          </button>
        </Dialog>
      )}
    </section>
  );
}
