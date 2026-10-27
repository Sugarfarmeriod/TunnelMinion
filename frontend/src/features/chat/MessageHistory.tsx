import type { ThreadDetail, ThreadMessage } from "./contracts";

export function MessageHistory({
  compact,
  detail,
  contextLabel,
}: {
  compact: boolean;
  detail: ThreadDetail | null;
  contextLabel?: string;
}) {
  return (
    <section
      aria-label={compact ? "对话记录" : undefined}
      aria-labelledby={compact ? undefined : "chat-messages-title"}
      className="chat-messages"
    >
      {!compact ? <h3 id="chat-messages-title">消息</h3> : null}
      {detail === null || detail.messages.length === 0 ? (
        <p className="chat-empty">这个线程还没有消息。</p>
      ) : (
        <ol>
          {detail.messages.map((message, index) => (
            <MessageItem
              key={`${message.run_id}-${message.role}-${index}`}
              message={message}
              contextLabel={contextLabel}
            />
          ))}
        </ol>
      )}
    </section>
  );
}

function MessageItem({
  message,
  contextLabel,
}: {
  message: ThreadMessage;
  contextLabel?: string;
}) {
  const unchecked =
    message.role === "assistant" && message.answer_checked !== true;
  const inferred =
    message.role === "assistant" &&
    message.answer_checked === true &&
    message.answer_basis === "inferred";
  const marker = "\n\n证据索引（程序生成）：\n";
  const index =
    message.role === "assistant" ? message.content.lastIndexOf(marker) : -1;
  return (
    <li>
      <article className={`chat-message chat-message--${message.role}`}>
        <header>
          <strong>{message.role === "user" ? "你" : "TunnelMinion"}</strong>
          <time dateTime={message.created_at}>
            {formatTimestamp(message.created_at)}
          </time>
        </header>
        {message.role === "user" && contextLabel ? (
          <span className="chat-context">关于：{contextLabel}</span>
        ) : null}
        {inferred ? (
          <span className="chat-basis-badge chat-basis-badge--inferred">
            推断 · 尚未逐条核对
          </span>
        ) : null}
        {unchecked ? (
          <>
            <p>这条旧说明还没有经过事实核对，请不要据此更改设置。</p>
            <details>
              <summary>查看原始说明（未核对）</summary>
              <p className="chat-untrusted-text">{message.content}</p>
            </details>
          </>
        ) : (
          <p className="chat-untrusted-text">
            {index < 0 ? message.content : message.content.slice(0, index)}
          </p>
        )}
        {inferred ? (
          <p className="chat-basis-note">
            这是模型根据本次检查记录得出的判断，程序还没有逐条核对；改设置前请先自己确认。
          </p>
        ) : null}
        {unchecked || index < 0 ? null : (
          <details>
            <summary>查看证据编号</summary>
            <p className="chat-untrusted-text">
              {message.content.slice(index + marker.length)}
            </p>
          </details>
        )}
      </article>
    </li>
  );
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}
