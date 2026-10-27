import type { FormEvent, RefObject } from "react";

export function ChatComposer({
  question,
  onChange,
  onSubmit,
  disabled,
  sending,
  contextLabel,
  inputRef,
}: {
  question: string;
  onChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  disabled: boolean;
  sending: boolean;
  contextLabel?: string;
  inputRef?: RefObject<HTMLTextAreaElement | null>;
}) {
  return (
    <form className="chat-composer" onSubmit={onSubmit}>
      {contextLabel ? (
        <span className="chat-context">关于：{contextLabel}</span>
      ) : null}
      <label htmlFor="chat-question">问题</label>
      <textarea
        id="chat-question"
        ref={inputRef}
        rows={3}
        maxLength={20_000}
        value={question}
        disabled={disabled}
        placeholder="直接说你的问题……"
        onChange={(event) => onChange(event.currentTarget.value)}
      />
      <button
        className="map-button map-go"
        type="submit"
        disabled={disabled || !question.trim()}
      >
        {sending ? "正在发送……" : "发送问题"}
      </button>
    </form>
  );
}
