import { useQueryClient } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";

import { ApiError } from "../api/client";

export const KEYCHAIN_APPROVAL_PENDING = "keychain_approval_pending";

/** 钥匙串在等 Mac 屏幕上的授权框时，后端给的那句提示；其他错误返回 null。 */
export function keychainHint(error: unknown): string | null {
  return error instanceof ApiError && error.code === KEYCHAIN_APPROVAL_PENDING
    ? error.message
    : null;
}

/**
 * 任何一个页面数据因为钥匙串等授权而读不到时，在页面顶部提示主人去 Mac 屏幕上点。
 *
 * 只看当前仍处于失败状态的读取；主人点了允许、重新读取成功后提示自动消失。
 */
export function KeychainNotice() {
  const cache = useQueryClient().getQueryCache();
  const hint = useSyncExternalStore(
    (notify) => cache.subscribe(notify),
    () => {
      for (const query of cache.getAll()) {
        const text =
          query.state.status === "error"
            ? keychainHint(query.state.error)
            : null;
        if (text !== null) return text;
      }
      return null;
    },
  );
  if (hint === null) return null;
  return (
    <p className="keychain-notice" role="alert">
      {hint}
    </p>
  );
}
