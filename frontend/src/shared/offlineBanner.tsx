import { useQueryClient } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";

/** 浏览器根本没连上本机程序时 fetch 抛 TypeError；后端返回的错误是 ApiError，不算"连不上"。 */
export function isConnectionError(error: unknown): boolean {
  return error instanceof TypeError;
}

/**
 * 本机 TunnelMinion 程序连不上时，所有页面顶部统一提示一次。
 *
 * 只看当前仍处于失败状态的读取；重新读取成功后横幅自动消失。
 */
export function OfflineBanner() {
  const client = useQueryClient();
  const cache = client.getQueryCache();
  const offline = useSyncExternalStore(
    (notify) => cache.subscribe(notify),
    () =>
      cache
        .getAll()
        .some(
          (query) =>
            query.state.status === "error" &&
            isConnectionError(query.state.error),
        ),
  );
  if (!offline) return null;
  return (
    <div className="offline-banner" role="alert">
      <p>
        连不上这台电脑上的 TunnelMinion 程序
        <span>
          页面上的内容可能是旧的。确认这台电脑上的 TunnelMinion
          还开着，再点重试。
        </span>
      </p>
      <button
        className="pixel-button"
        type="button"
        onClick={() =>
          void client.refetchQueries({
            predicate: (query) => query.state.status === "error",
          })
        }
      >
        重试
      </button>
    </div>
  );
}
