import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { isReadOnlyPreview } from "../../shared/previewMode";
import { peersQueryKey } from "../service-map/api";
import { identityQueryKey, loadIdentity } from "./api";
import type { Identity } from "./api";
import { OnboardingDialog, type Route } from "./OnboardingDialog";
import "./people.css";

// 页面不往浏览器存储写任何东西，"以后再说"只在这次打开网页期间有效。
let dismissedThisLoad = false;

/** 本机还没有机主身份时，地图顶部显示三选一。 */
export function WelcomeGate() {
  const queryClient = useQueryClient();
  const preview = isReadOnlyPreview();
  const [dismissed, setDismissed] = useState(dismissedThisLoad);
  // 打开弹窗时记下当时的身份；中途身份建好了也不能半路消失。
  const [open, setOpen] = useState<{ route: Route; identity: Identity } | null>(
    null,
  );
  const query = useQuery({
    queryKey: identityQueryKey,
    queryFn: loadIdentity,
    retry: false,
    enabled: !preview,
  });
  const data = query.data;
  return (
    <>
      {preview || dismissed || data === undefined || data.initialized ? null : (
        <aside
          className="people-welcome"
          aria-labelledby="people-welcome-title"
        >
          <h3 id="people-welcome-title">这台电脑还没有加入任何人的电脑</h3>
          <p>选一个最符合你的情况：</p>
          <div className="people-welcome__choices">
            <button
              type="button"
              className="map-button"
              onClick={() => setOpen({ route: "first", identity: data })}
            >
              这是我的第一台电脑
            </button>
            <button
              type="button"
              className="map-button"
              onClick={() => setOpen({ route: "join", identity: data })}
            >
              加入我的电脑
            </button>
            <button
              type="button"
              className="map-button map-go"
              onClick={() => setOpen({ route: "friend", identity: data })}
            >
              我是朋友，粘贴配对码
            </button>
            <button
              type="button"
              className="map-button"
              onClick={() => {
                dismissedThisLoad = true;
                setDismissed(true);
              }}
            >
              以后再说
            </button>
          </div>
        </aside>
      )}
      {open === null ? null : (
        <OnboardingDialog
          identity={open.identity}
          start={open.route}
          onClose={() => setOpen(null)}
          onChanged={(identity) => {
            queryClient.setQueryData(identityQueryKey, identity);
            void queryClient.invalidateQueries({ queryKey: peersQueryKey });
          }}
        />
      )}
    </>
  );
}
