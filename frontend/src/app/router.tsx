import {
  Navigate,
  Outlet,
  Link,
  useLocation,
  createBrowserRouter,
} from "react-router-dom";

import { MemoriesPage } from "../features/memories";
import { OperationDetailPage, OperationsPage } from "../features/operations";
import { PeoplePage } from "../features/people";
import { IncidentsPage } from "../features/overview";
import { SettingsPage } from "../features/settings";
import { ServiceMapPage } from "../features/service-map/ServiceMapPage";
import { RouteErrorPage } from "./RouteErrorPage";
import { KeychainNotice } from "../shared/keychainNotice";
import { OfflineBanner } from "../shared/offlineBanner";
import { isReadOnlyPreview } from "../shared/previewMode";

// "更多"菜单里的各页；非地图页顶部用同一份清单显示页面标签。
const morePages = [
  { path: "/app/operations", label: "请求记录" },
  { path: "/app/incidents", label: "最近事件" },
  { path: "/app/memories", label: "记忆" },
  { path: "/app/people", label: "电脑与朋友" },
  { path: "/app/settings", label: "设置" },
] as const;

function PageTabs({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="更多页面" className="page-tabs">
      {morePages.map((page) => (
        <Link
          key={page.path}
          to={page.path}
          aria-current={
            pathname === page.path || pathname.startsWith(`${page.path}/`)
              ? "page"
              : undefined
          }
        >
          {page.label}
        </Link>
      ))}
    </nav>
  );
}

function ProductShell() {
  const { pathname } = useLocation();
  const map = pathname === "/app/map";
  return (
    <div className={`product-shell${map ? " product-shell--map" : ""}`}>
      <div className="product-chrome">
        <header className="product-header">
          <h1>TunnelMinion</h1>
          <p className="privacy-note">只连接这台电脑上的 TunnelMinion</p>
          {isReadOnlyPreview() ? (
            <p className="privacy-note" role="status">
              预览模式：只看程序和已有记录，不自动调查，也不能发送问题或执行操作。
            </p>
          ) : null}
        </header>
        <nav aria-label="主要导航" className="primary-navigation">
          <Link to="/app/map" aria-current={map ? "page" : undefined}>
            {map ? "服务地图" : "← 回到地图"}
          </Link>
        </nav>
      </div>
      <main
        className={map ? undefined : "pixel-page"}
        id="main-content"
        tabIndex={-1}
      >
        <OfflineBanner />
        <KeychainNotice />
        {map ? null : <PageTabs pathname={pathname} />}
        <Outlet />
      </main>
    </div>
  );
}

function MapRedirect() {
  const { search, hash } = useLocation();
  return <Navigate replace to={`/app/map${search}${hash}`} />;
}

export const router = createBrowserRouter([
  {
    path: "/app",
    element: <ProductShell />,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <Navigate replace to="map" /> },
      { path: "map", element: <ServiceMapPage /> },
      { path: "overview", element: <MapRedirect /> },
      { path: "chat", element: <MapRedirect /> },
      { path: "incidents", element: <IncidentsPage /> },
      { path: "operations", element: <OperationsPage /> },
      { path: "operations/:operationId", element: <OperationDetailPage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "memories", element: <MemoriesPage /> },
      { path: "people", element: <PeoplePage /> },
    ],
  },
]);
