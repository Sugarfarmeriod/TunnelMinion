import { useEffect, useState } from "react";
import {
  NavLink,
  Navigate,
  Outlet,
  Link,
  useLocation,
  createBrowserRouter,
} from "react-router-dom";

import { WorkspacePage } from "../features/workspace/WorkspacePage";
import { MemoriesPage } from "../features/memories";
import { OperationDetailPage, OperationsPage } from "../features/operations";
import { SettingsPage } from "../features/settings";
import { ServiceMapPage } from "../features/service-map/ServiceMapPage";
import { RouteErrorPage } from "./RouteErrorPage";
import { isReadOnlyPreview } from "../shared/previewMode";

const navigation = [
  ["服务地图", "/app/map"],
  ["工作台", "/app/overview"],
  ["记忆", "/app/memories"],
  ["设置", "/app/settings"],
] as const;

function ProductShell() {
  const { pathname, search, hash } = useLocation();
  const workspaceActive = /^\/app\/(overview|chat|operations)(\/|$)/.test(
    pathname,
  );
  const [workspacePath, setWorkspacePath] = useState<string | null>(
    workspaceActive ? pathname + search + hash : null,
  );
  useEffect(() => {
    if (workspaceActive) setWorkspacePath(pathname + search + hash);
    else if (pathname !== "/app/settings") setWorkspacePath(null);
  }, [workspaceActive, pathname, search, hash]);
  return (
    <div className="product-shell">
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
          {navigation.map(([label, path]) =>
            path === "/app/overview" ? (
              <Link
                key={path}
                to={
                  pathname === "/app/settings" ? (workspacePath ?? path) : path
                }
                className={workspaceActive ? "active" : undefined}
                aria-current={workspaceActive ? "page" : undefined}
              >
                {label}
              </Link>
            ) : (
              <NavLink key={path} to={path}>
                {label}
              </NavLink>
            ),
          )}
        </nav>
      </div>
      <main id="main-content" tabIndex={-1}>
        <Outlet context={{ workspacePath, setWorkspacePath }} />
      </main>
    </div>
  );
}

export const router = createBrowserRouter([
  {
    path: "/app",
    element: <ProductShell />,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <Navigate replace to="map" /> },
      { path: "map", element: <ServiceMapPage /> },
      {
        element: <WorkspacePage />,
        children: [
          { path: "overview", element: null },
          { path: "chat", element: null },
          { path: "operations", element: <OperationsPage /> },
          { path: "operations/:operationId", element: <OperationDetailPage /> },
          { path: "settings", element: <SettingsPage /> },
        ],
      },
      { path: "memories", element: <MemoriesPage /> },
    ],
  },
]);
