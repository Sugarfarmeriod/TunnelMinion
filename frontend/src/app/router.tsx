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
import { RouteErrorPage } from "./RouteErrorPage";

const navigation = [
  ["工作台", "/app"],
  ["记忆", "/app/memories"],
  ["设置", "/app/settings"],
] as const;

function ProductShell() {
  const { pathname } = useLocation();
  const workspaceActive =
    pathname === "/app" ||
    /^\/app\/(overview|chat|operations)(\/|$)/.test(pathname);
  return (
    <div className="product-shell">
      <div className="product-chrome">
        <header className="product-header">
          <h1>TunnelMinion</h1>
          <p className="privacy-note">只连接这台电脑上的 TunnelMinion</p>
        </header>
        <nav aria-label="主要导航" className="primary-navigation">
          {navigation.map(([label, path]) =>
            path === "/app" ? (
              <Link
                key={path}
                to={path}
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
        <Outlet />
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
      {
        element: <WorkspacePage />,
        children: [
          { index: true, element: <Navigate replace to="overview" /> },
          { path: "overview", element: null },
          { path: "chat", element: null },
          { path: "operations", element: <OperationsPage /> },
          { path: "operations/:operationId", element: <OperationDetailPage /> },
        ],
      },
      { path: "memories", element: <MemoriesPage /> },
      {
        path: "settings",
        element: <SettingsPage />,
      },
    ],
  },
]);
