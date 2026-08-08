import {
  NavLink,
  Navigate,
  Outlet,
  createBrowserRouter,
} from "react-router-dom";

import { OverviewPage } from "../features/overview";
import { ChatPage } from "../features/chat";
import { MemoriesPage } from "../features/memories";
import { OperationDetailPage, OperationsPage } from "../features/operations";
import { SettingsPage } from "../features/settings";
import { RouteErrorPage } from "./RouteErrorPage";

const navigation = [
  ["总览", "/app/overview"],
  ["聊天", "/app/chat"],
  ["操作", "/app/operations"],
  ["记忆", "/app/memories"],
  ["设置", "/app/settings"],
] as const;

function ProductShell() {
  return (
    <div className="product-shell">
      <header className="product-header">
        <div>
          <p className="eyebrow">本机控制台</p>
          <h1>TunnelMinion</h1>
        </div>
        <p className="privacy-note">只连接这台电脑上的 TunnelMinion</p>
      </header>
      <nav aria-label="主要导航" className="primary-navigation">
        {navigation.map(([label, path]) => (
          <NavLink key={path} to={path}>
            {label}
          </NavLink>
        ))}
      </nav>
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
      { index: true, element: <Navigate replace to="overview" /> },
      { path: "overview", element: <OverviewPage /> },
      { path: "chat", element: <ChatPage /> },
      { path: "operations", element: <OperationsPage /> },
      {
        path: "operations/:operationId",
        element: <OperationDetailPage />,
      },
      { path: "memories", element: <MemoriesPage /> },
      {
        path: "settings",
        element: <SettingsPage />,
      },
    ],
  },
]);
