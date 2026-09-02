import { Link, useRouteError } from "react-router-dom";

export function RouteErrorPage() {
  useRouteError();
  return (
    <main className="product-shell" id="main-content" tabIndex={-1}>
      <section
        aria-labelledby="route-error-title"
        className="surface"
        role="alert"
      >
        <p className="eyebrow">页面暂时不可用</p>
        <h1 id="route-error-title">TunnelMinion 没能打开这个页面</h1>
        <p>已隐藏内部错误详情。你可以回到总览，再刷新一次服务端状态。</p>
        <Link to="/app/overview">返回总览</Link>
      </section>
    </main>
  );
}
