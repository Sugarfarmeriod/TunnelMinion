import type { ServiceEntry } from "./api";

/** 首页返回服务器错误：是网页，但在浏览器里打开只会看到报错。 */
export function webPageFailed(service: ServiceEntry): boolean {
  return service.endpoints.some((endpoint) => endpoint.web_failed === true);
}

/** 探测过首页、哪个入口都不是网页（例如只回纯文本、数据库、SSH）；不代表服务不正常。 */
export function withoutWebPage(service: ServiceEntry): boolean {
  return (
    !webPageFailed(service) &&
    service.endpoints.some((endpoint) => endpoint.has_web_page === false) &&
    !service.endpoints.some((endpoint) => endpoint.has_web_page === true)
  );
}
