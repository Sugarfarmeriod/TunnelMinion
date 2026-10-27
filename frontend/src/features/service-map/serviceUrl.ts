import type { ServiceEntry } from "./api";

export function serviceUrl(
  service: ServiceEntry,
  remoteHost?: string | null,
): string | null {
  const endpoint =
    service.endpoints.find((entry) => entry.has_web_page === true) ??
    service.endpoints.find(
      (entry) => entry.protocol === "tcp" && entry.has_web_page !== false,
    );
  if (!endpoint || remoteHost === null) return null;

  const address = remoteHost ?? endpoint.address;
  const ipv6 = address.includes(":");
  const local =
    address === "0.0.0.0" ||
    /^127\./.test(address) ||
    /^(?:0*:){2,7}0*1?$/.test(address) ||
    /^(?:0*:){2,6}ffff:(?:127\.|7f[0-9a-f]{2}:)/i.test(address);
  const host =
    local && remoteHost === undefined
      ? "localhost"
      : ipv6
        ? `[${address}]`
        : address;
  return `http://${host}:${endpoint.port}`;
}
