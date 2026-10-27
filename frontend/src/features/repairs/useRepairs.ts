import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { loadRepairs, repairsQueryKey } from "./api";

export function useRepairs(nodeId?: string) {
  const query = useQuery({
    queryKey: repairsQueryKey,
    queryFn: loadRepairs,
    refetchInterval: 5_000,
  });
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const local = (query.data?.repairs ?? []).filter(
    (repair) => repair.node_id === nodeId,
  );
  const pending = local.filter(
    (repair) =>
      repair.status === "awaiting_authorization" &&
      repair.approval_expires_at !== null &&
      Date.parse(repair.approval_expires_at) > now,
  );
  return { ...query, local, pending };
}
