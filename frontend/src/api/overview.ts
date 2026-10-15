import { ApiError, requestJson } from "./client";
import { resourceOverviewSchema } from "./schemas/overview";

export const programOverviewQueryKey = [
  "resource-overview",
  "applications",
] as const;

export async function loadProgramOverview({
  signal,
}: { signal?: AbortSignal } = {}) {
  try {
    return await requestJson("/api/ui/overview", resourceOverviewSchema, {
      signal,
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return requestJson("/api/resources/overview", resourceOverviewSchema, {
        signal,
      });
    }
    throw error;
  }
}
