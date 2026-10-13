import { ApiError, requestJson } from "./client";
import { resourceOverviewSchema } from "./schemas/overview";

export const programOverviewQueryKey = [
  "resource-overview",
  "applications",
] as const;

export async function loadProgramOverview() {
  try {
    return await requestJson("/api/ui/overview", resourceOverviewSchema);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return requestJson("/api/resources/overview", resourceOverviewSchema);
    }
    throw error;
  }
}
