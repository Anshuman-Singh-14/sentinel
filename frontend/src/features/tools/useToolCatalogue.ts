import { useQuery } from "@tanstack/react-query";

import { toolsApi } from "../../lib/api/endpoints";

export const TOOLS_QUERY_KEY = ["tools"] as const;

/** Backend tool catalogue. Changes only on deploy, so it is cached for longer. */
export function useToolCatalogue() {
  return useQuery({
    queryKey: TOOLS_QUERY_KEY,
    queryFn: ({ signal }) => toolsApi.list(signal),
    staleTime: 10 * 60_000,
  });
}
