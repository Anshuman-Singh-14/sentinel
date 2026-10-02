import { QueryClient } from "@tanstack/react-query";

import { ApiError, NetworkError } from "./api/errors";

/**
 * Retry only failures that might succeed a moment later: network errors and
 * 5xx. Retrying a 4xx (forbidden, validation, not found) only repeats a
 * request the server has already rejected, and retrying a 429 makes it worse.
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false;
  if (error instanceof NetworkError) return true;
  if (error instanceof ApiError && error.status !== undefined) return error.status >= 500;
  return false;
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        staleTime: 30_000,
        refetchOnWindowFocus: false,
      },
      mutations: { retry: false },
    },
  });
}
