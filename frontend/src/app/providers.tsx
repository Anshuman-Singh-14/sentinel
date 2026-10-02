import { QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import type { ReactNode } from "react";

import { ToastProvider, useToast } from "../components/ui";
import { AUTH_QUERY_KEY } from "../features/auth/useAuth";
import { onSessionExpired } from "../lib/api/client";
import type { User } from "../types/api";

/**
 * When the API client gives up on a session (refresh failed), drop every
 * cached response and mark the user anonymous. RequireAuth then redirects to
 * /login with the current page as `next`.
 */
function SessionExpiryHandler() {
  const queryClient = useQueryClient();
  const toast = useToast();

  useEffect(
    () =>
      onSessionExpired(() => {
        const wasSignedIn = Boolean(queryClient.getQueryData<User | null>(AUTH_QUERY_KEY));
        queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== "auth" });
        queryClient.setQueryData(AUTH_QUERY_KEY, null);
        if (wasSignedIn) {
          toast.show({
            tone: "info",
            title: "Session ended",
            description: "Your session expired or was revoked. Please sign in again.",
          });
        }
      }),
    [queryClient, toast],
  );
  return null;
}

export function AppProviders({ client, children }: { client: QueryClient; children: ReactNode }) {
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <SessionExpiryHandler />
        {children}
      </ToastProvider>
    </QueryClientProvider>
  );
}
