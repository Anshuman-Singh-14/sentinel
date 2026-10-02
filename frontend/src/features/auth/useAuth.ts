/**
 * Authentication state.
 *
 * The session lives in HttpOnly cookies the frontend cannot read, so "am I
 * logged in?" is answered by `GET /auth/me`. A 401 there (after the client's
 * own refresh attempt) means "anonymous", which is a normal state, not an
 * error. The user object is cached by TanStack Query under `AUTH_QUERY_KEY`.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authApi } from "../../lib/api/endpoints";
import { ApiError } from "../../lib/api/errors";
import type { User } from "../../types/api";

export const AUTH_QUERY_KEY = ["auth", "me"] as const;

async function fetchCurrentUser(signal: AbortSignal): Promise<User | null> {
  try {
    return await authApi.me(signal);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

export function useCurrentUser() {
  return useQuery({
    queryKey: AUTH_QUERY_KEY,
    queryFn: ({ signal }) => fetchCurrentUser(signal),
    staleTime: 5 * 60_000,
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      authApi.login(username, password),
    onSuccess: (session) => {
      // Drop anything cached under a previous identity before showing data.
      queryClient.clear();
      queryClient.setQueryData(AUTH_QUERY_KEY, session.user);
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => authApi.logout(),
    // Clear local state even if the server call fails: the user asked to
    // leave, and the cookies expire on their own.
    onSettled: () => {
      queryClient.clear();
      queryClient.setQueryData(AUTH_QUERY_KEY, null);
    },
  });
}

export function useChangePassword() {
  return useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) =>
      authApi.changePassword(current, next),
  });
}
