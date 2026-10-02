/**
 * Route guards.
 *
 * These are a usability layer, not a security boundary: the backend enforces
 * authentication and RBAC on every endpoint (ADR 0003, section 6). Hiding a
 * page from a viewer only spares them a screen full of 403s.
 */

import { ShieldX } from "lucide-react";
import { createContext, useContext } from "react";
import type { ReactNode } from "react";
import { Navigate, Outlet, useLocation } from "react-router";

import { Card, Spinner } from "../../components/ui";
import { errorMessage } from "../../lib/api/errors";
import type { Role, User } from "../../types/api";
import { roleAllows } from "../../types/api";
import { useCurrentUser } from "./useAuth";

/**
 * The signed-in user, published by RequireAuth. A context (rather than each
 * component reading the query cache) means the whole subtree sees the same
 * user and unmounts together on logout, instead of some components briefly
 * rendering with no user.
 */
const UserContext = createContext<User | null>(null);

export function FullPageMessage({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-md">{children}</div>
    </main>
  );
}

/** Renders child routes only for an authenticated user; otherwise go to /login. */
export function RequireAuth() {
  const { data: user, isPending, isError, error, refetch } = useCurrentUser();
  const location = useLocation();

  if (isPending) {
    return (
      <FullPageMessage>
        <div className="flex justify-center">
          <Spinner label="Checking your session" />
        </div>
      </FullPageMessage>
    );
  }
  if (isError) {
    // The API is down or misbehaving. That is not "logged out", so do not
    // bounce to the login page; say what happened and offer a retry.
    return (
      <FullPageMessage>
        <Card title="Cannot reach Sentinel">
          <p className="text-sm text-muted">{errorMessage(error)}</p>
          <button
            type="button"
            onClick={() => void refetch()}
            className="mt-4 text-sm text-accent underline"
          >
            Try again
          </button>
        </Card>
      </FullPageMessage>
    );
  }
  if (!user) {
    const next = `${location.pathname}${location.search}${location.hash}`;
    const target = next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`;
    return <Navigate to={target} replace />;
  }
  return (
    <UserContext.Provider value={user}>
      <Outlet />
    </UserContext.Provider>
  );
}

/** The signed-in user. Only valid below <RequireAuth>. */
export function useUser(): User {
  const user = useContext(UserContext);
  if (!user) throw new Error("useUser() called outside an authenticated route");
  return user;
}

/** Renders child routes only when the user's role is at least `role`. */
export function RequireRole({ role }: { role: Role }) {
  const user = useUser();
  if (!roleAllows(user.role, role)) {
    return (
      <Card title="Access denied">
        <div className="flex items-start gap-3 text-sm text-muted">
          <ShieldX size={20} aria-hidden="true" className="shrink-0 text-fail" />
          <p>
            This page needs the <strong className="text-text">{role}</strong> role. You are signed
            in as <strong className="text-text">{user.role}</strong>.
          </p>
        </div>
      </Card>
    );
  }
  return <Outlet />;
}
