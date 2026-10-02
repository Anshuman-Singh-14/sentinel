import { ShieldHalf } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router";

import { Button, Spinner, TextField } from "../../components/ui";
import { ApiError, errorMessage } from "../../lib/api/errors";
import { safeRedirectPath } from "../../lib/safeRedirect";
import { FullPageMessage } from "./guards";
import { useCurrentUser, useLogin } from "./useAuth";

function loginErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    // The server deliberately returns one message for every credential
    // failure (no user enumeration); show it as-is.
    if (error.code === "rate_limited") {
      return "Too many sign-in attempts. Wait a minute and try again.";
    }
    if (error.code === "csrf_failed") {
      return "Sign-in was blocked by a cross-site request check. Reload the page and try again.";
    }
  }
  return errorMessage(error);
}

export function LoginPage() {
  const [params] = useSearchParams();
  const next = safeRedirectPath(params.get("next"));
  const navigate = useNavigate();
  const { data: user, isPending } = useCurrentUser();
  const login = useLogin();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  if (isPending) {
    return (
      <FullPageMessage>
        <div className="flex justify-center">
          <Spinner label="Checking your session" />
        </div>
      </FullPageMessage>
    );
  }
  if (user) return <Navigate to={next} replace />;

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    login.mutate(
      { username: username.trim(), password },
      {
        onSuccess: () => navigate(next, { replace: true }),
        // Never keep a rejected password around in state.
        onError: () => setPassword(""),
      },
    );
  };

  return (
    <FullPageMessage>
      <div className="rounded-md border border-border bg-panel p-6 shadow-xl shadow-black/50">
        <div className="mb-6 flex items-center gap-3">
          <ShieldHalf size={32} aria-hidden="true" className="text-accent" />
          <div>
            <h1 className="text-xl font-bold tracking-[0.3em] text-accent uppercase">Sentinel</h1>
            <p className="text-xs text-muted">Defensive security console</p>
          </div>
        </div>
        <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
          <TextField
            label="Username"
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            maxLength={64}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <TextField
            label="Password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={1024}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {login.isError && (
            <p
              role="alert"
              className="rounded border border-fail/50 bg-fail/10 p-2 text-sm text-fail"
            >
              {loginErrorText(login.error)}
            </p>
          )}
          <Button type="submit" loading={login.isPending} disabled={!username.trim() || !password}>
            Sign in
          </Button>
        </form>
        <p className="mt-6 text-xs text-muted">
          Authorised use only. Every action is attributed to your account in a tamper-evident audit
          log.
        </p>
      </div>
    </FullPageMessage>
  );
}
