import { useState } from "react";
import type { FormEvent } from "react";

import { Badge, Button, Card, TextField, useToast } from "../../components/ui";
import { ApiError, errorMessage } from "../../lib/api/errors";
import { formatDateTime } from "../../lib/format";
import { useUser } from "./guards";
import { useChangePassword } from "./useAuth";

export function AccountPage() {
  const user = useUser();
  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <h1 className="text-lg font-semibold">Account</h1>
      <Card title="Profile">
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
          <dt className="text-muted">Username</dt>
          <dd>{user.username}</dd>
          <dt className="text-muted">Role</dt>
          <dd>
            <Badge tone="accent">{user.role}</Badge>
          </dd>
          <dt className="text-muted">Last sign-in</dt>
          <dd>{formatDateTime(user.last_login_at)}</dd>
          <dt className="text-muted">Account created</dt>
          <dd>{formatDateTime(user.created_at)}</dd>
        </dl>
      </Card>
      <ChangePasswordCard />
    </div>
  );
}

function ChangePasswordCard() {
  const change = useChangePassword();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const mismatch = confirm.length > 0 && next !== confirm;

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (mismatch) return;
    change.mutate(
      { current, next },
      {
        onSuccess: () => {
          setCurrent("");
          setNext("");
          setConfirm("");
          toast.show({
            tone: "success",
            title: "Password changed",
            description: "Your other sessions have been signed out.",
          });
        },
        onError: () => setCurrent(""),
      },
    );
  };

  const serverError =
    change.error instanceof ApiError && change.error.code === "password_policy"
      ? change.error.message
      : change.isError
        ? errorMessage(change.error)
        : null;

  return (
    <Card title="Change password">
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        <TextField
          label="Current password"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          hint="12–128 characters. Long passphrases are best; common and breached passwords are rejected."
          value={next}
          onChange={(e) => setNext(e.target.value)}
          maxLength={128}
          required
        />
        <TextField
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          error={mismatch ? "Passwords do not match." : undefined}
          maxLength={128}
          required
        />
        {serverError && (
          <p role="alert" className="text-sm text-fail">
            {serverError}
          </p>
        )}
        <div>
          <Button
            type="submit"
            loading={change.isPending}
            disabled={!current || !next || next !== confirm}
          >
            Update password
          </Button>
        </div>
      </form>
    </Card>
  );
}
