import { useQuery } from "@tanstack/react-query";
import { Bell, LogOut, Menu } from "lucide-react";
import { Link, useNavigate } from "react-router";

import { Badge, Button } from "../../components/ui";
import { useUser } from "../../features/auth/guards";
import { useLogout } from "../../features/auth/useAuth";
import { adminApi } from "../../lib/api/endpoints";
import { roleAllows } from "../../types/api";

export const UNACKED_ALERTS_QUERY_KEY = ["admin", "alerts", "unacknowledged"] as const;

function AlertsIndicator() {
  const alerts = useQuery({
    queryKey: UNACKED_ALERTS_QUERY_KEY,
    queryFn: ({ signal }) => adminApi.alerts(true, signal),
    refetchInterval: 60_000,
  });
  const count = alerts.data?.length ?? 0;
  const label =
    count === 0
      ? "No open security alerts"
      : `${count} open security alert${count === 1 ? "" : "s"}`;
  return (
    <Link
      to="/admin/audit?tab=alerts"
      aria-label={label}
      title={label}
      className="relative rounded p-1.5 text-muted hover:bg-panel-raised hover:text-text"
    >
      <Bell size={18} aria-hidden="true" />
      {count > 0 && (
        <span
          aria-hidden="true"
          className="absolute -top-0.5 -right-0.5 min-w-4 rounded-full bg-sev-critical px-1 text-center text-[0.6rem] leading-4 font-bold text-surface"
        >
          {count > 9 ? "9+" : count}
        </span>
      )}
    </Link>
  );
}

export function TopBar({ onOpenMenu }: { onOpenMenu: () => void }) {
  const user = useUser();
  const logout = useLogout();
  const navigate = useNavigate();

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-panel/80 px-4 backdrop-blur">
      <button
        type="button"
        onClick={onOpenMenu}
        aria-label="Open navigation"
        className="rounded p-1.5 text-muted hover:text-text lg:hidden"
      >
        <Menu size={20} aria-hidden="true" />
      </button>
      <p className="hidden text-[0.7rem] tracking-[0.2em] text-muted uppercase sm:block">
        Defensive operations console
      </p>
      <div className="ml-auto flex items-center gap-3">
        {roleAllows(user.role, "admin") && <AlertsIndicator />}
        <div className="flex items-center gap-2 text-sm">
          <span className="max-w-40 truncate">{user.username}</span>
          <Badge tone="accent">{user.role}</Badge>
        </div>
        <Button
          variant="ghost"
          size="sm"
          loading={logout.isPending}
          onClick={() => logout.mutate(undefined, { onSettled: () => navigate("/login") })}
        >
          <LogOut size={14} aria-hidden="true" />
          Sign out
        </Button>
      </div>
    </header>
  );
}
