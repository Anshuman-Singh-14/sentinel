import {
  Crosshair,
  History,
  LayoutDashboard,
  Lock,
  ScrollText,
  ShieldHalf,
  UserCog,
} from "lucide-react";
import { NavLink } from "react-router";

import { Badge, cn, Spinner } from "../../components/ui";
import { useUser } from "../../features/auth/guards";
import { buildToolNavigation } from "../../features/tools/registry";
import type { NavGroup, NavItem } from "../../features/tools/registry";
import { useToolCatalogue } from "../../features/tools/useToolCatalogue";
import { roleAllows } from "../../types/api";
import { StatusArea } from "./StatusArea";

const linkBase =
  "flex items-center gap-2.5 rounded px-2.5 py-1.5 text-sm transition-colors border-l-2";

function NavEntry({ item, onNavigate }: { item: NavItem; onNavigate?: () => void }) {
  const Icon = item.icon;
  const content = (
    <>
      <Icon size={16} aria-hidden="true" className="shrink-0" />
      <span className="min-w-0 flex-1 truncate">{item.label}</span>
      {item.locked && (
        <>
          <Lock size={12} aria-hidden="true" />
          <span className="sr-only">(view only: requires a higher role to run)</span>
        </>
      )}
      {item.tag && (
        <Badge tone={item.tag === "active" ? "warn" : "neutral"} className="text-[0.6rem]">
          {item.tag}
        </Badge>
      )}
    </>
  );
  if (item.disabled) {
    return (
      <span
        aria-disabled="true"
        title={item.description}
        className={cn(linkBase, "cursor-not-allowed border-transparent text-muted/80")}
      >
        {content}
      </span>
    );
  }
  return (
    <NavLink
      to={item.path}
      end
      title={item.description}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          linkBase,
          isActive
            ? "border-accent bg-accent/10 text-accent"
            : "border-transparent text-muted hover:bg-panel-raised hover:text-text",
        )
      }
    >
      {content}
    </NavLink>
  );
}

function Group({ group, onNavigate }: { group: NavGroup; onNavigate?: () => void }) {
  const headingId = `nav-group-${group.id.replace(/[^a-z0-9]/gi, "-")}`;
  return (
    <section aria-labelledby={headingId} className="flex flex-col gap-0.5">
      <h2
        id={headingId}
        className="px-2.5 pt-4 pb-1 text-[0.65rem] font-semibold tracking-[0.2em] text-muted uppercase"
      >
        {group.label}
      </h2>
      {group.note && <p className="px-2.5 pb-1 text-[0.65rem] text-ok">{group.note}</p>}
      <ul className="flex flex-col gap-0.5">
        {group.items.map((item) => (
          <li key={item.id}>
            <NavEntry item={item} onNavigate={onNavigate} />
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const user = useUser();
  const catalogue = useToolCatalogue();
  const toolGroups = buildToolNavigation(catalogue.data ?? [], user.role);

  const adminGroup: NavGroup = {
    id: "admin",
    label: "Administration",
    items: [
      { id: "admin:audit", label: "Audit log", path: "/admin/audit", icon: ScrollText },
      { id: "admin:scope", label: "Scope policy", path: "/admin/scope", icon: Crosshair },
    ],
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 border-b border-border px-4 py-4">
        <ShieldHalf size={24} aria-hidden="true" className="text-accent" />
        <span className="text-base font-bold tracking-[0.3em] text-accent uppercase">Sentinel</span>
      </div>
      <nav aria-label="Main" className="flex-1 overflow-y-auto px-2 py-3">
        <ul className="flex flex-col gap-0.5">
          <li>
            <NavEntry
              item={{ id: "dashboard", label: "Dashboard", path: "/", icon: LayoutDashboard }}
              onNavigate={onNavigate}
            />
          </li>
          <li>
            <NavEntry
              item={{ id: "runs", label: "Run history", path: "/runs", icon: History }}
              onNavigate={onNavigate}
            />
          </li>
        </ul>
        {toolGroups.map((group) => (
          <Group key={group.id} group={group} onNavigate={onNavigate} />
        ))}
        {catalogue.isPending && (
          <div className="px-2.5 pt-4">
            <Spinner label="Loading tools" />
          </div>
        )}
        {catalogue.isError && (
          <p role="alert" className="px-2.5 pt-4 text-xs text-fail">
            Could not load backend tools.
          </p>
        )}
        {roleAllows(user.role, "admin") && <Group group={adminGroup} onNavigate={onNavigate} />}
        <ul className="mt-4 flex flex-col gap-0.5 border-t border-border pt-3">
          <li>
            <NavEntry
              item={{ id: "account", label: "Account", path: "/account", icon: UserCog }}
              onNavigate={onNavigate}
            />
          </li>
        </ul>
      </nav>
      <StatusArea />
    </div>
  );
}
