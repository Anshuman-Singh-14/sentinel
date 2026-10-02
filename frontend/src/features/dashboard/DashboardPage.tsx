import { ArrowRight } from "lucide-react";
import { Link } from "react-router";

import { Badge, Card, SeverityBadge, Spinner } from "../../components/ui";
import { SEVERITIES } from "../../types/api";
import { useUser } from "../auth/guards";
import { buildToolNavigation } from "../tools/registry";
import { useToolCatalogue } from "../tools/useToolCatalogue";

export function DashboardPage() {
  const user = useUser();
  const catalogue = useToolCatalogue();
  const groups = buildToolNavigation(catalogue.data ?? [], user.role);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">Welcome back, {user.username}</h1>
        <p className="mt-1 text-sm text-muted">
          Every tool translates raw output into plain-language findings with a severity rationale
          and remediation steps.
        </p>
      </div>

      <Card title="Severity scale" eyebrow="How findings are rated">
        <ul className="flex flex-wrap gap-2">
          {SEVERITIES.map((severity) => (
            <li key={severity}>
              <SeverityBadge severity={severity} />
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-muted">
          CVE-based findings use CVSS v3.1 bands; configuration findings follow OWASP, CWE and NIST
          guidance. Each finding states why it got its rating.
        </p>
      </Card>

      <section aria-labelledby="tools-heading" className="flex flex-col gap-3">
        <h2
          id="tools-heading"
          className="text-sm font-semibold tracking-wider text-muted uppercase"
        >
          Tools
        </h2>
        {catalogue.isPending && <Spinner label="Loading tools" />}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {groups.flatMap((group) =>
            group.items.map((item) => {
              const Icon = item.icon;
              return (
                <Card
                  key={item.id}
                  eyebrow={group.label}
                  title={
                    <span className="flex items-center gap-2">
                      <Icon size={16} aria-hidden="true" className="text-accent" />
                      {item.label}
                    </span>
                  }
                  actions={item.tag ? <Badge>{item.tag}</Badge> : undefined}
                >
                  <p className="text-xs text-muted">{item.description}</p>
                  {!item.disabled && (
                    <Link
                      to={item.path}
                      className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-accent hover:underline"
                    >
                      Open <span className="sr-only">{item.label}</span>
                      <ArrowRight size={12} aria-hidden="true" />
                    </Link>
                  )}
                </Card>
              );
            }),
          )}
        </div>
      </section>
    </div>
  );
}
