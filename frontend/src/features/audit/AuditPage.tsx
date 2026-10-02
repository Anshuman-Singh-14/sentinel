/**
 * Admin audit viewer (03-logging-audit.md section 6).
 *
 * Read-only by construction: the backend grants the app role INSERT/SELECT
 * only on `audit_events`, so nothing on this page can alter history. Event
 * details are untrusted (they can include attacker-chosen usernames, user
 * agents and targets) and are rendered as escaped text only.
 */

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { useSearchParams } from "react-router";

import {
  Badge,
  Button,
  Card,
  DataTable,
  Drawer,
  JsonViewer,
  SeverityBadge,
  Tabs,
  TextField,
  isSeverity,
  useToast,
} from "../../components/ui";
import type { BadgeTone, Column } from "../../components/ui";
import { adminApi } from "../../lib/api/endpoints";
import type { AuditFilters } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";
import { formatDateTime, shortId } from "../../lib/format";
import type { AuditEvent, SecurityAlert, VerifyResponse } from "../../types/api";
import { UNACKED_ALERTS_QUERY_KEY } from "../../app/layout/TopBar";
import { AUDIT_ACTIONS, AUDIT_OUTCOMES } from "./actions";

const OUTCOME_TONE: Record<string, BadgeTone> = {
  SUCCESS: "ok",
  FAILURE: "fail",
  DENIED: "warn",
};

const selectClass =
  "rounded border border-border-strong bg-surface px-3 py-2 text-sm text-text focus:border-accent focus:outline-none";

/** `datetime-local` gives local wall-clock time; the API wants an ISO instant. */
function localInputToIso(value: string): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "alerts" ? "alerts" : "events";

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">Audit log</h1>
        <p className="mt-1 text-sm text-muted">
          Append-only, hash-chained record of every security-relevant action.
        </p>
      </div>
      <VerifyCard />
      <Tabs
        label="Audit sections"
        value={tab}
        onChange={(id) => setParams(id === "alerts" ? { tab: "alerts" } : {}, { replace: true })}
        items={[
          { id: "events", label: "Events", content: <EventsSection /> },
          { id: "alerts", label: "Security alerts", content: <AlertsSection /> },
        ]}
      />
    </div>
  );
}

// --- integrity verification ------------------------------------------------------

function VerifyCard() {
  const toast = useToast();
  const verify = useMutation({
    mutationFn: () => adminApi.verifyAudit(),
    onError: (error) =>
      toast.show({ tone: "error", title: "Verification failed", description: errorMessage(error) }),
  });
  const result: VerifyResponse | undefined = verify.data;

  return (
    <Card
      title="Chain integrity"
      actions={
        <Button
          size="sm"
          variant="secondary"
          loading={verify.isPending}
          onClick={() => verify.mutate()}
        >
          Verify chain
        </Button>
      }
    >
      {!result ? (
        <p className="text-sm text-muted">
          Recomputes every row hash from the genesis value. Any edited, inserted or deleted row
          breaks the chain from that point on.
        </p>
      ) : result.ok ? (
        <div role="status" className="flex items-start gap-3 text-sm">
          <ShieldCheck size={20} aria-hidden="true" className="shrink-0 text-ok" />
          <div>
            <p className="font-semibold text-ok">Chain intact</p>
            <p className="text-muted">
              {result.checked} events checked. Head hash{" "}
              <code className="break-all text-text">{result.head_hash}</code>
            </p>
          </div>
        </div>
      ) : (
        <div role="alert" className="flex items-start gap-3 text-sm">
          <ShieldAlert size={20} aria-hidden="true" className="shrink-0 text-sev-critical" />
          <div>
            <p className="font-semibold text-sev-critical">Chain broken</p>
            <p className="text-muted">
              First broken event: #{result.first_broken_id ?? "?"} ({result.reason ?? "unknown"}).{" "}
              {result.checked} events checked. A CRITICAL security alert has been raised.
            </p>
          </div>
        </div>
      )}
    </Card>
  );
}

// --- events -------------------------------------------------------------------------

interface FilterForm {
  username: string;
  action: string;
  outcome: string;
  securityOnly: boolean;
  since: string;
  until: string;
}

const EMPTY_FORM: FilterForm = {
  username: "",
  action: "",
  outcome: "",
  securityOnly: false,
  since: "",
  until: "",
};

function toFilters(form: FilterForm): AuditFilters {
  return {
    username: form.username.trim() || undefined,
    action: form.action || undefined,
    outcome: form.outcome || undefined,
    security_only: form.securityOnly || undefined,
    since: localInputToIso(form.since),
    until: localInputToIso(form.until),
  };
}

const EVENT_COLUMNS: Column<AuditEvent>[] = [
  {
    id: "time",
    header: "Time",
    cell: (e) => <span className="whitespace-nowrap">{formatDateTime(e.occurred_at)}</span>,
    sortValue: (e) => e.id,
  },
  {
    id: "user",
    header: "Actor",
    cell: (e) => e.username ?? <span className="text-muted">{e.actor_type}</span>,
    sortValue: (e) => e.username ?? "",
  },
  {
    id: "action",
    header: "Action",
    cell: (e) => (
      <span className="inline-flex items-center gap-1.5">
        {e.is_security_event && (
          <>
            <ShieldAlert size={12} aria-hidden="true" className="text-sev-high" />
            <span className="sr-only">Security event:</span>
          </>
        )}
        {e.action}
      </span>
    ),
    sortValue: (e) => e.action,
  },
  {
    id: "outcome",
    header: "Outcome",
    cell: (e) => <Badge tone={OUTCOME_TONE[e.outcome] ?? "neutral"}>{e.outcome}</Badge>,
    sortValue: (e) => e.outcome,
  },
  {
    id: "target",
    header: "Target",
    cell: (e) => <span className="break-all">{e.target ?? "—"}</span>,
  },
  {
    id: "ip",
    header: "Source IP",
    cell: (e) => e.source_ip ?? "—",
  },
];

function EventsSection() {
  const [form, setForm] = useState<FilterForm>(EMPTY_FORM);
  const [filters, setFilters] = useState<AuditFilters>({});
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const events = useInfiniteQuery({
    queryKey: ["admin", "audit", filters],
    queryFn: ({ pageParam, signal }) => adminApi.audit(filters, pageParam, signal),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before_id ?? undefined,
  });
  const rows = events.data?.pages.flatMap((page) => page.events) ?? [];

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFilters(toFilters(form));
  };
  const update = <K extends keyof FilterForm>(key: K, value: FilterForm[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

  return (
    <div className="flex flex-col gap-4">
      <form
        onSubmit={onSubmit}
        aria-label="Filter audit events"
        className="grid gap-3 rounded border border-border bg-panel p-4 sm:grid-cols-2 xl:grid-cols-6"
      >
        <TextField
          label="Username"
          value={form.username}
          maxLength={64}
          onChange={(e) => update("username", e.target.value)}
        />
        <label className="flex flex-col gap-1.5 text-xs font-semibold tracking-wider text-muted uppercase">
          Action
          <select
            className={selectClass}
            value={form.action}
            onChange={(e) => update("action", e.target.value)}
          >
            <option value="">Any</option>
            {AUDIT_ACTIONS.map((action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1.5 text-xs font-semibold tracking-wider text-muted uppercase">
          Outcome
          <select
            className={selectClass}
            value={form.outcome}
            onChange={(e) => update("outcome", e.target.value)}
          >
            <option value="">Any</option>
            {AUDIT_OUTCOMES.map((outcome) => (
              <option key={outcome} value={outcome}>
                {outcome}
              </option>
            ))}
          </select>
        </label>
        <TextField
          label="From"
          type="datetime-local"
          value={form.since}
          onChange={(e) => update("since", e.target.value)}
        />
        <TextField
          label="Until"
          type="datetime-local"
          value={form.until}
          onChange={(e) => update("until", e.target.value)}
        />
        <div className="flex flex-col justify-end gap-3">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.securityOnly}
              onChange={(e) => update("securityOnly", e.target.checked)}
              className="accent-accent"
            />
            Security events only
          </label>
          <div className="flex gap-2">
            <Button type="submit" size="sm">
              Apply
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setForm(EMPTY_FORM);
                setFilters({});
              }}
            >
              Reset
            </Button>
          </div>
        </div>
      </form>

      {events.isError && (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(events.error)}
        </p>
      )}

      <DataTable
        caption="Audit events, newest first"
        columns={EVENT_COLUMNS}
        rows={rows}
        getRowId={(e) => String(e.id)}
        loading={events.isPending}
        emptyMessage="No events match these filters."
        onRowClick={setSelected}
        rowActionLabel={(e) => `Show details for event ${e.id}, ${e.action}`}
        selectedRowId={selected ? String(selected.id) : null}
      />

      {events.hasNextPage && (
        <div>
          <Button
            variant="secondary"
            size="sm"
            loading={events.isFetchingNextPage}
            onClick={() => void events.fetchNextPage()}
          >
            Load older events
          </Button>
        </div>
      )}

      <Drawer
        open={selected !== null}
        title={selected ? `Event #${selected.id} · ${selected.action}` : ""}
        onClose={() => setSelected(null)}
      >
        {selected && <EventDetail event={selected} />}
      </Drawer>
    </div>
  );
}

function EventDetail({ event }: { event: AuditEvent }) {
  const rows: Array<[string, string]> = [
    ["Occurred", formatDateTime(event.occurred_at)],
    [
      "Actor",
      `${event.username ?? "—"} (${event.actor_type}${event.role ? `, ${event.role}` : ""})`,
    ],
    ["Outcome", event.outcome],
    ["Reason", event.reason ?? "—"],
    ["Target", event.target ?? "—"],
    ["Resource", event.resource_type ? `${event.resource_type} ${event.resource_id ?? ""}` : "—"],
    ["Source IP", event.source_ip ?? "—"],
    ["Request ID", event.request_id ?? "—"],
    ["Session", shortId(event.session_id)],
    ["Service", `${event.service} @ ${event.hostname}`],
  ];
  return (
    <div className="flex flex-col gap-4 text-sm">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted">{label}</dt>
            <dd className="break-all">{value}</dd>
          </div>
        ))}
      </dl>
      <section aria-label="Hash chain">
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-muted uppercase">
          Hash chain
        </h3>
        <p className="text-xs break-all">
          <span className="text-muted">prev </span>
          {event.prev_hash}
        </p>
        <p className="text-xs break-all">
          <span className="text-muted">row </span>
          {event.row_hash}
        </p>
      </section>
      <section aria-label="Full event">
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-muted uppercase">
          Full event (redacted at write time)
        </h3>
        <JsonViewer value={event} label="Audit event" defaultExpandDepth={2} />
      </section>
    </div>
  );
}

// --- alerts -------------------------------------------------------------------------

function AlertsSection() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [openOnly, setOpenOnly] = useState(true);

  const alerts = useQuery({
    queryKey: ["admin", "alerts", openOnly ? "unacknowledged" : "all"],
    queryFn: ({ signal }) => adminApi.alerts(openOnly, signal),
  });

  const acknowledge = useMutation({
    mutationFn: (id: string) => adminApi.acknowledgeAlert(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["admin", "alerts"] });
      void queryClient.invalidateQueries({ queryKey: UNACKED_ALERTS_QUERY_KEY });
      toast.show({ tone: "success", title: "Alert acknowledged" });
    },
    onError: (error) =>
      toast.show({
        tone: "error",
        title: "Could not acknowledge",
        description: errorMessage(error),
      }),
  });

  const columns: Column<SecurityAlert>[] = [
    {
      id: "severity",
      header: "Severity",
      cell: (a) =>
        isSeverity(a.severity) ? (
          <SeverityBadge severity={a.severity} />
        ) : (
          <Badge>{a.severity}</Badge>
        ),
    },
    { id: "time", header: "Raised", cell: (a) => formatDateTime(a.created_at) },
    { id: "rule", header: "Rule", cell: (a) => a.rule },
    { id: "message", header: "Message", cell: (a) => a.message },
    {
      id: "ack",
      header: "Status",
      cell: (a) =>
        a.acknowledged_at ? (
          <span className="text-muted">Acknowledged {formatDateTime(a.acknowledged_at)}</span>
        ) : (
          <Button
            size="sm"
            variant="secondary"
            loading={acknowledge.isPending && acknowledge.variables === a.id}
            onClick={() => acknowledge.mutate(a.id)}
          >
            Acknowledge
          </Button>
        ),
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={openOnly}
          onChange={(e) => setOpenOnly(e.target.checked)}
          className="accent-accent"
        />
        Open alerts only
      </label>
      {alerts.isError && (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(alerts.error)}
        </p>
      )}
      <DataTable
        caption="Security alerts, newest first"
        columns={columns}
        rows={alerts.data ?? []}
        getRowId={(a) => a.id}
        loading={alerts.isPending}
        emptyMessage={openOnly ? "No open alerts." : "No alerts have been raised."}
      />
    </div>
  );
}
