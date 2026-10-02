/**
 * Admin scope policy (04-security.md section 2). Every change is a security
 * event in the audit log. The hard denylist is shown for transparency but
 * cannot be edited here: it comes from server settings, by design.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldBan } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";

import { Badge, Button, Card, DataTable, Spinner, TextField, useToast } from "../../components/ui";
import type { Column } from "../../components/ui";
import { scopeApi } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";
import type { ScopeRule } from "../../types/api";
import { SCOPE_QUERY_KEY } from "./AuthorizationGate";

const ADMIN_SCOPE_KEY = ["admin", "scope"] as const;

function AddEntryForm() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [kind, setKind] = useState<ScopeRule["kind"]>("cidr");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const add = useMutation({
    mutationFn: () => scopeApi.add(kind, value, description),
    onSuccess: (rule) => {
      setValue("");
      setDescription("");
      void queryClient.invalidateQueries({ queryKey: ADMIN_SCOPE_KEY });
      void queryClient.invalidateQueries({ queryKey: SCOPE_QUERY_KEY });
      toast.show({ tone: "success", title: `Added ${rule.value} to the scope` });
    },
  });

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (value.trim()) add.mutate();
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-3" aria-label="Add scope entry">
      <div className="grid gap-3 sm:grid-cols-[auto_1fr_1fr]">
        <label className="flex flex-col gap-1.5 text-xs font-semibold tracking-wider text-muted uppercase">
          Type
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as ScopeRule["kind"])}
            className="rounded border border-border-strong bg-surface px-3 py-2 text-sm text-text normal-case focus:border-accent focus:outline-none"
          >
            <option value="cidr">IP / CIDR</option>
            <option value="domain">Domain suffix</option>
          </select>
        </label>
        <TextField
          label={kind === "cidr" ? "Address or range" : "Domain"}
          placeholder={kind === "cidr" ? "192.0.2.0/24" : "example.org"}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          maxLength={253}
          autoComplete="off"
          spellCheck={false}
          error={add.isError ? errorMessage(add.error) : undefined}
        />
        <TextField
          label="Why it is in scope"
          placeholder="Owned test server, written permission ref."
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          maxLength={256}
        />
      </div>
      <p className="text-xs text-muted">
        {kind === "domain"
          ? "Covers the domain and all its subdomains. The resolved addresses must still avoid the protected ranges."
          : "Ranges broader than /8 (IPv4) or /32 (IPv6) are refused."}
      </p>
      <div>
        <Button type="submit" loading={add.isPending} disabled={!value.trim()}>
          Add to scope
        </Button>
      </div>
    </form>
  );
}

export function ScopePage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const scope = useQuery({
    queryKey: ADMIN_SCOPE_KEY,
    queryFn: ({ signal }) => scopeApi.adminGet(signal),
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ADMIN_SCOPE_KEY });
    void queryClient.invalidateQueries({ queryKey: SCOPE_QUERY_KEY });
  };
  const toggle = useMutation({
    mutationFn: (rule: ScopeRule) => scopeApi.setEnabled(rule.id!, !rule.enabled),
    onSuccess: refresh,
    onError: (e) =>
      toast.show({ tone: "error", title: "Update failed", description: errorMessage(e) }),
  });
  const remove = useMutation({
    mutationFn: (rule: ScopeRule) => scopeApi.remove(rule.id!),
    onSuccess: refresh,
    onError: (e) =>
      toast.show({ tone: "error", title: "Delete failed", description: errorMessage(e) }),
  });

  const columns: Column<ScopeRule>[] = [
    {
      id: "value",
      header: "Target",
      cell: (r) => (
        <code className="break-all">{r.kind === "domain" ? `*.${r.value}` : r.value}</code>
      ),
    },
    { id: "kind", header: "Type", cell: (r) => (r.kind === "cidr" ? "IP / CIDR" : "Domain") },
    { id: "description", header: "Reason", cell: (r) => r.description || "—" },
    {
      id: "source",
      header: "Source",
      cell: (r) => <Badge tone={r.source === "builtin" ? "neutral" : "accent"}>{r.source}</Badge>,
    },
    {
      id: "state",
      header: "State",
      cell: (r) =>
        r.source === "builtin" ? (
          <span className="text-muted">Always on</span>
        ) : (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => toggle.mutate(r)}
              aria-label={`${r.enabled ? "Disable" : "Enable"} ${r.value}`}
            >
              {r.enabled ? "Disable" : "Enable"}
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => remove.mutate(r)}
              aria-label={`Remove ${r.value}`}
            >
              Remove
            </Button>
          </div>
        ),
    },
  ];

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold">Scope policy</h1>
        <p className="mt-1 text-sm text-muted">
          Active tools may only target what is listed here. Every change is recorded as a security
          event in the audit log.
        </p>
      </div>

      <Card title="Add an entry">
        <AddEntryForm />
      </Card>

      <Card title="Allowed targets">
        {scope.isPending ? (
          <Spinner label="Loading scope" />
        ) : scope.isError ? (
          <p role="alert" className="text-sm text-fail">
            {errorMessage(scope.error)}
          </p>
        ) : (
          <DataTable
            caption="Scope policy rules"
            columns={columns}
            rows={scope.data.rules}
            getRowId={(r) => r.id ?? `builtin:${r.value}`}
            emptyMessage="No rules."
          />
        )}
      </Card>

      {scope.data?.hard_deny && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <ShieldBan size={16} aria-hidden="true" className="text-fail" />
              Never scanned
            </span>
          }
        >
          <p className="mb-3 text-sm text-muted">
            Sentinel's own networks and reserved ranges (cloud metadata, link-local, multicast). Set
            in server configuration; no policy entry can override them, so a scan can never be
            pointed at Sentinel's database, cache or the cloud provider's metadata service.
          </p>
          <ul className="flex flex-wrap gap-2">
            {scope.data.hard_deny.map((cidr) => (
              <li key={cidr}>
                <code className="rounded border border-fail/40 bg-fail/10 px-1.5 py-0.5 text-xs text-fail">
                  {cidr}
                </code>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
