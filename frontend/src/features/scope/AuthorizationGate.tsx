/**
 * Active tools (which send traffic to a target) are gated behind the
 * authorised-use statement (04-security.md section 2). The server enforces
 * it too: this component only explains the requirement and records the
 * user's acceptance, which is audited server-side.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Scale } from "lucide-react";
import { useId, useState } from "react";
import type { ReactNode } from "react";

import { Button, Spinner } from "../../components/ui";
import { scopeApi } from "../../lib/api/endpoints";
import { errorMessage } from "../../lib/api/errors";

export const ACK_QUERY_KEY = ["scope", "acknowledgement"] as const;
export const SCOPE_QUERY_KEY = ["scope"] as const;

export function AuthorizationGate({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const checkboxId = useId();
  const [checked, setChecked] = useState(false);
  const ack = useQuery({
    queryKey: ACK_QUERY_KEY,
    queryFn: ({ signal }) => scopeApi.acknowledgement(signal),
  });
  const accept = useMutation({
    mutationFn: (version: number) => scopeApi.acknowledge(version),
    onSuccess: (data) => queryClient.setQueryData(ACK_QUERY_KEY, data),
    // 409: the statement changed while the page was open; show the new text.
    onError: () => void queryClient.invalidateQueries({ queryKey: ACK_QUERY_KEY }),
  });

  if (ack.isPending) return <Spinner label="Checking authorisation" />;
  if (ack.isError) {
    return (
      <p role="alert" className="text-sm text-fail">
        {errorMessage(ack.error)}
      </p>
    );
  }
  if (ack.data.acknowledged) return <>{children}</>;

  return (
    <section
      aria-labelledby={`${checkboxId}-title`}
      className="flex flex-col gap-3 rounded border border-warn/50 bg-warn/5 p-4"
    >
      <h3
        id={`${checkboxId}-title`}
        className="flex items-center gap-2 text-sm font-semibold text-warn"
      >
        <Scale size={16} aria-hidden="true" />
        Authorised use only
      </h3>
      <p className="text-sm text-muted">
        This tool sends network traffic to the target. Before your first active scan, confirm the
        statement below. Your acceptance is recorded in the audit log.
      </p>
      <blockquote className="border-l-2 border-warn/60 pl-3 text-sm">
        {ack.data.statement}
      </blockquote>
      <label htmlFor={checkboxId} className="flex items-start gap-2 text-sm">
        <input
          id={checkboxId}
          type="checkbox"
          className="mt-0.5 accent-accent"
          checked={checked}
          onChange={(e) => setChecked(e.target.checked)}
        />
        I have read and accept this statement.
      </label>
      {accept.isError && (
        <p role="alert" className="text-sm text-fail">
          {errorMessage(accept.error)}
        </p>
      )}
      <div>
        <Button
          disabled={!checked}
          loading={accept.isPending}
          onClick={() => accept.mutate(ack.data.version)}
        >
          Accept and continue
        </Button>
      </div>
    </section>
  );
}

/** What active tools may target, so users know before they try. */
export function ScopeSummary() {
  const scope = useQuery({
    queryKey: SCOPE_QUERY_KEY,
    queryFn: ({ signal }) => scopeApi.get(signal),
  });
  if (!scope.data) return null;
  return (
    <details className="rounded border border-border bg-surface text-sm">
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold tracking-wider text-muted uppercase">
        Allowed targets ({scope.data.rules.length} rules)
      </summary>
      <ul className="flex flex-col gap-1 border-t border-border px-3 py-2">
        {scope.data.rules.map((rule) => (
          <li key={`${rule.kind}:${rule.value}`} className="flex flex-wrap gap-2">
            <code className="text-accent">
              {rule.kind === "domain" ? `*.${rule.value}` : rule.value}
            </code>
            <span className="text-muted">{rule.description}</span>
          </li>
        ))}
      </ul>
      <p className="border-t border-border px-3 py-2 text-xs text-muted">
        Sentinel's own infrastructure and cloud metadata addresses are always blocked, whatever the
        policy says. Ask an admin to add systems you own or may test.
      </p>
    </details>
  );
}
