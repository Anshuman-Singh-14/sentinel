import { Ban, CircleCheck, CircleX, Clock, LoaderCircle, Timer } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useState } from "react";

import { Badge, JsonViewer, SeverityBadge, cn } from "../../components/ui";
import type { BadgeTone } from "../../components/ui";
import type { Finding, RunStatus, Severity } from "../../types/api";
import { SEVERITIES } from "../../types/api";

const STATUS: Record<RunStatus, { tone: BadgeTone; icon: LucideIcon; label: string }> = {
  QUEUED: { tone: "neutral", icon: Clock, label: "Queued" },
  RUNNING: { tone: "accent", icon: LoaderCircle, label: "Running" },
  COMPLETED: { tone: "ok", icon: CircleCheck, label: "Completed" },
  FAILED: { tone: "fail", icon: CircleX, label: "Failed" },
  CANCELLED: { tone: "warn", icon: Ban, label: "Cancelled" },
  TIMED_OUT: { tone: "fail", icon: Timer, label: "Timed out" },
};

export function RunStatusBadge({ status }: { status: RunStatus }) {
  const s = STATUS[status];
  const Icon = s.icon;
  return (
    <Badge tone={s.tone} data-status={status}>
      <Icon
        size={12}
        aria-hidden="true"
        className={status === "RUNNING" ? "animate-spin" : undefined}
      />
      {s.label}
    </Badge>
  );
}

type StepState = "done" | "current" | "pending" | "bad";

/**
 * QUEUED -> RUNNING -> outcome, as a three-step timeline. `started` tells a
 * run cancelled while still queued (it never ran) from one stopped mid-run.
 */
export function RunTimeline({ status, started }: { status: RunStatus; started: boolean }) {
  const active = status === "QUEUED" || status === "RUNNING";
  const running: StepState =
    status === "QUEUED"
      ? "pending"
      : status === "RUNNING"
        ? "current"
        : started
          ? "done"
          : "pending";
  const steps: Array<{ label: string; state: StepState }> = [
    { label: "Queued", state: status === "QUEUED" ? "current" : "done" },
    { label: "Running", state: running },
    {
      label: STATUS[active ? "COMPLETED" : status].label,
      state: active ? "pending" : status === "COMPLETED" ? "done" : "bad",
    },
  ];
  return (
    <ol className="flex items-center gap-2 text-xs" aria-label="Run progress">
      {steps.map((step, i) => (
        <li key={step.label} className="flex items-center gap-2">
          {i > 0 && <span aria-hidden="true" className="h-px w-6 bg-border-strong" />}
          <span
            aria-current={step.state === "current" ? "step" : undefined}
            className={cn(
              "rounded-full border px-2.5 py-0.5 font-semibold",
              step.state === "done" && "border-ok/60 text-ok",
              step.state === "current" && "border-accent text-accent",
              step.state === "pending" && "border-border text-muted",
              step.state === "bad" && "border-fail/60 text-fail",
            )}
          >
            {step.label}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function SeveritySummary({ counts }: { counts: Record<Severity, number> }) {
  return (
    <ul className="flex flex-wrap gap-2" aria-label="Findings by severity">
      {SEVERITIES.map((severity) => (
        <li key={severity}>
          <SeverityBadge
            severity={severity}
            count={counts[severity] ?? 0}
            className={(counts[severity] ?? 0) === 0 ? "opacity-50" : undefined}
          />
        </li>
      ))}
    </ul>
  );
}

const FINDING_STATUS_TONE: Record<string, BadgeTone> = {
  PASS: "ok",
  FAIL: "fail",
  MISSING: "fail",
  WEAK: "warn",
  DETECTED: "warn",
  ERROR: "fail",
};

/**
 * One finding, in the Educational Translation Engine's order: what it is,
 * why it matters, why this severity, how to fix it, then the evidence.
 */
export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(finding.severity !== "INFO");
  const hasEvidence = Object.keys(finding.evidence).length > 0;
  return (
    <li className="rounded border border-border bg-surface">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-2 px-3 py-2.5 text-left hover:bg-panel-raised"
      >
        <SeverityBadge severity={finding.severity} />
        <Badge tone={FINDING_STATUS_TONE[finding.status] ?? "neutral"}>{finding.status}</Badge>
        <span className="min-w-0 flex-1 text-sm font-semibold">{finding.item}</span>
        <span className="text-[0.65rem] text-muted uppercase">{finding.category}</span>
      </button>
      {open && (
        <div className="flex flex-col gap-3 border-t border-border px-3 py-3 text-sm">
          <section>
            <h4 className="text-xs font-semibold tracking-wider text-muted uppercase">
              What this means
            </h4>
            <p className="mt-1">{finding.explanation}</p>
          </section>
          <section>
            <h4 className="text-xs font-semibold tracking-wider text-muted uppercase">
              Why {finding.severity}
              {finding.confidence !== "HIGH" &&
                ` (confidence: ${finding.confidence.toLowerCase()})`}
            </h4>
            <p className="mt-1 text-muted">{finding.severity_rationale}</p>
          </section>
          <section>
            <h4 className="text-xs font-semibold tracking-wider text-ok uppercase">
              How to fix it
            </h4>
            <p className="mt-1 whitespace-pre-wrap">{finding.remediation}</p>
          </section>
          {finding.references.length > 0 && (
            <section>
              <h4 className="text-xs font-semibold tracking-wider text-muted uppercase">
                References
              </h4>
              {/* Plain text, never links: references are data, and only our
                  own knowledge base is trusted, not every tool's output. */}
              <ul className="mt-1 list-disc pl-5 text-xs text-muted">
                {finding.references.map((ref) => (
                  <li key={ref} className="break-all">
                    {ref}
                  </li>
                ))}
              </ul>
            </section>
          )}
          {hasEvidence && (
            <section>
              <h4 className="mb-1 text-xs font-semibold tracking-wider text-muted uppercase">
                Evidence
              </h4>
              <JsonViewer value={finding.evidence} label={`Evidence for ${finding.item}`} />
            </section>
          )}
        </div>
      )}
    </li>
  );
}
