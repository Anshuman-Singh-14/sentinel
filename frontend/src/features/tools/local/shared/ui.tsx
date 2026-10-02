import { BookOpen, Check, Copy, MonitorSmartphone } from "lucide-react";
import { useId, useState } from "react";
import type { ReactNode, TextareaHTMLAttributes } from "react";

import { SeverityBadge, cn } from "../../../../components/ui";
import type { LocalFinding } from "./findings";

/**
 * The privacy promise, shown on every local tool and kept visible while
 * scrolling (02-modules.md, shared rules).
 */
export function LocalOnlyBadge() {
  return (
    <p
      role="note"
      className="inline-flex items-center gap-2 rounded border border-ok/50 bg-ok/10 px-2.5 py-1 text-xs font-semibold text-ok"
    >
      <MonitorSmartphone size={14} aria-hidden="true" />
      Runs locally — nothing leaves your browser
    </p>
  );
}

export function LocalToolLayout({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <div className="sticky -top-4 z-10 -mx-4 flex flex-wrap items-start justify-between gap-3 border-b border-border bg-surface/95 px-4 py-3 backdrop-blur lg:-top-6 lg:-mx-6 lg:px-6">
        <div className="min-w-0">
          <p className="text-[0.7rem] font-semibold tracking-[0.2em] text-muted uppercase">
            Local utility
          </p>
          <h1 className="text-lg font-semibold">{title}</h1>
          <p className="mt-0.5 text-sm text-muted">{description}</p>
        </div>
        <LocalOnlyBadge />
      </div>
      {children}
    </div>
  );
}

/** Collapsible "learn more" panel, using native <details> for free accessibility. */
export function Explainer({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details open={defaultOpen} className="group rounded-md border border-border bg-panel">
      <summary className="flex cursor-pointer items-center gap-2 px-4 py-3 text-sm font-semibold text-accent select-none">
        <BookOpen size={16} aria-hidden="true" />
        {title}
      </summary>
      <div className="flex flex-col gap-2 border-t border-border px-4 py-3 text-sm leading-relaxed text-muted [&_strong]:text-text">
        {children}
      </div>
    </details>
  );
}

/** Banner for the one thing a user must not get wrong. */
export function Callout({
  tone = "warn",
  children,
}: {
  tone?: "warn" | "fail" | "info";
  children: ReactNode;
}) {
  const tones = {
    warn: "border-warn/60 bg-warn/10 text-warn",
    fail: "border-fail/60 bg-fail/10 text-fail",
    info: "border-accent/60 bg-accent/10 text-accent",
  };
  return (
    <div role="note" className={cn("rounded border px-3 py-2 text-sm font-semibold", tones[tone])}>
      {children}
    </div>
  );
}

interface TextAreaFieldProps extends Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id"> {
  label: string;
  hint?: ReactNode;
  error?: ReactNode;
}

/**
 * Text area for sensitive input. Autocomplete, spellcheck and autocorrect are
 * off: browser spellcheck services can send the text to a remote server.
 */
export function TextAreaField({ label, hint, error, className, ...rest }: TextAreaFieldProps) {
  const id = useId();
  const describedBy = [hint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean);
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <label htmlFor={id} className="text-xs font-semibold tracking-wider text-muted uppercase">
        {label}
      </label>
      <textarea
        id={id}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy.join(" ") || undefined}
        className={cn(
          "min-h-24 resize-y rounded border bg-surface px-3 py-2 text-sm break-all text-text",
          "focus:border-accent focus:outline-none",
          error ? "border-fail" : "border-border-strong",
        )}
        {...rest}
      />
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} role="alert" className="text-xs text-fail">
          {error}
        </p>
      )}
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      disabled={!value}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          // Clipboard permission denied; the value is still selectable.
        }
      }}
      className="inline-flex items-center gap-1 rounded border border-border bg-panel-raised px-2 py-1 text-xs text-muted hover:text-text disabled:opacity-50"
    >
      {copied ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function FindingList({ findings }: { findings: LocalFinding[] }) {
  if (findings.length === 0) return <p className="text-sm text-muted">No findings.</p>;
  return (
    <ul className="flex flex-col gap-3">
      {findings.map((finding) => (
        <li key={finding.id} className="rounded border border-border bg-surface p-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <h3 className="text-sm font-semibold">{finding.title}</h3>
          </div>
          <p className="mt-2 text-sm text-muted">{finding.explanation}</p>
          {finding.rationale && (
            <p className="mt-1 text-xs text-muted">
              <span className="font-semibold text-text">Why this severity: </span>
              {finding.rationale}
            </p>
          )}
          {finding.remediation && (
            <p className="mt-1 text-xs text-muted">
              <span className="font-semibold text-ok">Fix: </span>
              {finding.remediation}
            </p>
          )}
          {finding.references && finding.references.length > 0 && (
            <p className="mt-1 text-xs text-muted">References: {finding.references.join(", ")}</p>
          )}
        </li>
      ))}
    </ul>
  );
}

/** Comparison table used by the encoder and hash explainers. */
export function TransformComparison() {
  const rows: Array<[string, string, string, string, string]> = [
    [
      "Encoding",
      "Yes, by anyone",
      "No",
      "Represent data safely in another format",
      "Base64, URL, hex",
    ],
    ["Hashing", "No (one-way)", "No", "Fingerprint data; detect changes", "SHA-256, SHA-512"],
    ["Encryption", "Yes, with the key", "Yes", "Keep data secret", "AES-GCM, ChaCha20"],
    [
      "Password hashing",
      "No, and slow on purpose",
      "No (uses a salt)",
      "Store passwords",
      "Argon2id, bcrypt",
    ],
  ];
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <caption className="sr-only">Encoding versus hashing versus encryption</caption>
        <thead className="text-muted">
          <tr>
            {["", "Reversible?", "Needs a key?", "Purpose", "Examples"].map((h) => (
              <th key={h} scope="col" className="border-b border-border px-2 py-1.5 font-semibold">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map(([name, ...cells]) => (
            <tr key={name} className="border-b border-border last:border-b-0">
              <th scope="row" className="px-2 py-1.5 font-semibold text-text">
                {name}
              </th>
              {cells.map((cell, i) => (
                <td key={i} className="px-2 py-1.5">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
