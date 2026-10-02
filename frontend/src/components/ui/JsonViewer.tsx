import { Check, ChevronDown, ChevronRight, Copy } from "lucide-react";
import { useState } from "react";

import { cn } from "./cn";

/**
 * Collapsible, read-only view of arbitrary JSON (raw tool output, audit details).
 *
 * Security: this data is untrusted. A port banner or HTTP header can contain
 * `<script>` or a `javascript:` URL. Everything is rendered as React text
 * nodes, which React escapes; nothing becomes HTML or a link.
 *
 * Robustness: rendering is bounded so a huge or hostile payload cannot freeze
 * the tab. Deep nesting is cut at `maxDepth`, long strings are truncated, and
 * long arrays/objects show the first `maxItems` entries.
 */

export interface JsonViewerProps {
  value: unknown;
  /** Accessible name for the tree. */
  label?: string;
  /** Levels expanded on first render. */
  defaultExpandDepth?: number;
  maxDepth?: number;
  maxItems?: number;
  maxStringLength?: number;
  className?: string;
}

interface Limits {
  defaultExpandDepth: number;
  maxDepth: number;
  maxItems: number;
  maxStringLength: number;
}

export function JsonViewer({
  value,
  label = "JSON data",
  defaultExpandDepth = 1,
  maxDepth = 12,
  maxItems = 200,
  maxStringLength = 2000,
  className,
}: JsonViewerProps) {
  const limits = { defaultExpandDepth, maxDepth, maxItems, maxStringLength };
  return (
    <div
      className={cn(
        "relative overflow-auto rounded border border-border bg-surface p-3 text-xs leading-relaxed",
        className,
      )}
    >
      <CopyButton value={value} />
      <div role="tree" aria-label={label} className="pr-10">
        <JsonNode name={null} value={value} depth={0} limits={limits} />
      </div>
    </div>
  );
}

function CopyButton({ value }: { value: unknown }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(safeStringify(value));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be denied; the data is still on screen.
    }
  };
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? "Copied" : "Copy JSON"}
      className="absolute top-2 right-2 rounded border border-border bg-panel-raised p-1 text-muted hover:text-text"
    >
      {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
    </button>
  );
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

function JsonNode({
  name,
  value,
  depth,
  limits,
}: {
  name: string | null;
  value: unknown;
  depth: number;
  limits: Limits;
}) {
  const isContainer = typeof value === "object" && value !== null;
  const [expanded, setExpanded] = useState(depth < limits.defaultExpandDepth);

  const keyLabel =
    name === null ? null : <span className="text-accent">{JSON.stringify(name)}: </span>;

  if (!isContainer) {
    return (
      <div role="treeitem" aria-selected={false} className="break-all whitespace-pre-wrap">
        {keyLabel}
        <Primitive value={value} maxLength={limits.maxStringLength} />
      </div>
    );
  }

  const isArray = Array.isArray(value);
  const entries: Array<[string, unknown]> = isArray
    ? (value as unknown[]).map((item, index) => [String(index), item])
    : Object.entries(value as Record<string, unknown>);
  const [open, close] = isArray ? ["[", "]"] : ["{", "}"];

  if (entries.length === 0) {
    return (
      <div role="treeitem" aria-selected={false}>
        {keyLabel}
        <span className="text-muted">
          {open}
          {close}
        </span>
      </div>
    );
  }

  if (depth >= limits.maxDepth) {
    return (
      <div role="treeitem" aria-selected={false}>
        {keyLabel}
        <span className="text-muted italic">
          {open}…{close} (nested too deep to display; use Copy)
        </span>
      </div>
    );
  }

  const shown = entries.slice(0, limits.maxItems);
  const hidden = entries.length - shown.length;
  const summary = `${entries.length} ${isArray ? "items" : "keys"}`;

  return (
    <div role="treeitem" aria-expanded={expanded} aria-selected={false}>
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="inline-flex items-center text-left hover:text-text"
        aria-label={`${expanded ? "Collapse" : "Expand"} ${name ?? "root"} (${summary})`}
      >
        {expanded ? (
          <ChevronDown size={12} aria-hidden="true" />
        ) : (
          <ChevronRight size={12} aria-hidden="true" />
        )}
        {keyLabel}
        <span className="text-muted">
          {open}
          {!expanded && ` ${summary} ${close}`}
        </span>
      </button>
      {expanded && (
        <div role="group" className="ml-2 border-l border-border pl-3">
          {shown.map(([key, child]) => (
            <JsonNode
              key={key}
              name={isArray ? null : key}
              value={child}
              depth={depth + 1}
              limits={limits}
            />
          ))}
          {hidden > 0 && (
            <div className="text-muted italic">… {hidden} more not shown (use Copy)</div>
          )}
        </div>
      )}
      {expanded && <span className="text-muted">{close}</span>}
    </div>
  );
}

function Primitive({ value, maxLength }: { value: unknown; maxLength: number }) {
  if (value === null) return <span className="text-muted">null</span>;
  switch (typeof value) {
    case "string": {
      const truncated = value.length > maxLength;
      const text = truncated ? value.slice(0, maxLength) : value;
      return (
        <span className="text-ok">
          {JSON.stringify(text)}
          {truncated && (
            <span className="text-muted italic"> … (+{value.length - maxLength} chars)</span>
          )}
        </span>
      );
    }
    case "number":
    case "bigint":
      return <span className="text-sev-medium">{String(value)}</span>;
    case "boolean":
      return <span className="text-sev-low">{String(value)}</span>;
    default:
      return <span className="text-muted">{String(value)}</span>;
  }
}
