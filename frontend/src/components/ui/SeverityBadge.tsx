import { Info, OctagonAlert, ShieldAlert, TriangleAlert, CircleAlert } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { Severity } from "../../types/api";
import { cn } from "./cn";

interface SeverityStyle {
  icon: LucideIcon;
  className: string;
  /** Plain-language meaning, used as the accessible description. */
  meaning: string;
}

/**
 * Colour + icon + text for each severity. Colour alone would fail WCAG 1.4.1
 * (use of colour) for colour-blind users, so the label is always visible.
 */
export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  CRITICAL: {
    icon: OctagonAlert,
    className: "text-sev-critical border-sev-critical/60 bg-sev-critical/10",
    meaning: "Critical: act immediately",
  },
  HIGH: {
    icon: ShieldAlert,
    className: "text-sev-high border-sev-high/60 bg-sev-high/10",
    meaning: "High: fix soon",
  },
  MEDIUM: {
    icon: TriangleAlert,
    className: "text-sev-medium border-sev-medium/60 bg-sev-medium/10",
    meaning: "Medium: plan a fix",
  },
  LOW: {
    icon: CircleAlert,
    className: "text-sev-low border-sev-low/60 bg-sev-low/10",
    meaning: "Low: minor issue",
  },
  INFO: {
    icon: Info,
    className: "text-sev-info border-sev-info/60 bg-sev-info/10",
    meaning: "Informational: no action needed",
  },
};

export function isSeverity(value: string): value is Severity {
  return value in SEVERITY_STYLES;
}

export function SeverityBadge({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  const style = SEVERITY_STYLES[severity];
  const Icon = style.icon;
  return (
    <span
      title={style.meaning}
      data-severity={severity}
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-[0.7rem] leading-none font-bold tracking-wider whitespace-nowrap",
        style.className,
        className,
      )}
    >
      <Icon size={12} aria-hidden="true" />
      {severity}
      {count !== undefined && <span className="tabular-nums">{count}</span>}
    </span>
  );
}
