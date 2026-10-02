import type { HTMLAttributes } from "react";

import { cn } from "./cn";

export type BadgeTone = "neutral" | "accent" | "ok" | "warn" | "fail";

const TONES: Record<BadgeTone, string> = {
  neutral: "text-muted border-border-strong bg-panel-raised",
  accent: "text-accent border-accent/50 bg-accent/10",
  ok: "text-ok border-ok/50 bg-ok/10",
  warn: "text-warn border-warn/50 bg-warn/10",
  fail: "text-fail border-fail/50 bg-fail/10",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

export function Badge({ tone = "neutral", className, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-[0.7rem] leading-none font-semibold tracking-wider whitespace-nowrap uppercase",
        TONES[tone],
        className,
      )}
      {...rest}
    />
  );
}
