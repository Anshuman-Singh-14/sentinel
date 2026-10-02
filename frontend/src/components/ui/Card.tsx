import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "./cn";

interface CardProps extends Omit<HTMLAttributes<HTMLElement>, "title"> {
  title?: ReactNode;
  /** Small uppercase label above the title, e.g. a category. */
  eyebrow?: ReactNode;
  actions?: ReactNode;
}

/** Bordered panel with an optional header row. Renders a <section>, so give it a title. */
export function Card({ title, eyebrow, actions, className, children, ...rest }: CardProps) {
  return (
    <section
      className={cn(
        "rounded-md border border-border bg-panel shadow-sm shadow-black/40",
        className,
      )}
      {...rest}
    >
      {(title || actions || eyebrow) && (
        <header className="flex items-start justify-between gap-4 border-b border-border px-4 py-3">
          <div className="min-w-0">
            {eyebrow && (
              <p className="text-[0.7rem] font-semibold tracking-[0.2em] text-muted uppercase">
                {eyebrow}
              </p>
            )}
            {title && <h2 className="truncate text-sm font-semibold text-text">{title}</h2>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
