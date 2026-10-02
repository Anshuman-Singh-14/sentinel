import { useId } from "react";
import type { InputHTMLAttributes, ReactNode } from "react";

import { cn } from "./cn";

export interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
}

/** Labelled input. Hints and errors are tied to it with aria-describedby. */
export function TextField({ label, hint, error, className, ...rest }: TextFieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <label htmlFor={id} className="text-xs font-semibold tracking-wider text-muted uppercase">
        {label}
      </label>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={[hintId, errorId].filter(Boolean).join(" ") || undefined}
        className={cn(
          "rounded border bg-surface px-3 py-2 text-sm text-text placeholder:text-muted/70",
          "focus:border-accent focus:outline-none",
          error ? "border-fail" : "border-border-strong",
        )}
        {...rest}
      />
      {hint && (
        <p id={hintId} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-xs text-fail">
          {error}
        </p>
      )}
    </div>
  );
}
