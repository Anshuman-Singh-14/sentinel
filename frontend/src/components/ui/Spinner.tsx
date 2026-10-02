import { LoaderCircle } from "lucide-react";

/**
 * Loading indicator. Pass `label={null}` when the surrounding element already
 * announces the busy state (for example a button with aria-busy).
 */
export function Spinner({
  size = 18,
  label = "Loading",
}: {
  size?: number;
  label?: string | null;
}) {
  return (
    <span role={label ? "status" : undefined} className="inline-flex items-center gap-2 text-muted">
      <LoaderCircle size={size} className="animate-spin" aria-hidden="true" />
      {label && <span className="sr-only">{label}</span>}
    </span>
  );
}
