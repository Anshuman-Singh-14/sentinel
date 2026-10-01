import { useEffect, useState } from "react";

import { getHealth } from "../lib/api";

type HealthState = { kind: "loading" } | { kind: "ok"; version: string } | { kind: "error" };

/** Phase 0 placeholder: proves the frontend -> proxy -> API path works. */
export function App() {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    getHealth(controller.signal)
      .then((body) => setHealth({ kind: "ok", version: body.version }))
      .catch(() => {
        // Unmounting aborts the request; that is not an API failure.
        if (!controller.signal.aborted) setHealth({ kind: "error" });
      });
    return () => controller.abort();
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center p-6 font-mono">
      <section className="w-full max-w-md rounded-lg border border-border bg-panel p-6">
        <h1 className="text-xl font-semibold tracking-widest text-accent uppercase">Sentinel</h1>
        <p className="mt-1 text-sm text-muted">SOC console — foundation build</p>
        <div className="mt-6" role="status" aria-live="polite">
          <HealthBadge health={health} />
        </div>
      </section>
    </main>
  );
}

function HealthBadge({ health }: { health: HealthState }) {
  switch (health.kind) {
    case "loading":
      return <span className="text-muted">Checking API…</span>;
    case "ok":
      return (
        <span className="text-ok">
          ● API healthy <span className="text-muted">(v{health.version})</span>
        </span>
      );
    case "error":
      return <span className="text-fail">● API unreachable</span>;
  }
}
