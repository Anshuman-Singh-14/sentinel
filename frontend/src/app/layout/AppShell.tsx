import { useEffect, useState } from "react";
import { Outlet } from "react-router";

import { prefetchLocalTools } from "../../features/tools/registry";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

/** Authenticated layout: sidebar navigation, top bar and the routed page. */
export function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false);

  // Warm the local tools' chunks once the browser is idle, so they still open
  // if the connection drops later.
  useEffect(() => {
    const idle = window.requestIdleCallback ?? ((cb: () => void) => window.setTimeout(cb, 2000));
    const cancel = window.cancelIdleCallback ?? window.clearTimeout;
    const handle = idle(() => prefetchLocalTools());
    return () => cancel(handle);
  }, []);

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  return (
    // `relative` on the shell and on <main>: absolutely positioned descendants
    // (sr-only labels, popovers) must be contained here. Otherwise the browser
    // positions them against the document, which then grows taller than the
    // window and gets a second, page-level scrollbar that drags the whole shell.
    <div className="relative flex h-screen overflow-hidden">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-on-accent"
      >
        Skip to content
      </a>

      {/* Desktop sidebar */}
      <aside className="relative hidden w-64 shrink-0 border-r border-border bg-panel lg:block">
        <Sidebar />
      </aside>

      {/* Mobile drawer */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60"
            aria-hidden="true"
            onClick={() => setMenuOpen(false)}
          />
          <aside className="relative h-full w-64 border-r border-border bg-panel">
            <Sidebar onNavigate={() => setMenuOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onOpenMenu={() => setMenuOpen(true)} />
        <main id="main" tabIndex={-1} className="relative flex-1 overflow-y-auto p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
