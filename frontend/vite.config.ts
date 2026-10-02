import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In docker compose the API is reachable as http://api:8000. Running Vite on the
// host falls back to localhost.
const apiTarget = process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8000";

// The dev proxy keeps the browser on a single origin (localhost:5173). That is
// required for the SameSite=Strict auth cookies added in Phase 2, and it means
// the API needs no permissive CORS in development.
const proxied = ["/api", "/health", "/ready"];

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // The zxcvbn English dictionaries are one ~1.2 MB lazy chunk, loaded only
    // for the password analyzer (and prefetched when idle). The main bundle
    // stays far below this.
    chunkSizeWarningLimit: 1300,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      ...Object.fromEntries(proxied.map((path) => [path, { target: apiTarget }])),
      // Live run updates (Phase 5). Same origin as the page, like everything else.
      "/ws": { target: apiTarget, ws: true },
    },
    // Bind mounts from a Windows host do not deliver file events to the container.
    watch: process.env.VITE_USE_POLLING === "true" ? { usePolling: true, interval: 500 } : {},
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    unstubGlobals: true,
    // Password tests load the real zxcvbn dictionaries; leave headroom on slow CI runners.
    testTimeout: 15_000,
  },
});
