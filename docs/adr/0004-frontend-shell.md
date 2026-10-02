# ADR 0004 — Frontend shell, API client and design system

- **Status:** Accepted
- **Date:** 2026-10-02
- **Phase:** 3

## Context

Phase 3 turns the placeholder page into the console every later phase plugs
into: routing, login, an API client that honours the ADR 0003 contract
(cookies, CSRF, refresh), registry-driven navigation and a small set of UI
primitives. The frontend renders hostile data (banners, headers, audit
details), so the rendering rules matter as much as the backend ones.

## Decisions

### 1. Dependencies (exact pins)

| Package | Why |
|---|---|
| `react-router` 8.4.0 | Routing, nested layouts and route guards. Data-router API, so tests mount the real route table in a memory router |
| `@tanstack/react-query` 5.104.1 | Server state: caching, cancellation via `AbortSignal`, retries, infinite (keyset) paging for the audit log. Named in the spec |
| `lucide-react` 1.49.0 | Icons, named in the spec. Tree-shaken per icon |
| `@testing-library/user-event` 14.6.7 (dev) | Realistic keyboard and pointer events for the accessibility tests |

No component library and no `clsx`: the primitives are small, and owning them
keeps the XSS and accessibility rules in one reviewable place.

### 2. One API client (`src/lib/api/client.ts`)

- **Same-origin only.** `buildUrl` rejects anything that is not an absolute
  path (`https://…`, `//host`, `/\host`), so a bug cannot send session cookies
  to another host. **Deviation from ADR 0003:** `credentials: "same-origin"`
  instead of `"include"`. With relative URLs the two send the same cookies,
  and `same-origin` cannot leak them cross-origin.
- **`redirect: "error"`**: the API never redirects, so a redirect is treated as
  a fault rather than followed.
- **CSRF:** every non-GET request echoes the CSRF cookie
  (`__Host-sentinel_csrf`, or `sentinel_csrf` in the dev insecure mode) in
  `X-CSRF-Token`.
- **Timeouts:** 10 s by default (3 s for the health poll, 60 s for audit
  verification). A timeout becomes `NetworkError("timeout")`. A caller abort
  propagates unchanged so TanStack Query can ignore it.
- **Errors:** the backend envelope becomes a typed `ApiError` with `code`,
  `message` and `requestId`. Non-envelope bodies (such as a proxy's HTML 502
  page) are never shown; the user sees a generic message.
- **Refresh:** a 401 with code `authentication_required` triggers one refresh
  and one retry. `invalid_credentials` (a wrong password) never does.
  Concurrent 401s share one refresh promise (single-flight), and the
  **Web Locks API** serialises refreshes across tabs. Without that lock, two
  tabs refreshing with the same token look like token theft and the server
  revokes the session (ADR 0003, section 2).
- **Session expiry:** if the refresh fails, the client emits `sessionExpired`.
  The provider drops every cached response, marks the user anonymous and
  shows a toast. The route guard then redirects to `/login?next=…`.

### 3. Auth state and route guards

- "Who am I" is `GET /auth/me` cached under `["auth","me"]`. A 401 there means
  anonymous, which is a normal state. A 5xx or network error shows an outage
  card instead of the login page, so an API outage is not mistaken for a
  logout.
- `RequireAuth` publishes the user through a React context. The whole
  authenticated subtree therefore sees one consistent user and unmounts
  together on logout.
- `RequireRole` mirrors the backend role hierarchy. **The guards are UX, not
  security:** the backend enforces RBAC on every endpoint.
- **Open-redirect guard:** `?next=` accepts only same-origin paths.
  Protocol-relative, backslash, control-character, overlong and `/login`
  targets fall back to `/`.
- Login and logout clear the whole query cache, so data cached under one
  identity is never shown to the next one. Rejected passwords are cleared
  from component state.

### 4. Registry-driven navigation

`features/tools/registry.ts` is the frontend manifest:

- **Local tools** (Phase 4) are declared there, because the backend never sees
  them. They are listed under "Runs in your browser only" and disabled until
  they ship.
- **Backend tools** come from `GET /api/v1/tools`, grouped by category, with an
  optional icon hint. An unknown `tool_id` still appears, with a fallback icon.
  Adding a backend tool therefore needs no frontend change (CLAUDE.md rule 9).
- Tools above the user's role show a lock: viewers can read results but not
  run tools.

### 5. Rendering untrusted data

- Everything renders as React text nodes. ESLint still bans
  `dangerouslySetInnerHTML`.
- `JsonViewer` never turns values into links (no `javascript:` URLs). It caps
  depth (12), items per node (200) and string length (2000), so a hostile
  payload cannot freeze the tab. **Copy** exports the full value.
- `RouteErrorPage` shows no exception text. Details go to the console in dev
  builds only.

### 6. Design system and accessibility

- **Tokens:** colour tokens live in `src/index.css` (`@theme`).
  `src/theme/contrast.test.ts` parses them and asserts **WCAG AA (4.5:1)** for
  every text colour on every background, and for the primary button text on
  the accent fill. A palette change that breaks contrast fails CI.
- **Severity** is never shown by colour alone (WCAG 1.4.1): `SeverityBadge`
  always shows the label and an icon, with a plain-language tooltip.
- **Primitives:** `Card`, `Badge`, `SeverityBadge`, `Button`, `TextField`,
  `DataTable`, `JsonViewer`, `Tabs`, `Toast`, `Drawer` and `Spinner`.
  - `Tabs` follows the WAI-ARIA tabs pattern (arrow keys, Home/End, roving
    tabindex).
  - `Drawer` follows the dialog pattern: focus moves in, Tab is trapped,
    Escape closes it and focus returns to the opener.
  - `Toast` announces errors with `role="alert"` and keeps them until they are
    dismissed. Other toasts use `role="status"`.
  - `DataTable` sets `aria-sort` and makes rows keyboard-activatable.
- **Global rules:** a visible focus ring everywhere, a skip link, and
  `prefers-reduced-motion` support.

### 7. Admin audit viewer (spec gap closed)

03-logging-audit.md section 6 was not assigned to any phase. Phase 3 delivers
it on top of the existing Phase 2 API:

- **Events:** a filterable table (user, action, outcome, date range,
  security-only) with keyset paging, and a detail drawer showing the full
  redacted event and its hash pair.
- **Verification:** a "Verify chain" button with the result.
- **Alerts:** a tab listing security alerts with an acknowledge action, and a
  bell in the top bar for admins.

**Deferred:** CSV/JSON export of filtered results. The spec requires exports to
be audited (`audit.exported`), which needs a server endpoint. It fits the
Phase 13 exporters.

## Consequences

- **WebSockets:** Phase 5 adds `useRunStatus` and the run viewer on the same
  client. The client already accepts `AbortSignal`. WebSocket auth (T12)
  remains a Phase 5 item.
- **Dev dependency installs:** `frontend_node_modules` is a named volume.
  After a dependency change, run
  `docker compose exec frontend npm ci` (or remove the volume); rebuilding the
  image alone does not refresh it.
- **Production CSP:** the strict CSP in `nginx.conf` still holds. The build
  has no inline scripts or styles, and no external fonts or CDNs.
