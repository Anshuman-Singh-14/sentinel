/**
 * Validate the `?next=` target used after login.
 *
 * An unchecked redirect parameter is an open redirect: a phishing link like
 * `/login?next=https://evil.example` would bounce a freshly authenticated user
 * to an attacker's page. Only same-origin absolute paths are accepted; anything
 * else falls back to the dashboard.
 */
export function safeRedirectPath(next: string | null | undefined, fallback = "/"): string {
  if (!next || next.length > 2048) return fallback;
  // Must be a path, not protocol-relative ("//evil") or a backslash trick ("/\evil").
  if (!next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return fallback;
  // Control characters (tabs, newlines) are stripped by URL parsers and can
  // turn "/\t/evil" into "//evil".
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(next)) return fallback;
  try {
    const url = new URL(next, window.location.origin);
    if (url.origin !== window.location.origin) return fallback;
    // Never bounce back to the login page itself.
    if (url.pathname === "/login") return fallback;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return fallback;
  }
}
