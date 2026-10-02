/**
 * CSRF token lookup (ADR 0003, section 4).
 *
 * The backend sets a JavaScript-readable CSRF cookie at login and on every
 * refresh. State-changing requests must echo it in `X-CSRF-Token`; the server
 * checks that the header equals the cookie *and* matches the digest stored on
 * the session row. A cross-site attacker can make the browser send cookies but
 * cannot read them, so it cannot produce the header.
 *
 * With `COOKIE_SECURE=true` the cookie is `__Host-sentinel_csrf`; the dev-only
 * insecure mode uses the unprefixed `sentinel_csrf`. The prefixed name wins.
 */

export const CSRF_HEADER = "X-CSRF-Token";
const CSRF_COOKIE_NAMES = ["__Host-sentinel_csrf", "sentinel_csrf"] as const;

export function readCookie(name: string, cookieString: string = document.cookie): string | null {
  for (const part of cookieString.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      const value = part.slice(index + 1).trim();
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }
  return null;
}

export function readCsrfToken(cookieString?: string): string | null {
  for (const name of CSRF_COOKIE_NAMES) {
    const value = readCookie(name, cookieString);
    if (value) return value;
  }
  return null;
}
