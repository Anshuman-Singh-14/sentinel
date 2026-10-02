// @vitest-environment node
/// <reference types="node" />
/**
 * Static privacy guarantee for the client-side tools (CLAUDE.md rule 2).
 *
 * Walks the import graph from each local tool's entry module and fails if any
 * reachable *project* file
 *   - is the API client (src/lib/api) or uses TanStack Query, or
 *   - mentions a network, storage or logging API.
 * Third-party packages are restricted to an explicit allowlist, each of which
 * is pure computation.
 *
 * The runtime test (isolation.test.tsx) complements this by exercising the
 * tools with every network API replaced by a spy.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const ENTRIES = [
  "features/tools/local/password/PasswordTool.tsx",
  "features/tools/local/password/estimator.ts",
  "features/tools/local/jwt/JwtTool.tsx",
  "features/tools/local/hash/HashTool.tsx",
  "features/tools/local/encoder/EncoderTool.tsx",
];

const ALLOWED_PACKAGES = [
  /^react$/,
  /^react\/jsx-runtime$/,
  /^lucide-react$/,
  /^@zxcvbn-ts\/(core|language-common|language-en)$/,
  /^@noble\/hashes\/(sha2|legacy)\.js$/,
];

const FORBIDDEN: Array<[RegExp, string]> = [
  [/\bfetch\s*\(/, "fetch()"],
  [/XMLHttpRequest/, "XMLHttpRequest"],
  [/\bWebSocket\b/, "WebSocket"],
  [/\bEventSource\b/, "EventSource"],
  [/sendBeacon/, "navigator.sendBeacon"],
  [/\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b/, "browser storage"],
  [/document\.cookie/, "document.cookie"],
  [/\bconsole\.(log|info|debug|warn|error)\b/, "console logging"],
  [/new\s+Image\s*\(/, "image beacons"],
  [/window\.open\s*\(/, "window.open"],
  [/@tanstack\/react-query/, "TanStack Query"],
  [/https?:\/\/(?!datatracker\.ietf\.org)[^\s"'`]+/, "hard-coded URLs"],
];

const IMPORT_RE =
  /(?:import|export)\s[^;]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

function resolveRelative(from: string, spec: string): string {
  const base = resolve(dirname(from), spec);
  for (const candidate of [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}/index.ts`,
    `${base}/index.tsx`,
  ]) {
    if (existsSync(candidate) && !candidate.endsWith("/") && /\.(ts|tsx)$/.test(candidate))
      return candidate;
  }
  throw new Error(`Cannot resolve ${spec} from ${from}`);
}

function walk(): { files: Set<string>; packages: Set<string> } {
  const files = new Set<string>();
  const packages = new Set<string>();
  const queue = ENTRIES.map((e) => resolve(SRC, e));
  while (queue.length) {
    const file = queue.pop()!;
    if (files.has(file)) continue;
    files.add(file);
    const source = readFileSync(file, "utf-8");
    for (const match of source.matchAll(IMPORT_RE)) {
      const spec = (match[1] ?? match[2])!;
      if (spec.startsWith(".")) queue.push(resolveRelative(file, spec));
      else packages.add(spec);
    }
  }
  return { files, packages };
}

/**
 * Source with comments removed, so documentation that *mentions* an API
 * ("pushed over the run WebSocket") is not mistaken for code that uses it.
 * Only block comments and whole-line `//` comments are stripped: a `//`
 * inside a string (a URL) stays and is still checked.
 */
function code(file: string): string {
  return readFileSync(file, "utf-8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

const graph = walk();
const rel = (f: string) => relative(SRC, f).replace(/\\/g, "/");

describe("local tools are isolated from the network (static)", () => {
  it("reaches the expected modules", () => {
    const files = [...graph.files].map(rel);
    expect(files).toEqual(expect.arrayContaining(ENTRIES));
    expect(files.length).toBeGreaterThan(ENTRIES.length);
  });

  it("never imports the API client", () => {
    const offenders = [...graph.files].map(rel).filter((f) => f.startsWith("lib/api/"));
    expect(offenders).toEqual([]);
  });

  it("only imports allowlisted third-party packages", () => {
    const unexpected = [...graph.packages].filter(
      (p) => !ALLOWED_PACKAGES.some((re) => re.test(p)),
    );
    expect(unexpected).toEqual([]);
  });

  for (const [pattern, label] of FORBIDDEN) {
    it(`no reachable module uses ${label}`, () => {
      const offenders = [...graph.files]
        .filter((f) => !/\.test\.tsx?$/.test(f))
        .filter((f) => pattern.test(code(f)))
        .map(rel);
      expect(offenders).toEqual([]);
    });
  }
});
