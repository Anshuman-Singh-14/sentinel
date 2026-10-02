/**
 * Hash generator & verifier logic (02-modules.md, client-side utility 3).
 *
 * - Text is hashed with the Web Crypto API (`crypto.subtle.digest`), the
 *   browser's native, audited implementation. Web Crypto has no MD5, so MD5
 *   text hashing falls back to @noble/hashes.
 * - Files are hashed with @noble/hashes because Web Crypto has no incremental
 *   API: `digest()` needs the whole file in memory at once. Streaming through
 *   `update()` keeps memory flat and makes progress reporting possible.
 *   noble is audited, dependency-free and its output is cross-checked against
 *   Web Crypto in the tests.
 */

import { md5, sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";

import { bytesToHex, constantTimeEqual, utf8Encode } from "../shared/bytes";

export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512" | "SHA-1" | "MD5";

interface AlgorithmInfo {
  /** Hex digest length. */
  hexLength: number;
  legacy: boolean;
  note: string;
  webCrypto: boolean;
  create: () => { update(data: Uint8Array): unknown; digest(): Uint8Array };
}

export const ALGORITHMS: Record<HashAlgorithm, AlgorithmInfo> = {
  "SHA-256": {
    hexLength: 64,
    legacy: false,
    note: "Current standard (FIPS 180-4). Used for file integrity, TLS and Git's new object format.",
    webCrypto: true,
    create: () => sha256.create(),
  },
  "SHA-384": {
    hexLength: 96,
    legacy: false,
    note: "Truncated SHA-512. Resistant to length-extension attacks.",
    webCrypto: true,
    create: () => sha384.create(),
  },
  "SHA-512": {
    hexLength: 128,
    legacy: false,
    note: "Larger digest; often faster than SHA-256 on 64-bit CPUs.",
    webCrypto: true,
    create: () => sha512.create(),
  },
  "SHA-1": {
    hexLength: 40,
    legacy: true,
    note: "Legacy — not collision resistant. Practical collisions exist (SHAttered, 2017).",
    webCrypto: true,
    create: () => sha1.create(),
  },
  MD5: {
    hexLength: 32,
    legacy: true,
    note: "Legacy — not collision resistant. Collisions take seconds on a laptop.",
    webCrypto: false,
    create: () => md5.create(),
  },
};

export const ALGORITHM_ORDER: HashAlgorithm[] = ["SHA-256", "SHA-384", "SHA-512", "SHA-1", "MD5"];

export async function hashText(algorithm: HashAlgorithm, text: string): Promise<string> {
  const bytes = utf8Encode(text);
  const info = ALGORITHMS[algorithm];
  if (info.webCrypto) {
    // Copy into a fresh ArrayBuffer-backed view for the BufferSource type.
    const digest = await crypto.subtle.digest(algorithm, new Uint8Array(bytes));
    return bytesToHex(new Uint8Array(digest));
  }
  return bytesToHex(hashBytesSync(algorithm, bytes));
}

export function hashBytesSync(algorithm: HashAlgorithm, bytes: Uint8Array): Uint8Array {
  const hasher = ALGORITHMS[algorithm].create();
  hasher.update(bytes);
  return hasher.digest();
}

/** 4 GiB: far beyond normal use, but a hard ceiling (CLAUDE.md rule 7). */
export const MAX_FILE_BYTES = 4 * 1024 ** 3;
const CHUNK_BYTES = 4 * 1024 * 1024;

export class FileTooLargeError extends Error {
  constructor(size: number) {
    super(`The file is ${formatBytes(size)}; the limit is ${formatBytes(MAX_FILE_BYTES)}.`);
    this.name = "FileTooLargeError";
  }
}

async function* readChunks(file: Blob): AsyncGenerator<Uint8Array> {
  if (typeof file.stream === "function") {
    const reader = file.stream().getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        yield value;
      }
    } finally {
      reader.releaseLock();
    }
  }
  // Fallback for environments without Blob.stream(): bounded slices.
  for (let offset = 0; offset < file.size; offset += CHUNK_BYTES) {
    yield new Uint8Array(await file.slice(offset, offset + CHUNK_BYTES).arrayBuffer());
  }
}

/**
 * Hash a file with several algorithms in one pass. The file is read in
 * chunks, so memory use stays constant regardless of file size. The loop
 * yields to the event loop between chunks to keep the page responsive and to
 * notice cancellation.
 */
export async function hashFile(
  file: Blob,
  algorithms: HashAlgorithm[],
  options: { onProgress?: (fraction: number) => void; signal?: AbortSignal } = {},
): Promise<Record<HashAlgorithm, string>> {
  if (file.size > MAX_FILE_BYTES) throw new FileTooLargeError(file.size);
  const hashers = algorithms.map(
    (algorithm) => [algorithm, ALGORITHMS[algorithm].create()] as const,
  );
  let processed = 0;
  options.onProgress?.(0);
  for await (const chunk of readChunks(file)) {
    options.signal?.throwIfAborted();
    for (const [, hasher] of hashers) hasher.update(chunk);
    processed += chunk.byteLength;
    options.onProgress?.(file.size === 0 ? 1 : processed / file.size);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  options.signal?.throwIfAborted();
  options.onProgress?.(1);
  const out = {} as Record<HashAlgorithm, string>;
  for (const [algorithm, hasher] of hashers) out[algorithm] = bytesToHex(hasher.digest());
  return out;
}

// --- verification ---------------------------------------------------------------------

/**
 * Normalise a pasted digest: trim, drop whitespace and an optional
 * `algo:` / `0x` prefix (as in `sha256:abc…` or `sha256sum` output), lowercase.
 * Returns null if what is left is not hex.
 */
export function normalizeDigest(input: string): string | null {
  let value = input.trim();
  // `sha256sum` prints "<digest>  <filename>": keep the first field.
  value = value.split(/\s{2,}|\t/)[0] ?? "";
  value = value
    .replace(/^[a-z0-9-]+:/i, "")
    .replace(/^0x/i, "")
    .replace(/\s+/g, "")
    .toLowerCase();
  return /^[0-9a-f]+$/.test(value) ? value : null;
}

/** Algorithms whose digest has this hex length. */
export function algorithmsForLength(hexLength: number): HashAlgorithm[] {
  return ALGORITHM_ORDER.filter((a) => ALGORITHMS[a].hexLength === hexLength);
}

export type CompareResult =
  | { kind: "invalid" }
  | { kind: "match"; algorithm: HashAlgorithm }
  | { kind: "mismatch"; expectedAlgorithms: HashAlgorithm[] };

/** Compare an expected digest against computed ones in constant time. */
export function compareDigest(
  expected: string,
  computed: Partial<Record<HashAlgorithm, string>>,
): CompareResult {
  const normalized = normalizeDigest(expected);
  if (!normalized) return { kind: "invalid" };
  let matched: HashAlgorithm | null = null;
  for (const algorithm of ALGORITHM_ORDER) {
    const actual = computed[algorithm];
    // Every candidate is compared; no early exit on the first match.
    if (actual && constantTimeEqual(normalized, actual) && matched === null) matched = algorithm;
  }
  return matched
    ? { kind: "match", algorithm: matched }
    : { kind: "mismatch", expectedAlgorithms: algorithmsForLength(normalized.length) };
}

export function formatBytes(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}
