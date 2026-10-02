/**
 * Encoder / decoder logic (02-modules.md, client-side utility 4).
 *
 * Every format here is an *encoding*: a public, keyless, reversible change of
 * representation. Nothing here provides confidentiality, which is the point
 * the UI makes in its "encoding is not encryption" banner.
 */

import {
  DecodeError,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  bytesToHex,
  hexToBytes,
  utf8Decode,
  utf8Encode,
} from "../shared/bytes";

export type Format = "base64" | "base64url" | "url" | "hex";

export const FORMATS: Record<Format, { label: string; description: string }> = {
  base64: {
    label: "Base64",
    description: "Binary-to-text for email attachments, data: URIs and PEM keys (RFC 4648 §4).",
  },
  base64url: {
    label: "Base64URL",
    description: "URL- and filename-safe Base64 without padding, used inside JWTs (RFC 4648 §5).",
  },
  url: {
    label: "URL encoding",
    description: "Percent-encoding so text can sit inside a URL component (RFC 3986).",
  },
  hex: {
    label: "Hex",
    description: "Two hexadecimal digits per byte. Common for hashes and binary dumps.",
  },
};

/** Inputs are capped so a pasted multi-megabyte blob cannot freeze the tab. */
export const MAX_INPUT_CHARS = 1_000_000;

export function encode(format: Format, text: string): string {
  const bytes = utf8Encode(text);
  switch (format) {
    case "base64":
      return base64Encode(bytes);
    case "base64url":
      return base64UrlEncode(bytes);
    case "hex":
      return bytesToHex(bytes);
    case "url":
      return encodeURIComponent(text);
  }
}

export interface Decoded {
  /** The decoded text, or null when the bytes are not valid UTF-8. */
  text: string | null;
  bytes: Uint8Array;
}

export function decodeToBytes(format: Format, input: string): Uint8Array {
  switch (format) {
    case "base64":
      return base64Decode(input);
    case "base64url":
      return base64UrlDecode(input);
    case "hex":
      return hexToBytes(input);
    case "url":
      try {
        return utf8Encode(decodeURIComponent(input.replace(/\+/g, " ")));
      } catch {
        const bad = /%(?![0-9a-f]{2})/i.exec(input);
        throw new DecodeError(
          bad
            ? `URL: "%" at position ${bad.index + 1} must be followed by two hex digits.`
            : "URL: the percent-escapes do not form valid UTF-8.",
        );
      }
  }
}

export function decode(format: Format, input: string): Decoded {
  const bytes = decodeToBytes(format, input);
  return { bytes, text: utf8Decode(bytes) };
}

/**
 * Round-trip check. For encoding: does decoding the output give the input
 * back? For decoding: does re-encoding give the same string (ignoring
 * whitespace and Base64 padding)? A mismatch means the input was not in
 * canonical form, e.g. Base64 with non-zero trailing bits.
 */
export function roundTrips(format: Format, direction: "encode" | "decode", input: string): boolean {
  try {
    if (direction === "encode") return decode(format, encode(format, input)).text === input;
    const { text, bytes } = decode(format, input);
    const reencoded =
      format === "url"
        ? encodeURIComponent(text ?? "")
        : format === "hex"
          ? bytesToHex(bytes)
          : format === "base64"
            ? base64Encode(bytes)
            : base64UrlEncode(bytes);
    const normalise = (s: string) => {
      const noSpace = s.replace(/\s+/g, "");
      return format === "hex" ? noSpace.toLowerCase() : noSpace.replace(/=+$/, "");
    };
    // URL decoding is many-to-one ("a b", "a+b", "a%20b"), so compare the decoded text instead.
    if (format === "url") return decode("url", reencoded).text === text;
    return normalise(reencoded) === normalise(input);
  } catch {
    return false;
  }
}

export interface Suggestion {
  format: Format;
  preview: string;
  reason: string;
}

function isMostlyPrintable(text: string): boolean {
  if (!text) return false;
  let printable = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) printable++;
  }
  return printable / [...text].length >= 0.95;
}

/**
 * Suggest formats the input could be decoded from, most specific first.
 * A suggestion requires a clean decode to mostly printable UTF-8 text, so
 * random words ("cafe" is valid hex and Base64) rarely qualify.
 */
export function detectFormats(input: string): Suggestion[] {
  const value = input.trim();
  if (value.length < 2) return [];
  const candidates: Array<[Format, boolean, string]> = [
    ["url", /%[0-9a-f]{2}/i.test(value), "contains %XX escapes"],
    ["hex", /^(?:[0-9a-f]{2})+$/i.test(value.replace(/\s+/g, "")), "only hex digits, even length"],
    [
      "base64url",
      /^[A-Za-z0-9_-]+$/.test(value) && /[-_]/.test(value),
      "uses the URL-safe alphabet (- and _)",
    ],
    [
      "base64",
      /^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length % 4 === 0,
      "Base64 alphabet and a length divisible by 4",
    ],
  ];
  const out: Suggestion[] = [];
  for (const [format, plausible, reason] of candidates) {
    if (!plausible) continue;
    try {
      const { text } = decode(format, value);
      if (text !== null && isMostlyPrintable(text) && text !== value) {
        out.push({ format, preview: text.slice(0, 80), reason });
      }
    } catch {
      // Not decodable in this format.
    }
  }
  return out;
}
