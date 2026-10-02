/**
 * Byte/text conversions shared by the local tools. Pure functions, no I/O.
 *
 * Implemented by hand rather than with `btoa`/`atob` because those work on
 * Latin-1 "binary strings", not bytes, and silently mangle non-ASCII text.
 */

const textEncoder = new TextEncoder();

export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/** Strict UTF-8 decode. Returns null when the bytes are not valid UTF-8. */
export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export class DecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecodeError";
  }
}

// --- hex --------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(input: string): Uint8Array {
  const hex = input.replace(/\s+/g, "");
  if (hex.length % 2 !== 0) {
    throw new DecodeError(`Hex needs an even number of digits (got ${hex.length}).`);
  }
  const bad = /[^0-9a-f]/i.exec(hex);
  if (bad) {
    throw new DecodeError(
      `"${bad[0]}" at position ${bad.index + 1} is not a hex digit (0-9, a-f).`,
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// --- base64 / base64url (RFC 4648) ---------------------------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function encode64(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + alphabet[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + (pad ? "==" : "");
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + (pad ? "=" : "");
  }
  return out;
}

function decode64(input: string, alphabet: string, name: string): Uint8Array {
  const clean = input.replace(/\s+/g, "");
  const firstPad = clean.indexOf("=");
  const body = firstPad === -1 ? clean : clean.slice(0, firstPad);
  const padding = firstPad === -1 ? "" : clean.slice(firstPad);
  if (!/^={0,2}$/.test(padding)) {
    throw new DecodeError(`${name}: "=" padding may only appear (at most twice) at the end.`);
  }
  for (let i = 0; i < body.length; i++) {
    if (!alphabet.includes(body[i]!)) {
      const hint =
        name === "Base64" && (body[i] === "-" || body[i] === "_")
          ? " This looks like Base64URL."
          : name === "Base64URL" && (body[i] === "+" || body[i] === "/")
            ? " This looks like standard Base64."
            : "";
      throw new DecodeError(
        `${name}: "${body[i]}" at position ${i + 1} is not in the alphabet.${hint}`,
      );
    }
  }
  if (body.length % 4 === 1) {
    throw new DecodeError(
      `${name}: length ${body.length} is impossible (one character too many or too few).`,
    );
  }
  if (padding && (body.length + padding.length) % 4 !== 0) {
    throw new DecodeError(`${name}: wrong amount of "=" padding.`);
  }
  const out = new Uint8Array(Math.floor((body.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (const ch of body) {
    buffer = (buffer << 6) | alphabet.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

export const base64Encode = (bytes: Uint8Array) => encode64(bytes, B64, true);
export const base64Decode = (input: string) => decode64(input, B64, "Base64");
export const base64UrlEncode = (bytes: Uint8Array) => encode64(bytes, B64URL, false);
export const base64UrlDecode = (input: string) => decode64(input, B64URL, "Base64URL");

/** Constant-time string equality: the loop never exits early on a mismatch. */
export function constantTimeEqual(a: string, b: string): boolean {
  // Length is not secret here (hash lengths are public), so it may short-circuit.
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
