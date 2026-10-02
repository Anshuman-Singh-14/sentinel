/**
 * JWT inspector logic (02-modules.md, client-side utility 2).
 *
 * Decoding is not verifying: anyone can read (and forge) a JWT's header and
 * payload. Only a signature check with the right key says who issued it.
 * Analysis runs on the *unverified* contents and says so.
 */

import { DecodeError, base64Decode, base64UrlDecode, utf8Decode } from "../shared/bytes";
import type { LocalFinding } from "../shared/findings";
import { sortFindings } from "../shared/findings";

/** Real tokens are a few KB; this cap keeps a pasted blob from hanging the tab. */
export const MAX_TOKEN_CHARS = 64 * 1024;

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** The signature exactly as it appears in the token (base64url). */
  signature: string;
  /** `header.payload`: the bytes the signature covers. */
  signingInput: string;
}

export class JwtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwtError";
  }
}

function decodeJsonSegment(segment: string, name: string): Record<string, unknown> {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(segment);
  } catch (error) {
    throw new JwtError(`The ${name} is not valid Base64URL. ${(error as DecodeError).message}`);
  }
  const text = utf8Decode(bytes);
  if (text === null) throw new JwtError(`The ${name} is not valid UTF-8 text.`);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new JwtError(`The ${name} is not valid JSON.`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new JwtError(`The ${name} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

export function decodeJwt(input: string): DecodedJwt {
  // Tolerate a pasted "Bearer " prefix and surrounding whitespace.
  const token = input.trim().replace(/^bearer\s+/i, "");
  if (!token) throw new JwtError("Paste a token to inspect it.");
  if (token.length > MAX_TOKEN_CHARS) {
    throw new JwtError(`The token is longer than ${MAX_TOKEN_CHARS} characters.`);
  }
  const parts = token.split(".");
  if (parts.length === 5) {
    throw new JwtError(
      "This is an encrypted JWT (JWE, five parts). Its payload cannot be read without the decryption key.",
    );
  }
  if (parts.length !== 3) {
    throw new JwtError(
      `A signed JWT has three dot-separated parts (header.payload.signature); this has ${parts.length}.`,
    );
  }
  const [headerPart, payloadPart, signature] = parts as [string, string, string];
  return {
    header: decodeJsonSegment(headerPart, "header"),
    payload: decodeJsonSegment(payloadPart, "payload"),
    signature,
    signingInput: `${headerPart}.${payloadPart}`,
  };
}

// --- algorithms ------------------------------------------------------------------------

export type AlgorithmFamily = "none" | "hmac" | "rsa" | "rsa-pss" | "ecdsa" | "eddsa" | "unknown";

export function algorithmFamily(alg: unknown): AlgorithmFamily {
  if (typeof alg !== "string") return "unknown";
  if (alg.toLowerCase() === "none") return "none";
  if (/^HS(256|384|512)$/.test(alg)) return "hmac";
  if (/^RS(256|384|512)$/.test(alg)) return "rsa";
  if (/^PS(256|384|512)$/.test(alg)) return "rsa-pss";
  if (/^ES(256|384|512)$/.test(alg)) return "ecdsa";
  if (alg === "EdDSA" || alg === "Ed25519") return "eddsa";
  return "unknown";
}

// --- time claims ----------------------------------------------------------------------

export interface TimeClaim {
  claim: "exp" | "nbf" | "iat";
  label: string;
  date: Date;
  relative: string;
}

const TIME_LABELS = { exp: "Expires", nbf: "Not valid before", iat: "Issued at" } as const;

export function relativeTime(date: Date, now: Date): string {
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["day", 86_400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1],
  ];
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size || unit === "second") {
      return rtf.format(Math.round(seconds / size), unit);
    }
  }
  return rtf.format(0, "second");
}

function numericDate(value: unknown): Date | null {
  // RFC 7519 NumericDate: seconds since the epoch. Bound it to sane dates.
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value < 0 || value > 253402300799) return null; // year 9999
  return new Date(value * 1000);
}

export function timeClaims(payload: Record<string, unknown>, now: Date): TimeClaim[] {
  const out: TimeClaim[] = [];
  for (const claim of ["iat", "nbf", "exp"] as const) {
    const date = numericDate(payload[claim]);
    if (date)
      out.push({ claim, label: TIME_LABELS[claim], date, relative: relativeTime(date, now) });
  }
  return out;
}

// --- analysis ---------------------------------------------------------------------------

const SENSITIVE_KEY =
  /pass(word|wd)?|secret|private[_-]?key|api[_-]?key|access[_-]?key|credit|card[_-]?number|cvv|ssn|social[_-]?security|pin$|^otp|refresh[_-]?token/i;
const PII_KEY = /^(email|phone|phone_number|address|birthdate|dob|date_of_birth)$/i;
const SENSITIVE_VALUE = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b/;

function walk(
  value: unknown,
  path: string,
  visit: (path: string, key: string, value: unknown) => void,
  depth = 0,
) {
  if (depth > 10 || typeof value !== "object" || value === null) return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = path ? `${path}.${key}` : key;
    visit(childPath, key, child);
    walk(child, childPath, visit, depth + 1);
  }
}

const HOUR = 3600;
const DAY = 24 * HOUR;

/** Findings about a decoded (unverified) token. */
export function analyzeJwt(jwt: DecodedJwt, now: Date = new Date()): LocalFinding[] {
  const { header, payload } = jwt;
  const findings: LocalFinding[] = [];
  const alg = header.alg;
  const family = algorithmFamily(alg);

  // Algorithm
  if (alg === undefined) {
    findings.push({
      id: "alg-missing",
      severity: "HIGH",
      title: "No algorithm in the header",
      explanation: "The `alg` header is required for signed JWTs (RFC 7515 §4.1.1).",
      rationale:
        "A verifier that guesses the algorithm can be tricked into accepting forged tokens.",
      remediation:
        "Issue tokens with an explicit algorithm and have verifiers pin the algorithm they expect.",
    });
  } else if (family === "none") {
    findings.push({
      id: "alg-none",
      severity: "CRITICAL",
      title: 'Unsigned token: alg is "none"',
      explanation:
        "This token carries no signature, so anyone can create or modify one with any claims.",
      rationale:
        "Libraries that honour alg=none let attackers forge identities outright (CVE-2015-9235 and many others).",
      remediation:
        "Reject alg=none on every verifier. Configure the expected algorithm explicitly instead of reading it from the token.",
      references: ["https://datatracker.ietf.org/doc/html/rfc8725#section-3.1", "CWE-347"],
    });
  } else if (family === "hmac") {
    findings.push({
      id: "alg-symmetric",
      severity: "INFO",
      title: `Symmetric algorithm (${String(alg)})`,
      explanation:
        "HMAC uses one shared secret both to sign and to verify. Every service that can verify these tokens can also mint them.",
      rationale: "Fine within one trust boundary; risky when many services share the secret.",
      remediation:
        "Use a random secret of at least as many bytes as the hash (32 for HS256). For tokens checked by many services, prefer an asymmetric algorithm (ES256, EdDSA, RS256).",
      references: ["https://datatracker.ietf.org/doc/html/rfc7518#section-3.2"],
    });
  } else if (family === "unknown") {
    findings.push({
      id: "alg-unknown",
      severity: "MEDIUM",
      title: `Unrecognised algorithm "${String(alg)}"`,
      explanation: "This is not one of the registered JWS algorithms.",
      rationale: "Non-standard algorithms are rarely implemented safely.",
      remediation: "Use a registered algorithm from RFC 7518 or RFC 8037.",
    });
  } else {
    findings.push({
      id: "alg-asymmetric",
      severity: "INFO",
      title: `Asymmetric algorithm (${String(alg)})`,
      explanation:
        "Signed with a private key and verified with the matching public key, so verifiers cannot mint tokens.",
    });
  }

  if (family !== "none" && jwt.signature === "") {
    findings.push({
      id: "signature-empty",
      severity: "HIGH",
      title: "The signature part is empty",
      explanation: `The header claims ${String(alg)} but no signature is attached. A verifier that skips empty signatures would accept anything.`,
      remediation: "Treat a missing signature as invalid.",
    });
  }

  // Key-location headers
  if (header.jku !== undefined || header.x5u !== undefined) {
    findings.push({
      id: "header-key-url",
      severity: "MEDIUM",
      title: `Key URL in the header (${["jku", "x5u"].filter((k) => header[k] !== undefined).join(", ")})`,
      explanation:
        "These headers point the verifier at a URL to fetch the verification key from. If the verifier follows a URL chosen by whoever made the token, an attacker can host their own key and sign anything.",
      rationale:
        "A classic JWT forgery vector, and a server-side request forgery (SSRF) channel too.",
      remediation:
        "Only fetch keys from an allowlist of trusted URLs, or ignore these headers entirely.",
      references: ["https://datatracker.ietf.org/doc/html/rfc8725#section-3.10", "CWE-918"],
    });
  }
  if (header.jwk !== undefined) {
    findings.push({
      id: "header-embedded-jwk",
      severity: "HIGH",
      title: "Embedded public key in the header (jwk)",
      explanation:
        "The token carries its own verification key. A verifier that trusts it will accept a token signed by anyone, with their own key.",
      remediation: "Never verify with a key supplied by the token itself.",
      references: ["CVE-2018-0114", "CWE-347"],
    });
  }
  if (header.x5c !== undefined) {
    findings.push({
      id: "header-x5c",
      severity: "LOW",
      title: "Certificate chain in the header (x5c)",
      explanation:
        "The token embeds an X.509 chain. That is safe only if the verifier validates the chain against its own trusted roots.",
      remediation: "Validate x5c against a pinned trust store, or ignore it.",
    });
  }
  if (header.kid !== undefined) {
    const kid = String(header.kid);
    const suspicious = /\.\.|[/\\]|['";]|\|/.test(kid);
    findings.push({
      id: "header-kid",
      severity: suspicious ? "MEDIUM" : "INFO",
      title: suspicious ? "Suspicious key ID (kid)" : "Key ID present (kid)",
      explanation: suspicious
        ? `The kid "${kid}" contains path, quote or shell characters. Verifiers that use kid to build a file path or SQL query can be attacked through it.`
        : "kid tells the verifier which of its own keys to use. It is a lookup hint, not a key.",
      remediation: "Look kid up in a fixed key set; never use it in a path, query or command.",
    });
  }

  // Time claims
  const exp = numericDate(payload.exp);
  const nbf = numericDate(payload.nbf);
  const iat = numericDate(payload.iat);
  if (!exp) {
    findings.push({
      id: "exp-missing",
      severity: "MEDIUM",
      title: "No expiry (exp)",
      explanation: "Without exp, a stolen token works forever unless the server tracks revocation.",
      rationale: "RFC 8725 recommends short-lived tokens to limit the damage of a leak.",
      remediation: "Set exp. Access tokens typically live for 5–60 minutes.",
      references: ["https://datatracker.ietf.org/doc/html/rfc8725#section-3.10"],
    });
  } else {
    if (exp <= now) {
      findings.push({
        id: "expired",
        severity: "INFO",
        title: "Expired",
        explanation: `This token expired ${relativeTime(exp, now)}. A correct verifier rejects it.`,
      });
    }
    const start = iat ?? nbf;
    if (start) {
      const lifetime = (exp.getTime() - start.getTime()) / 1000;
      if (lifetime > 30 * DAY) {
        findings.push({
          id: "lifetime-very-long",
          severity: "MEDIUM",
          title: `Very long lifetime (${Math.round(lifetime / DAY)} days)`,
          explanation: "A leaked token stays usable for a long time.",
          remediation:
            "Use short-lived access tokens with refresh tokens, or server-side sessions.",
        });
      } else if (lifetime > DAY) {
        findings.push({
          id: "lifetime-long",
          severity: "LOW",
          title: `Long lifetime (${Math.round(lifetime / HOUR)} hours)`,
          explanation: "Access tokens normally live minutes to an hour.",
          remediation: "Shorten the lifetime unless there is a documented reason.",
        });
      }
    }
  }
  if (nbf && nbf > now) {
    findings.push({
      id: "not-yet-valid",
      severity: "INFO",
      title: "Not yet valid",
      explanation: `nbf is ${relativeTime(nbf, now)}. Verifiers reject the token until then.`,
    });
  }
  if (iat && iat.getTime() > now.getTime() + 5 * 60_000) {
    findings.push({
      id: "iat-future",
      severity: "LOW",
      title: "Issued in the future",
      explanation:
        "iat is later than now (beyond 5 minutes of clock skew). That points to a wrong issuer clock or a hand-made token.",
    });
  }

  // Sensitive data in the payload
  const sensitive: string[] = [];
  const pii: string[] = [];
  walk(payload, "", (path, key, value) => {
    if (SENSITIVE_KEY.test(key)) sensitive.push(path);
    else if (PII_KEY.test(key)) pii.push(path);
    else if (typeof value === "string" && SENSITIVE_VALUE.test(value)) sensitive.push(path);
  });
  if (sensitive.length) {
    findings.push({
      id: "payload-sensitive",
      severity: "HIGH",
      title: "Sensitive-looking data in the payload",
      explanation: `Fields ${sensitive.map((p) => `"${p}"`).join(", ")} look like secrets. A JWT payload is only Base64URL-encoded, not encrypted: anyone holding the token can read it.`,
      rationale: "Tokens end up in logs, browser storage and proxies.",
      remediation:
        "Keep secrets out of tokens. Put an opaque reference in the token, or use JWE if the payload must be confidential.",
      references: ["CWE-312"],
    });
  }
  if (pii.length) {
    findings.push({
      id: "payload-pii",
      severity: "LOW",
      title: "Personal data in the payload",
      explanation: `Fields ${pii.map((p) => `"${p}"`).join(", ")} are personal data, readable by anyone who sees the token.`,
      remediation: "Include only the claims the recipient needs (data minimisation).",
    });
  }

  return sortFindings(findings);
}

// --- signature verification (Web Crypto) ---------------------------------------------------

export type VerifyResult = { ok: true } | { ok: false; reason: string };

const HASHES: Record<string, string> = { "256": "SHA-256", "384": "SHA-384", "512": "SHA-512" };
const CURVES: Record<string, string> = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };

function pemToDer(pem: string): Uint8Array {
  const match = /-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
  if (!match) throw new JwtError("The key is not a PEM block.");
  if (match[1] !== "PUBLIC KEY") {
    throw new JwtError(
      match[1]!.includes("PRIVATE")
        ? "That is a PRIVATE key. Verification needs only the public key; never paste private keys into tools."
        : `Expected "-----BEGIN PUBLIC KEY-----" (SPKI), got "${match[1]}".`,
    );
  }
  return base64Decode(match[2]!);
}

export function looksLikePublicKey(key: string): boolean {
  const k = key.trim();
  return k.startsWith("-----BEGIN") || (k.startsWith("{") && /"kty"\s*:/.test(k));
}

async function importVerifyKey(alg: string, key: string): Promise<CryptoKey> {
  const family = algorithmFamily(alg);
  const bits = alg.slice(2);
  let params: RsaHashedImportParams | EcKeyImportParams | HmacImportParams | Algorithm;
  switch (family) {
    case "hmac":
      params = { name: "HMAC", hash: HASHES[bits]! };
      break;
    case "rsa":
      params = { name: "RSASSA-PKCS1-v1_5", hash: HASHES[bits]! };
      break;
    case "rsa-pss":
      params = { name: "RSA-PSS", hash: HASHES[bits]! };
      break;
    case "ecdsa":
      params = { name: "ECDSA", namedCurve: CURVES[alg]! };
      break;
    case "eddsa":
      params = { name: "Ed25519" };
      break;
    default:
      throw new JwtError(`Cannot verify algorithm "${alg}".`);
  }

  if (family === "hmac") {
    // Algorithm confusion (RFC 8725 §2.1): a verifier fed an RS256 public key
    // as an HMAC secret accepts tokens signed with that public, i.e. known, key.
    if (looksLikePublicKey(key)) {
      throw new JwtError(
        `The token says ${alg} (HMAC) but you supplied a public key. Accepting that combination is the "algorithm confusion" attack: a public key is not a secret. Verification refused.`,
      );
    }
    return crypto.subtle.importKey("raw", new TextEncoder().encode(key), params, false, ["verify"]);
  }

  const trimmed = key.trim();
  if (trimmed.startsWith("{")) {
    let jwk: JsonWebKey;
    try {
      jwk = JSON.parse(trimmed) as JsonWebKey;
    } catch {
      throw new JwtError("The JWK is not valid JSON.");
    }
    if ("d" in jwk) {
      throw new JwtError("That JWK contains a private part (d). Paste only the public key.");
    }
    return crypto.subtle.importKey("jwk", jwk, params, false, ["verify"]);
  }
  if (!trimmed) throw new JwtError("Paste the issuer's public key (PEM or JWK).");
  return crypto.subtle.importKey("spki", new Uint8Array(pemToDer(trimmed)), params, false, [
    "verify",
  ]);
}

/**
 * Verify the signature locally with Web Crypto. The algorithm comes from the
 * token header but the *key type* is checked against it, so a mismatched key
 * is refused rather than reinterpreted.
 */
export async function verifyJwt(jwt: DecodedJwt, key: string): Promise<VerifyResult> {
  const alg = jwt.header.alg;
  if (typeof alg !== "string" || algorithmFamily(alg) === "none") {
    return { ok: false, reason: "Unsigned tokens (alg none) can never be verified." };
  }
  if (algorithmFamily(alg) === "unknown") {
    return { ok: false, reason: `Unsupported algorithm "${alg}".` };
  }
  try {
    const cryptoKey = await importVerifyKey(alg, key);
    const signature = new Uint8Array(base64UrlDecode(jwt.signature));
    const data = new TextEncoder().encode(jwt.signingInput);
    const family = algorithmFamily(alg);
    const params: AlgorithmIdentifier | RsaPssParams | EcdsaParams =
      family === "rsa-pss"
        ? { name: "RSA-PSS", saltLength: Number(alg.slice(2)) / 8 }
        : family === "ecdsa"
          ? { name: "ECDSA", hash: HASHES[alg.slice(2)]! }
          : cryptoKey.algorithm.name;
    const valid = await crypto.subtle.verify(params, cryptoKey, signature, data);
    return valid
      ? { ok: true }
      : {
          ok: false,
          reason:
            "The signature does not match this key. The token was altered or signed with a different key.",
        };
  } catch (error) {
    if (error instanceof JwtError || error instanceof DecodeError)
      return { ok: false, reason: error.message };
    return {
      ok: false,
      reason:
        "The key could not be used for this algorithm. Check that it is the right type and format.",
    };
  }
}

/** HMAC secrets shorter than the hash output weaken the MAC (RFC 7518 §3.2). */
export function weakHmacSecret(alg: unknown, secret: string): string | null {
  if (algorithmFamily(alg) !== "hmac" || !secret) return null;
  const needed = Number(String(alg).slice(2)) / 8;
  const have = new TextEncoder().encode(secret).length;
  return have < needed
    ? `This secret is ${have} bytes; ${String(alg)} requires at least ${needed} (RFC 7518 §3.2). Short secrets can be brute-forced offline from any token.`
    : null;
}
