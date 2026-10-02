import { describe, expect, it } from "vitest";

import { base64Encode, base64UrlEncode, utf8Encode } from "../shared/bytes";
import {
  JwtError,
  algorithmFamily,
  analyzeJwt,
  decodeJwt,
  relativeTime,
  timeClaims,
  verifyJwt,
  weakHmacSecret,
} from "./jwt";

const NOW = new Date("2026-10-02T12:00:00Z");
const NOW_S = NOW.getTime() / 1000;

function segment(value: unknown): string {
  return base64UrlEncode(utf8Encode(JSON.stringify(value)));
}

function unsigned(header: object, payload: object, signature = "sig"): string {
  return `${segment(header)}.${segment(payload)}.${signature}`;
}

const ids = (token: string) => analyzeJwt(decodeJwt(token), NOW).map((f) => f.id);

// --- signing helpers (test-only) ------------------------------------------------------------

async function sign(
  alg: string,
  key: CryptoKey,
  params: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
  payload: object = { sub: "alice", exp: NOW_S + 600 },
): Promise<string> {
  const input = `${segment({ alg, typ: "JWT" })}.${segment(payload)}`;
  const sig = await crypto.subtle.sign(params, key, new TextEncoder().encode(input));
  return `${input}.${base64UrlEncode(new Uint8Array(sig))}`;
}

async function spkiPem(key: CryptoKey): Promise<string> {
  const der = new Uint8Array(await crypto.subtle.exportKey("spki", key));
  const b64 = base64Encode(der).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

// --- decoding ------------------------------------------------------------------------------------

describe("decodeJwt", () => {
  // The example token from RFC 7519 §3.1.
  const RFC_TOKEN =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  it("decodes the RFC 7519 example", () => {
    const jwt = decodeJwt(RFC_TOKEN);
    expect(jwt.header).toEqual({ typ: "JWT", alg: "HS256" });
    expect(jwt.payload).toEqual({
      iss: "joe",
      exp: 1300819380,
      "http://example.com/is_root": true,
    });
    expect(jwt.signature).toBe("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  });

  it("accepts a Bearer prefix and whitespace", () => {
    expect(decodeJwt(`  Bearer ${RFC_TOKEN}\n`).header.alg).toBe("HS256");
  });

  it.each([
    ["", /paste a token/i],
    ["abc", /three dot-separated parts/],
    ["a.b.c.d.e", /JWE/],
    ["!!.e30.x", /header is not valid Base64URL/],
    [`${segment({ alg: "HS256" })}.bm90IGpzb24.x`, /payload is not valid JSON/],
    [`${segment([1, 2])}.e30.x`, /header must be a JSON object/],
    [`${base64UrlEncode(Uint8Array.from([0xff]))}.e30.x`, /UTF-8/],
  ])("rejects %j", (input, message) => {
    expect(() => decodeJwt(input)).toThrow(JwtError);
    expect(() => decodeJwt(input)).toThrow(message);
  });

  it("caps the token size", () => {
    expect(() => decodeJwt("a".repeat(70_000))).toThrow(/longer than/);
  });
});

// --- analysis ---------------------------------------------------------------------------------------

describe("analyzeJwt", () => {
  it("flags alg none as CRITICAL", () => {
    const findings = analyzeJwt(decodeJwt(unsigned({ alg: "none" }, { exp: NOW_S + 60 }, "")), NOW);
    expect(findings[0]).toMatchObject({ id: "alg-none", severity: "CRITICAL" });
  });

  it.each(["none", "None", "NONE"])("treats %s case-insensitively", (alg) => {
    expect(algorithmFamily(alg)).toBe("none");
  });

  it("explains symmetric vs asymmetric algorithms", () => {
    expect(ids(unsigned({ alg: "HS256" }, { exp: NOW_S + 60 }))).toContain("alg-symmetric");
    expect(ids(unsigned({ alg: "ES256" }, { exp: NOW_S + 60 }))).toContain("alg-asymmetric");
    expect(ids(unsigned({ alg: "XX1" }, { exp: NOW_S + 60 }))).toContain("alg-unknown");
    expect(ids(unsigned({}, { exp: NOW_S + 60 }))).toContain("alg-missing");
  });

  it("flags a missing signature on a signed algorithm", () => {
    expect(ids(unsigned({ alg: "HS256" }, { exp: NOW_S + 60 }, ""))).toContain("signature-empty");
  });

  it("flags a missing exp", () => {
    expect(ids(unsigned({ alg: "HS256" }, { sub: "x" }))).toContain("exp-missing");
  });

  it("flags expired and not-yet-valid tokens", () => {
    const found = ids(unsigned({ alg: "HS256" }, { exp: NOW_S - 3600, nbf: NOW_S + 60 }));
    expect(found).toContain("expired");
    expect(found).toContain("not-yet-valid");
  });

  it("grades lifetimes", () => {
    expect(ids(unsigned({ alg: "HS256" }, { iat: NOW_S, exp: NOW_S + 3600 }))).not.toContain(
      "lifetime-long",
    );
    expect(ids(unsigned({ alg: "HS256" }, { iat: NOW_S, exp: NOW_S + 2 * 86400 }))).toContain(
      "lifetime-long",
    );
    expect(ids(unsigned({ alg: "HS256" }, { iat: NOW_S, exp: NOW_S + 90 * 86400 }))).toContain(
      "lifetime-very-long",
    );
  });

  it("flags iat in the future beyond clock skew", () => {
    expect(ids(unsigned({ alg: "HS256" }, { iat: NOW_S + 60, exp: NOW_S + 600 }))).not.toContain(
      "iat-future",
    );
    expect(ids(unsigned({ alg: "HS256" }, { iat: NOW_S + 3600, exp: NOW_S + 7200 }))).toContain(
      "iat-future",
    );
  });

  it("explains key-location headers", () => {
    const found = ids(
      unsigned(
        { alg: "RS256", jku: "https://evil.example/jwks", jwk: {}, x5c: [], kid: "k1" },
        { exp: NOW_S + 60 },
      ),
    );
    expect(found).toEqual(
      expect.arrayContaining(["header-key-url", "header-embedded-jwk", "header-x5c", "header-kid"]),
    );
  });

  it("rates an injection-looking kid higher", () => {
    const [kid] = analyzeJwt(
      decodeJwt(unsigned({ alg: "HS256", kid: "../../dev/null" }, { exp: NOW_S + 60 })),
      NOW,
    ).filter((f) => f.id === "header-kid");
    expect(kid?.severity).toBe("MEDIUM");
  });

  it("finds sensitive and personal data, including nested", () => {
    const findings = analyzeJwt(
      decodeJwt(
        unsigned(
          { alg: "HS256" },
          {
            exp: NOW_S + 60,
            email: "a@b.c",
            profile: { password: "x" },
            key: "-----BEGIN RSA PRIVATE KEY-----",
          },
        ),
      ),
      NOW,
    );
    const sensitive = findings.find((f) => f.id === "payload-sensitive");
    expect(sensitive?.severity).toBe("HIGH");
    expect(sensitive?.explanation).toContain('"profile.password"');
    expect(sensitive?.explanation).toContain('"key"');
    expect(findings.find((f) => f.id === "payload-pii")?.explanation).toContain('"email"');
  });

  it("orders findings most severe first", () => {
    const findings = analyzeJwt(decodeJwt(unsigned({ alg: "none" }, { password: "x" }, "")), NOW);
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const ranks = findings.map((f) => order.indexOf(f.severity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe("time claims", () => {
  it("renders NumericDates with relative time", () => {
    const claims = timeClaims({ iat: NOW_S - 7200, exp: NOW_S + 3600, nbf: "bad" }, NOW);
    expect(claims.map((c) => [c.claim, c.relative])).toEqual([
      ["iat", "2 hours ago"],
      ["exp", "in 1 hour"],
    ]);
  });

  it("ignores absurd values", () => {
    expect(timeClaims({ exp: 1e20, iat: -5 }, NOW)).toEqual([]);
  });

  it("formats relative times", () => {
    expect(relativeTime(new Date(NOW.getTime() + 3 * 86400_000), NOW)).toBe("in 3 days");
    expect(relativeTime(NOW, NOW)).toBe("now");
  });
});

// --- verification ---------------------------------------------------------------------------------------

describe("verifyJwt (Web Crypto)", () => {
  it("verifies HS256 and rejects a wrong secret", async () => {
    const secret = "a-very-long-shared-secret-of-32+bytes!";
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const token = await sign("HS256", key, "HMAC");
    expect(await verifyJwt(decodeJwt(token), secret)).toEqual({ ok: true });
    expect(await verifyJwt(decodeJwt(token), "wrong")).toMatchObject({ ok: false });
  });

  it("detects a tampered payload", async () => {
    const secret = "a-very-long-shared-secret-of-32+bytes!";
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const [h, , s] = (await sign("HS256", key, "HMAC")).split(".");
    const forged = `${h}.${segment({ sub: "admin" })}.${s}`;
    expect(await verifyJwt(decodeJwt(forged), secret)).toMatchObject({ ok: false });
  });

  it("verifies RS256 with a PEM public key and with a JWK", async () => {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const token = await sign("RS256", pair.privateKey, "RSASSA-PKCS1-v1_5");
    expect(await verifyJwt(decodeJwt(token), await spkiPem(pair.publicKey))).toEqual({ ok: true });
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    expect(await verifyJwt(decodeJwt(token), JSON.stringify(jwk))).toEqual({ ok: true });
  });

  it("verifies PS256", async () => {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const token = await sign("PS256", pair.privateKey, { name: "RSA-PSS", saltLength: 32 });
    expect(await verifyJwt(decodeJwt(token), await spkiPem(pair.publicKey))).toEqual({ ok: true });
  });

  it("verifies ES256 (raw r||s signatures)", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const token = await sign("ES256", pair.privateKey, { name: "ECDSA", hash: "SHA-256" });
    expect(await verifyJwt(decodeJwt(token), await spkiPem(pair.publicKey))).toEqual({ ok: true });
  });

  it("verifies EdDSA (Ed25519)", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const token = await sign("EdDSA", pair.privateKey, { name: "Ed25519" });
    expect(await verifyJwt(decodeJwt(token), await spkiPem(pair.publicKey))).toEqual({ ok: true });
  });

  it("refuses the algorithm-confusion attack (HS256 with a public key as secret)", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const pem = await spkiPem(pair.publicKey);
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(pem),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const forged = await sign("HS256", hmacKey, "HMAC");
    const result = await verifyJwt(decodeJwt(forged), pem);
    expect(result).toMatchObject({ ok: false });
    expect(!result.ok && result.reason).toMatch(/algorithm confusion/);
  });

  it("never verifies alg none", async () => {
    expect(await verifyJwt(decodeJwt(unsigned({ alg: "none" }, {}, "")), "anything")).toMatchObject(
      {
        ok: false,
      },
    );
  });

  it("refuses private keys", async () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
    const result = await verifyJwt(decodeJwt(unsigned({ alg: "RS256" }, {})), pem);
    expect(!result.ok && result.reason).toMatch(/PRIVATE key/);
    const jwkResult = await verifyJwt(
      decodeJwt(unsigned({ alg: "ES256" }, {})),
      JSON.stringify({ kty: "EC", crv: "P-256", x: "a", y: "b", d: "secret" }),
    );
    expect(!jwkResult.ok && jwkResult.reason).toMatch(/private part/);
  });

  it("explains an unusable key", async () => {
    const result = await verifyJwt(decodeJwt(unsigned({ alg: "RS256" }, {})), "not a key");
    expect(result).toMatchObject({ ok: false });
  });
});

describe("weakHmacSecret", () => {
  it("warns about secrets shorter than the hash", () => {
    expect(weakHmacSecret("HS256", "short")).toMatch(/5 bytes; HS256 requires at least 32/);
    expect(weakHmacSecret("HS512", "x".repeat(64))).toBeNull();
    expect(weakHmacSecret("RS256", "short")).toBeNull();
  });
});
