import { ShieldCheck, ShieldX } from "lucide-react";
import { useMemo, useState } from "react";

import { Button, Card, JsonViewer, cn } from "../../../../components/ui";
import { formatDateTime } from "../../../../lib/format";
import { Callout, Explainer, FindingList, LocalToolLayout, TextAreaField } from "../shared/ui";
import {
  JwtError,
  MAX_TOKEN_CHARS,
  algorithmFamily,
  analyzeJwt,
  decodeJwt,
  timeClaims,
  verifyJwt,
  weakHmacSecret,
} from "./jwt";
import type { DecodedJwt, VerifyResult } from "./jwt";

function decodeSafely(token: string): { jwt: DecodedJwt | null; error: string | null } {
  if (!token.trim()) return { jwt: null, error: null };
  try {
    return { jwt: decodeJwt(token), error: null };
  } catch (error) {
    return {
      jwt: null,
      error: error instanceof JwtError ? error.message : "Could not decode the token.",
    };
  }
}

function VerifyPanel({ jwt }: { jwt: DecodedJwt }) {
  const [key, setKey] = useState("");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const family = algorithmFamily(jwt.header.alg);
  const isHmac = family === "hmac";
  const weak = weakHmacSecret(jwt.header.alg, key);

  if (family === "none" || family === "unknown") {
    return (
      <p className="text-sm text-muted">
        This token cannot be verified:{" "}
        {family === "none" ? "it is unsigned." : "its algorithm is not supported."}
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <TextAreaField
        label={isHmac ? "Shared secret" : "Issuer's public key (PEM or JWK)"}
        hint={
          isHmac
            ? "The secret is used only in this tab, in memory, and is cleared when you leave the page."
            : 'Paste the public key only (-----BEGIN PUBLIC KEY----- or a JWK without "d"). Never paste private keys.'
        }
        value={key}
        onChange={(e) => {
          setKey(e.target.value);
          setResult(null);
        }}
        rows={isHmac ? 2 : 5}
      />
      {weak && <p className="text-xs text-warn">{weak}</p>}
      <div>
        <Button
          size="sm"
          variant="secondary"
          loading={busy}
          disabled={!key}
          onClick={async () => {
            setBusy(true);
            setResult(await verifyJwt(jwt, key));
            setBusy(false);
          }}
        >
          Verify signature locally
        </Button>
      </div>
      {result && (
        <p
          role="status"
          className={cn(
            "flex items-start gap-2 rounded border p-2 text-sm",
            result.ok ? "border-ok/50 bg-ok/10 text-ok" : "border-fail/50 bg-fail/10 text-fail",
          )}
        >
          {result.ok ? (
            <ShieldCheck size={18} aria-hidden="true" className="shrink-0" />
          ) : (
            <ShieldX size={18} aria-hidden="true" className="shrink-0" />
          )}
          {result.ok
            ? `Signature valid for this key (${String(jwt.header.alg)}). The claims were not changed since signing. Expiry, audience and issuer still need checking by the application.`
            : result.reason}
        </p>
      )}
    </div>
  );
}

export default function JwtTool() {
  const [token, setToken] = useState("");
  const { jwt, error } = useMemo(() => decodeSafely(token), [token]);
  // Evaluated once per decode so relative times are stable while reading.
  const now = useMemo(() => (jwt ? new Date() : null), [jwt]);
  const findings = useMemo(() => (jwt && now ? analyzeJwt(jwt, now) : []), [jwt, now]);
  const times = useMemo(() => (jwt && now ? timeClaims(jwt.payload, now) : []), [jwt, now]);

  return (
    <LocalToolLayout
      title="JWT Inspector"
      description="Decode a JSON Web Token, read its claims and spot risky settings."
    >
      <Callout>
        Decoding is not verifying. Anyone can read or forge the contents below; only a signature
        check with the issuer's key shows the token is genuine.
      </Callout>

      <Card title="Token">
        <TextAreaField
          label="JWT"
          hint="Paste a token (a leading 'Bearer ' is fine). Treat real tokens as passwords: they grant access until they expire."
          value={token}
          onChange={(e) => setToken(e.target.value)}
          maxLength={MAX_TOKEN_CHARS + 16}
          error={error ?? undefined}
          rows={4}
        />
      </Card>

      {jwt && (
        <>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Header" eyebrow="Unverified">
              <JsonViewer value={jwt.header} label="JWT header" defaultExpandDepth={3} />
            </Card>
            <Card title="Payload (claims)" eyebrow="Unverified">
              <JsonViewer value={jwt.payload} label="JWT payload" defaultExpandDepth={3} />
            </Card>
          </div>

          {times.length > 0 && (
            <Card title="Timeline">
              <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm">
                {times.map((t) => (
                  <div key={t.claim} className="contents">
                    <dt className="text-muted">
                      {t.label} <code className="text-xs">({t.claim})</code>
                    </dt>
                    <dd>
                      {formatDateTime(t.date.toISOString())}{" "}
                      <span className="text-muted">— {t.relative}</span>
                    </dd>
                  </div>
                ))}
              </dl>
            </Card>
          )}

          <Card title="Findings">
            <FindingList findings={findings} />
          </Card>

          <Card title="Verify signature (optional, local)">
            <VerifyPanel key={jwt.signingInput + jwt.signature} jwt={jwt} />
          </Card>
        </>
      )}

      <Explainer title="How a JWT is built">
        <p>
          A signed JWT is three Base64URL segments joined by dots: <strong>header</strong>{" "}
          (algorithm, key id), <strong>payload</strong> (claims such as <code>sub</code>,{" "}
          <code>exp</code>) and <strong>signature</strong> over the first two. The first two are
          only encoded, not encrypted.
        </p>
        <p>
          A verifier must <strong>pin the algorithm</strong> it expects instead of trusting the
          header, and check <code>exp</code>, <code>nbf</code>, <code>iss</code> and{" "}
          <code>aud</code> after the signature.
        </p>
      </Explainer>
      <Explainer title="Common JWT attacks">
        <p>
          <strong>alg: none</strong>: strip the signature and claim the token is unsigned.
        </p>
        <p>
          <strong>Algorithm confusion</strong>: change RS256 to HS256 and sign with the server's
          <em> public</em> key as the HMAC secret. A verifier that picks the algorithm from the
          token accepts it. This tool refuses that combination.
        </p>
        <p>
          <strong>Key injection</strong>: point <code>jku</code>/<code>x5u</code> at an attacker URL
          or embed a <code>jwk</code>, so the verifier checks the signature with the attacker's own
          key.
        </p>
        <p>
          <strong>Weak HMAC secrets</strong>: any captured token lets an attacker brute-force the
          secret offline, then mint tokens.
        </p>
      </Explainer>
    </LocalToolLayout>
  );
}
