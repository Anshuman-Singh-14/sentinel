import { ArrowDownUp, CircleCheck, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { Button, Card, cn } from "../../../../components/ui";
import { bytesToHex } from "../shared/bytes";
import {
  Callout,
  CopyButton,
  Explainer,
  LocalToolLayout,
  TextAreaField,
  TransformComparison,
} from "../shared/ui";
import { FORMATS, MAX_INPUT_CHARS, decode, detectFormats, encode, roundTrips } from "./codec";
import type { Format } from "./codec";

type Direction = "encode" | "decode";

type Output =
  | { kind: "empty" }
  | { kind: "text"; value: string; roundTrip: boolean }
  | { kind: "binary"; hex: string; byteLength: number; roundTrip: boolean }
  | { kind: "error"; message: string };

function compute(format: Format, direction: Direction, input: string): Output {
  if (!input) return { kind: "empty" };
  if (input.length > MAX_INPUT_CHARS) {
    return {
      kind: "error",
      message: `Input is limited to ${MAX_INPUT_CHARS.toLocaleString()} characters.`,
    };
  }
  try {
    if (direction === "encode") {
      return {
        kind: "text",
        value: encode(format, input),
        roundTrip: roundTrips(format, "encode", input),
      };
    }
    const result = decode(format, input);
    const roundTrip = roundTrips(format, "decode", input);
    return result.text === null
      ? {
          kind: "binary",
          hex: bytesToHex(result.bytes.slice(0, 4096)),
          byteLength: result.bytes.length,
          roundTrip,
        }
      : { kind: "text", value: result.text, roundTrip };
  } catch (error) {
    return { kind: "error", message: (error as Error).message };
  }
}

export default function EncoderTool() {
  const [format, setFormat] = useState<Format>("base64");
  const [direction, setDirection] = useState<Direction>("encode");
  const [input, setInput] = useState("");

  const output = useMemo(() => compute(format, direction, input), [format, direction, input]);
  const suggestions = useMemo(
    () => (direction === "decode" ? detectFormats(input).filter((s) => s.format !== format) : []),
    [direction, format, input],
  );

  const swap = () => {
    if (output.kind === "text") setInput(output.value);
    setDirection((d) => (d === "encode" ? "decode" : "encode"));
  };

  return (
    <LocalToolLayout
      title="Encoder / Decoder"
      description="Convert text to and from Base64, Base64URL, URL encoding and hex."
    >
      <Callout>
        Encoding is not encryption. Anyone can decode these formats; they hide nothing.
      </Callout>

      <Card title="Convert">
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-end gap-4">
            <fieldset className="flex flex-col gap-1.5">
              <legend className="text-xs font-semibold tracking-wider text-muted uppercase">
                Format
              </legend>
              <div className="flex flex-wrap gap-1">
                {(Object.keys(FORMATS) as Format[]).map((f) => (
                  <label
                    key={f}
                    className={cn(
                      "cursor-pointer rounded border px-2.5 py-1 text-xs font-semibold has-focus-visible:outline-2 has-focus-visible:outline-accent",
                      format === f
                        ? "border-accent bg-accent/10 text-accent"
                        : "border-border-strong text-muted hover:text-text",
                    )}
                  >
                    <input
                      type="radio"
                      name="format"
                      value={f}
                      checked={format === f}
                      onChange={() => setFormat(f)}
                      className="sr-only"
                    />
                    {FORMATS[f].label}
                  </label>
                ))}
              </div>
            </fieldset>
            <fieldset className="flex flex-col gap-1.5">
              <legend className="text-xs font-semibold tracking-wider text-muted uppercase">
                Direction
              </legend>
              <div className="flex gap-1">
                {(["encode", "decode"] as const).map((d) => (
                  <label
                    key={d}
                    className={cn(
                      "cursor-pointer rounded border px-2.5 py-1 text-xs font-semibold capitalize has-focus-visible:outline-2 has-focus-visible:outline-accent",
                      direction === d
                        ? "border-accent bg-accent/10 text-accent"
                        : "border-border-strong text-muted hover:text-text",
                    )}
                  >
                    <input
                      type="radio"
                      name="direction"
                      value={d}
                      checked={direction === d}
                      onChange={() => setDirection(d)}
                      className="sr-only"
                    />
                    {d}
                  </label>
                ))}
              </div>
            </fieldset>
            <Button variant="secondary" size="sm" onClick={swap} disabled={output.kind !== "text"}>
              <ArrowDownUp size={14} aria-hidden="true" />
              Use output as input
            </Button>
          </div>
          <p className="text-xs text-muted">{FORMATS[format].description}</p>

          <TextAreaField
            label={direction === "encode" ? "Text to encode" : `${FORMATS[format].label} to decode`}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            maxLength={MAX_INPUT_CHARS}
            error={output.kind === "error" ? output.message : undefined}
          />

          {suggestions.length > 0 && (
            <div role="status" className="rounded border border-accent/40 bg-accent/5 p-3 text-xs">
              <p className="font-semibold text-accent">This input also decodes cleanly as:</p>
              <ul className="mt-1 flex flex-col gap-1">
                {suggestions.map((s) => (
                  <li key={s.format} className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setFormat(s.format)}
                      className="font-semibold text-accent underline"
                    >
                      {FORMATS[s.format].label}
                    </button>
                    <span className="text-muted">({s.reason})</span>
                    <span className="truncate text-text">→ {s.preview}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <section aria-label="Output" className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-xs font-semibold tracking-wider text-muted uppercase">Output</h2>
              <CopyButton
                value={
                  output.kind === "text" ? output.value : output.kind === "binary" ? output.hex : ""
                }
              />
            </div>
            <output
              aria-live="polite"
              className="min-h-24 rounded border border-border bg-surface px-3 py-2 text-sm break-all whitespace-pre-wrap"
            >
              {output.kind === "text" && output.value}
              {output.kind === "binary" && (
                <>
                  <span className="block text-xs text-warn">
                    The result is {output.byteLength} bytes of binary data, not UTF-8 text. Shown as
                    hex
                    {output.byteLength > 4096 ? " (first 4096 bytes)" : ""}:
                  </span>
                  {output.hex}
                </>
              )}
            </output>
            {(output.kind === "text" || output.kind === "binary") && (
              <p
                className={cn(
                  "flex items-center gap-1.5 text-xs",
                  output.roundTrip ? "text-ok" : "text-warn",
                )}
              >
                {output.roundTrip ? (
                  <CircleCheck size={14} aria-hidden="true" />
                ) : (
                  <TriangleAlert size={14} aria-hidden="true" />
                )}
                {output.roundTrip
                  ? "Round-trip check passed: converting back gives the original."
                  : "Round-trip check failed: the input is not in canonical form, so converting back gives a different string."}
              </p>
            )}
          </section>
        </div>
      </Card>

      <Explainer title="Encoding vs hashing vs encryption" defaultOpen>
        <TransformComparison />
        <p>
          <strong>Encoding</strong> changes how data is written so it survives a channel (an email,
          a URL, a JSON string). It is public and reversible by design. Seeing Base64 in a config
          file or a JWT tells you nothing is protected.
        </p>
      </Explainer>
      <Explainer title="Where you meet each format">
        <p>
          <strong>Base64</strong>: email attachments, <code>data:</code> URIs, PEM keys, HTTP Basic
          auth (which is why Basic auth over plain HTTP exposes the password).
        </p>
        <p>
          <strong>Base64URL</strong>: JWT segments, URL-safe tokens. Same as Base64 with{" "}
          <code>-</code> and <code>_</code> instead of <code>+</code> and <code>/</code>, usually
          without padding.
        </p>
        <p>
          <strong>URL encoding</strong>: query strings and form posts. Attackers use double encoding
          (<code>%252e</code>) to slip past filters that decode once.
        </p>
        <p>
          <strong>Hex</strong>: hash digests, packet dumps, binary file signatures.
        </p>
      </Explainer>
    </LocalToolLayout>
  );
}
