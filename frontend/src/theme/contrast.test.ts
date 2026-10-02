// @vitest-environment node
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { contrastRatio, parseColorTokens } from "./contrast";

// Read the stylesheet from disk: Vitest replaces CSS imports with empty modules.
const css = readFileSync(fileURLToPath(new URL("../index.css", import.meta.url)), "utf-8");
const tokens = parseColorTokens(css);

const TEXT_TOKENS = [
  "text",
  "muted",
  "accent",
  "accent-strong",
  "ok",
  "warn",
  "fail",
  "sev-critical",
  "sev-high",
  "sev-medium",
  "sev-low",
  "sev-info",
];
const BACKGROUNDS = ["surface", "panel", "panel-raised"];
const AA_NORMAL_TEXT = 4.5;

describe("theme contrast (WCAG AA)", () => {
  it("computes known reference ratios", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrastRatio("#777777", "#ffffff")).toBeCloseTo(4.48, 2);
  });

  it("parses every token used by the test", () => {
    for (const name of [...TEXT_TOKENS, ...BACKGROUNDS, "on-accent"]) {
      expect(tokens[name], `missing --color-${name}`).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  for (const fg of TEXT_TOKENS) {
    for (const bg of BACKGROUNDS) {
      it(`${fg} on ${bg} reaches ${AA_NORMAL_TEXT}:1`, () => {
        expect(contrastRatio(tokens[fg]!, tokens[bg]!)).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
      });
    }
  }

  it("primary button text is readable on the accent fill", () => {
    expect(contrastRatio(tokens["on-accent"]!, tokens["accent"]!)).toBeGreaterThanOrEqual(
      AA_NORMAL_TEXT,
    );
  });
});
