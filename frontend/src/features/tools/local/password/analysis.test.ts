import { describe, expect, it } from "vitest";

import {
  analyzeCharset,
  crackEstimates,
  explainPatterns,
  humanDuration,
  humanRange,
  recommendations,
} from "./analysis";
import { estimate } from "./estimator";

describe("charset entropy", () => {
  it("is length × log2(pool)", () => {
    const result = analyzeCharset("abcdefgh");
    expect(result.poolSize).toBe(26);
    expect(result.entropyBits).toBeCloseTo(8 * Math.log2(26), 6);
  });

  it("adds the pool of every class present", () => {
    const result = analyzeCharset("aA1!");
    expect(result.classes.map((c) => c.id)).toEqual(["lower", "upper", "digit", "symbol"]);
    expect(result.poolSize).toBe(26 + 26 + 10 + 32);
  });

  it("counts code points, not UTF-16 units", () => {
    const result = analyzeCharset("🔒é");
    expect(result.length).toBe(2);
    expect(result.classes.map((c) => c.id)).toEqual(["other"]);
  });

  it("handles spaces and the empty string", () => {
    expect(analyzeCharset("a b").classes.map((c) => c.id)).toEqual(["lower", "space"]);
    expect(analyzeCharset("")).toMatchObject({ length: 0, poolSize: 0, entropyBits: 0 });
  });

  it("counts unique characters", () => {
    expect(analyzeCharset("aaaa").uniqueChars).toBe(1);
  });
});

describe("crack-time estimates", () => {
  it("divides guesses by each scenario's rate range", () => {
    const [online, slow, fast] = crackEstimates(1e10);
    expect(online!.fastestSeconds).toBeCloseTo(1e9);
    expect(slow!.slowestSeconds).toBeCloseTo(1e7);
    expect(fast!.fastestSeconds).toBeCloseTo(0.1);
    for (const e of [online!, slow!, fast!]) {
      expect(e.fastestSeconds).toBeLessThanOrEqual(e.slowestSeconds);
      expect(e.scenario.assumption.length).toBeGreaterThan(20);
    }
  });

  it.each([
    [0.5, "instantly"],
    [1, "1 second"],
    [90, "1 minute"],
    [7200, "2 hours"],
    [3 * 86400, "3 days"],
    [2 * 365.25 * 86400, "2 years"],
    [500 * 365.25 * 86400, "5 centuries"],
    [Infinity, "longer than the age of the universe"],
  ])("humanises %d seconds as %s", (seconds, expected) => {
    expect(humanDuration(seconds)).toBe(expected);
  });

  it("collapses equal ends of a range", () => {
    const [, , fast] = crackEstimates(10);
    expect(humanRange(fast!)).toBe("instantly");
  });
});

describe("pattern-aware estimate (zxcvbn, bundled dictionaries)", () => {
  it("sees through a high-charset but predictable password", async () => {
    const charset = analyzeCharset("P@ssw0rd1990");
    const result = await estimate("P@ssw0rd1990");
    const patternBits = result.guessesLog10 * Math.log2(10);
    expect(charset.entropyBits).toBeGreaterThan(70);
    expect(patternBits).toBeLessThan(20);
    const kinds = explainPatterns(result.sequence).map((p) => p.kind);
    expect(kinds).toEqual(["Leetspeak word", "Recent year"]);
  });

  it.each([
    ["qwertyuiop", /Dictionary word|Keyboard walk/],
    ["aaaaaaaa", /Repetition/],
    ["abcdefgh", /Sequence/],
    ["zxcvbnm,./", /Keyboard walk/],
    ["14/03/1987", /Date/],
  ])("explains %s", async (password, kind) => {
    const kinds = explainPatterns((await estimate(password)).sequence).map((p) => p.kind);
    expect(kinds.join(" ")).toMatch(kind);
  });

  it("rates a random passphrase as strong", async () => {
    const result = await estimate("velvet-crater-orbit-nimble-sauce");
    expect(result.score).toBeGreaterThanOrEqual(4);
  });

  it("caps very long input", async () => {
    const result = await estimate("x".repeat(10_000));
    expect(result.password.length).toBeLessThanOrEqual(256);
  });
});

describe("recommendations", () => {
  it("always mentions a password manager and suggests length for short passwords", () => {
    const tips = recommendations(analyzeCharset("abc"), {
      score: 0,
      feedback: {
        warning: "This is a top-10 common password.",
        suggestions: ["Add another word or two."],
      },
    });
    expect(tips[0]).toMatch(/longer/);
    expect(tips).toContain("This is a top-10 common password.");
    expect(tips.some((t) => /passphrase/i.test(t))).toBe(true);
    expect(tips.at(-1)).toMatch(/password manager/);
  });

  it("does not push passphrases on strong passwords", () => {
    const tips = recommendations(analyzeCharset("velvet-crater-orbit-nimble-sauce"), {
      score: 4,
      feedback: { warning: null, suggestions: [] },
    });
    expect(tips.some((t) => /passphrase/i.test(t))).toBe(false);
  });
});
