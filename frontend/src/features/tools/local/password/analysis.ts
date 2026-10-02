/**
 * Password strength analysis (02-modules.md, client-side utility 1).
 *
 * Two estimates are shown side by side, because the gap between them is the
 * lesson:
 *
 * - **Charset entropy** (`length × log2(pool)`) assumes every character was
 *   picked uniformly at random from the character classes present. That is
 *   only true for machine-generated passwords.
 * - **Pattern-aware entropy** (zxcvbn) models how crackers actually guess:
 *   dictionaries, leaked-password lists, keyboard walks, dates, sequences,
 *   repeats and l33t substitutions. "P@ssw0rd1990" has a large charset but
 *   is guessed almost immediately.
 *
 * Pure functions only. The zxcvbn engine is injected (see estimator.ts) so it
 * can be lazy-loaded and this module stays cheap to test.
 */

import type { ZxcvbnResult } from "@zxcvbn-ts/core";

export const MAX_PASSWORD_CHARS = 256;

// --- character classes -------------------------------------------------------------

export interface CharClass {
  id: "lower" | "upper" | "digit" | "symbol" | "space" | "other";
  label: string;
  /** Characters an attacker must consider if this class is used. */
  poolSize: number;
}

export const CHAR_CLASSES: CharClass[] = [
  { id: "lower", label: "Lowercase a–z", poolSize: 26 },
  { id: "upper", label: "Uppercase A–Z", poolSize: 26 },
  { id: "digit", label: "Digits 0–9", poolSize: 10 },
  { id: "symbol", label: "ASCII symbols", poolSize: 32 },
  { id: "space", label: "Space", poolSize: 1 },
  // A conservative figure: real attacks rarely enumerate all of Unicode.
  { id: "other", label: "Other Unicode", poolSize: 100 },
];

function classify(ch: string): CharClass["id"] {
  if (/[a-z]/.test(ch)) return "lower";
  if (/[A-Z]/.test(ch)) return "upper";
  if (/[0-9]/.test(ch)) return "digit";
  if (ch === " ") return "space";
  if (/[!-/:-@[-`{-~]/.test(ch)) return "symbol";
  return "other";
}

export interface CharsetAnalysis {
  /** Length in Unicode code points, not UTF-16 units ("🔒" counts as 1). */
  length: number;
  classes: CharClass[];
  poolSize: number;
  /** length × log2(poolSize) */
  entropyBits: number;
  uniqueChars: number;
}

export function analyzeCharset(password: string): CharsetAnalysis {
  const chars = Array.from(password);
  const present = new Set(chars.map(classify));
  const classes = CHAR_CLASSES.filter((c) => present.has(c.id));
  const poolSize = classes.reduce((sum, c) => sum + c.poolSize, 0);
  return {
    length: chars.length,
    classes,
    poolSize,
    entropyBits: poolSize > 0 ? chars.length * Math.log2(poolSize) : 0,
    uniqueChars: new Set(chars).size,
  };
}

// --- crack-time scenarios ----------------------------------------------------------------

export interface Scenario {
  id: string;
  title: string;
  /** Guesses per second, low and high end of the assumed range. */
  rateLow: number;
  rateHigh: number;
  assumption: string;
}

/**
 * Attack scenarios with their assumptions spelled out, because a crack time
 * without its assumptions is meaningless.
 */
export const SCENARIOS: Scenario[] = [
  {
    id: "online-throttled",
    title: "Online, rate-limited login",
    rateLow: 100 / 3600,
    rateHigh: 10,
    assumption:
      "Guessing through a login form that enforces lockout or rate limits (Sentinel allows 10 attempts per minute per IP): roughly 100 per hour to 10 per second across many IPs.",
  },
  {
    id: "offline-slow",
    title: "Offline, slow hash (bcrypt, scrypt, Argon2)",
    rateLow: 1e3,
    rateHigh: 1e5,
    assumption:
      "The password database leaked and passwords were stored with a deliberately slow, salted hash. One GPU to a small cracking rig.",
  },
  {
    id: "offline-fast",
    title: "Offline, fast hash (MD5, SHA-1, SHA-256)",
    rateLow: 1e9,
    rateHigh: 1e11,
    assumption:
      "The database leaked and passwords were stored with a fast general-purpose hash. A single modern GPU does billions of guesses per second.",
  },
];

export interface CrackEstimate {
  scenario: Scenario;
  /** Time to exhaust the estimated guesses at the high and low rate. */
  fastestSeconds: number;
  slowestSeconds: number;
}

export function crackEstimates(guesses: number): CrackEstimate[] {
  return SCENARIOS.map((scenario) => ({
    scenario,
    fastestSeconds: guesses / scenario.rateHigh,
    slowestSeconds: guesses / scenario.rateLow,
  }));
}

const DURATIONS: Array<[number, string]> = [
  [60, "second"],
  [60, "minute"],
  [24, "hour"],
  [365.25, "day"],
  [100, "year"],
  [Number.POSITIVE_INFINITY, "century"],
];

export function humanDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds > 1e13 * 3.15e7)
    return "longer than the age of the universe";
  if (seconds < 1) return "instantly";
  let value = seconds;
  for (const [size, unit] of DURATIONS) {
    if (value < size) {
      const rounded = Math.floor(value);
      const plural = unit === "century" ? "centuries" : `${unit}s`;
      return `${rounded} ${rounded === 1 ? unit : plural}`;
    }
    value /= size;
  }
  return "centuries";
}

export function humanRange(estimate: CrackEstimate): string {
  const fast = humanDuration(estimate.fastestSeconds);
  const slow = humanDuration(estimate.slowestSeconds);
  return fast === slow ? fast : `${fast} – ${slow}`;
}

// --- pattern explanations -----------------------------------------------------------------

export interface PatternExplanation {
  token: string;
  kind: string;
  explanation: string;
}

type Match = ZxcvbnResult["sequence"][number];

const DICTIONARY_LABELS: Record<string, string> = {
  passwords: "a list of leaked passwords",
  commonWords: "a list of common words",
  firstnames: "a list of first names",
  lastnames: "a list of surnames",
  wikipedia: "words common on Wikipedia",
  userInputs: "your own details",
  diceware: "the Diceware word list",
};

function dictionaryLabel(name: unknown): string {
  const base = String(name ?? "").replace(/-.*$/, "");
  return DICTIONARY_LABELS[base] ?? "a word list";
}

/** Turn zxcvbn's match sequence into plain-language explanations. */
export function explainPatterns(sequence: Match[]): PatternExplanation[] {
  const out: PatternExplanation[] = [];
  for (const match of sequence) {
    const token = String(match.token);
    switch (match.pattern) {
      case "dictionary": {
        const extras = [
          match.l33t
            ? "with l33t substitutions (like @ for a, 0 for o), which crackers try automatically"
            : null,
          match.reversed ? "written backwards, which crackers also try" : null,
        ].filter(Boolean);
        out.push({
          token,
          kind: match.l33t ? "Leetspeak word" : "Dictionary word",
          explanation: `Found in ${dictionaryLabel(match.dictionaryName)}${typeof match.rank === "number" ? ` (rank ${match.rank})` : ""}${extras.length ? `, ${extras.join(" and ")}` : ""}.`,
        });
        break;
      }
      case "spatial":
        out.push({
          token,
          kind: "Keyboard walk",
          explanation: `Adjacent keys on a ${String(match.graph ?? "keyboard")} layout. Crackers enumerate keyboard paths.`,
        });
        break;
      case "repeat":
        out.push({
          token,
          kind: "Repetition",
          explanation: `"${String(match.baseToken ?? token)}" repeated ${String(match.repeatCount ?? "")} times adds almost nothing over writing it once.`,
        });
        break;
      case "sequence":
        out.push({
          token,
          kind: "Sequence",
          explanation: `A run of consecutive ${String(match.sequenceName ?? "characters")} characters, among the first things guessed.`,
        });
        break;
      case "date":
        out.push({
          token,
          kind: "Date",
          explanation:
            "Looks like a date. Birthdays and anniversaries are easy to research and to enumerate.",
        });
        break;
      case "regex":
        out.push({
          token,
          kind: match.regexName === "recentYear" ? "Recent year" : "Common pattern",
          explanation:
            match.regexName === "recentYear"
              ? "Recent years are among the most common password suffixes."
              : "Matches a common pattern crackers try early.",
        });
        break;
      case "separator":
        break;
      case "bruteforce":
        out.push({
          token,
          kind: "No pattern",
          explanation: "No known pattern found; an attacker has to brute-force this part.",
        });
        break;
      default:
        out.push({
          token,
          kind: String(match.pattern),
          explanation: "Matches a known guessing pattern.",
        });
    }
  }
  return out;
}

// --- recommendations ------------------------------------------------------------------------

export function recommendations(
  charset: CharsetAnalysis,
  result: Pick<ZxcvbnResult, "score" | "feedback">,
): string[] {
  const tips: string[] = [];
  if (charset.length < 12) {
    tips.push(
      "Make it longer. Length beats complexity: aim for 15+ characters, or 4+ random words.",
    );
  }
  if (result.feedback.warning) tips.push(result.feedback.warning);
  tips.push(...result.feedback.suggestions);
  if (charset.length > 0 && charset.uniqueChars <= 3) {
    tips.push("Use more distinct characters; a few repeated characters add little.");
  }
  if (result.score < 3) {
    tips.push(
      "Try a passphrase: four or more random, unrelated words (e.g. from Diceware) are long, memorable and hard to guess.",
    );
  }
  tips.push(
    "Use a password manager to generate and remember a unique password for every site, so one breach cannot unlock the others.",
  );
  return [...new Set(tips)];
}

/** zxcvbn score 0–4 as words. */
export const SCORE_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"] as const;
