import type { ZxcvbnResult } from "@zxcvbn-ts/core";
import { Eye, EyeOff } from "lucide-react";
import { useDeferredValue, useEffect, useId, useState } from "react";

import { Badge, Card, Spinner, cn } from "../../../../components/ui";
import { Explainer, LocalToolLayout } from "../shared/ui";
import {
  MAX_PASSWORD_CHARS,
  SCORE_LABELS,
  analyzeCharset,
  crackEstimates,
  explainPatterns,
  humanRange,
  recommendations,
} from "./analysis";
import { estimate } from "./estimator";

const SCORE_COLOURS = ["bg-sev-critical", "bg-sev-high", "bg-sev-medium", "bg-sev-low", "bg-ok"];

type EstimateState =
  | { status: "idle" }
  | { status: "ready"; password: string; result: ZxcvbnResult }
  | { status: "error" };

function useEstimate(password: string): EstimateState {
  const [state, setState] = useState<EstimateState>({ status: "idle" });
  useEffect(() => {
    if (!password) return;
    let cancelled = false;
    estimate(password).then(
      (result) => !cancelled && setState({ status: "ready", password, result }),
      () => !cancelled && setState({ status: "error" }),
    );
    return () => {
      cancelled = true;
    };
  }, [password]);
  return state;
}

function StrengthMeter({ score }: { score: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex gap-1" aria-hidden="true">
        {[0, 1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className={cn("h-2 flex-1 rounded-sm", i <= score ? SCORE_COLOURS[score] : "bg-border")}
          />
        ))}
      </div>
      <p className="text-sm font-semibold">
        Strength: {SCORE_LABELS[score]} <span className="text-muted">({score}/4)</span>
      </p>
    </div>
  );
}

export default function PasswordTool() {
  const inputId = useId();
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  // Typing stays responsive; the expensive analysis follows the deferred value.
  const deferred = useDeferredValue(password);
  const estimateState = useEstimate(deferred);
  const charset = analyzeCharset(deferred);
  const ready =
    deferred && estimateState.status === "ready" && estimateState.password === deferred
      ? estimateState.result
      : null;
  const patternBits = ready ? ready.guessesLog10 * Math.log2(10) : null;

  return (
    <LocalToolLayout
      title="Password Analyzer"
      description="See how an attacker would guess a password, not just how complex it looks."
    >
      <Card title="Password">
        <div className="flex flex-col gap-1.5">
          <label
            htmlFor={inputId}
            className="text-xs font-semibold tracking-wider text-muted uppercase"
          >
            Password to analyse
          </label>
          <div className="flex gap-2">
            <input
              id={inputId}
              type={visible ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              maxLength={MAX_PASSWORD_CHARS}
              // Not a login form: stop password managers from offering to save it.
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              className="min-w-0 flex-1 rounded border border-border-strong bg-surface px-3 py-2 text-sm focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setVisible((v) => !v)}
              aria-pressed={visible}
              aria-label={visible ? "Hide password" : "Show password"}
              className="rounded border border-border-strong px-2.5 text-muted hover:text-text"
            >
              {visible ? (
                <EyeOff size={16} aria-hidden="true" />
              ) : (
                <Eye size={16} aria-hidden="true" />
              )}
            </button>
          </div>
          <p className="text-xs text-muted">
            Analysed in this tab only. Prefer testing a password <em>like</em> yours rather than
            your real one.
          </p>
        </div>
      </Card>

      {deferred && (
        <>
          <Card title="Result">
            {estimateState.status === "error" ? (
              <p role="alert" className="text-sm text-fail">
                The pattern dictionaries failed to load. Reload the page to try again.
              </p>
            ) : !ready ? (
              <Spinner label="Analysing" />
            ) : (
              <div className="flex flex-col gap-4" aria-live="polite">
                <StrengthMeter score={ready.score} />
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded border border-border bg-surface p-3">
                    <p className="text-xs text-muted uppercase">Charset entropy</p>
                    <p className="text-xl font-semibold tabular-nums">
                      {charset.entropyBits.toFixed(1)} bits
                    </p>
                    <p className="text-xs text-muted">
                      {charset.length} characters × log₂({charset.poolSize}) — assumes every
                      character is random
                    </p>
                  </div>
                  <div className="rounded border border-border bg-surface p-3">
                    <p className="text-xs text-muted uppercase">Pattern-aware estimate</p>
                    <p className="text-xl font-semibold tabular-nums">
                      {patternBits!.toFixed(1)} bits
                    </p>
                    <p className="text-xs text-muted">
                      ≈ 10^{ready.guessesLog10.toFixed(1)} guesses, modelled on real cracking
                      strategies
                    </p>
                  </div>
                </div>
                {charset.entropyBits - patternBits! > 10 && (
                  <p className="rounded border border-warn/50 bg-warn/10 p-2 text-sm text-warn">
                    The charset figure overstates strength by{" "}
                    {Math.round(charset.entropyBits - patternBits!)} bits. Crackers do not try
                    random strings first; they try the patterns found below, so this password falls
                    much sooner than its length and character mix suggest.
                  </p>
                )}
                <div>
                  <h3 className="mb-1 text-xs font-semibold tracking-wider text-muted uppercase">
                    Character classes
                  </h3>
                  <ul className="flex flex-wrap gap-1.5">
                    {charset.classes.map((c) => (
                      <li key={c.id}>
                        <Badge>
                          {c.label} (+{c.poolSize})
                        </Badge>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </Card>

          {ready && (
            <>
              <Card title="Patterns found">
                <ul className="flex flex-col gap-2">
                  {explainPatterns(ready.sequence).map((p, i) => (
                    <li
                      key={`${p.token}-${i}`}
                      className="rounded border border-border bg-surface p-2.5 text-sm"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={p.kind === "No pattern" ? "ok" : "warn"}>{p.kind}</Badge>
                        <code className="break-all text-text">
                          {visible ? p.token : "•".repeat(Array.from(p.token).length)}
                        </code>
                      </div>
                      <p className="mt-1 text-xs text-muted">{p.explanation}</p>
                    </li>
                  ))}
                </ul>
              </Card>

              <Card title="Estimated time to crack">
                <table className="w-full text-left text-sm">
                  <caption className="sr-only">Crack-time estimates by attack scenario</caption>
                  <thead className="text-xs text-muted">
                    <tr>
                      <th scope="col" className="pb-2">
                        Scenario
                      </th>
                      <th scope="col" className="pb-2">
                        Time to exhaust the estimate
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {crackEstimates(ready.guesses).map((e) => (
                      <tr key={e.scenario.id} className="border-t border-border align-top">
                        <th scope="row" className="py-2 pr-4 font-semibold">
                          {e.scenario.title}
                          <p className="mt-0.5 text-xs font-normal text-muted">
                            {e.scenario.assumption}
                          </p>
                        </th>
                        <td className="py-2 whitespace-nowrap">{humanRange(e)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="mt-2 text-xs text-muted">
                  Ranges, not promises: real attackers may be faster (better hardware, a password
                  reused from another breach) or slower. A reused password is cracked instantly,
                  whatever its strength.
                </p>
              </Card>

              <Card title="Recommendations">
                <ul className="flex list-disc flex-col gap-1.5 pl-5 text-sm">
                  {recommendations(charset, ready).map((tip) => (
                    <li key={tip}>{tip}</li>
                  ))}
                </ul>
              </Card>
            </>
          )}
        </>
      )}

      <Explainer title="Why two different entropy numbers?" defaultOpen>
        <p>
          <strong>Charset entropy</strong> asks: if every character were picked at random, how many
          possibilities are there? That is right for a generated password like{" "}
          <code>q7#Lp2!vXz</code>.
        </p>
        <p>
          <strong>Pattern-aware estimation</strong> (zxcvbn) asks how real cracking tools would
          proceed: leaked-password lists first, then dictionary words with capitals, l33t swaps and
          years appended, then keyboard walks and dates. <code>P@ssw0rd1990</code> scores high on
          charset entropy and falls in seconds.
        </p>
      </Explainer>
      <Explainer title="Passphrases and password managers">
        <p>
          A <strong>passphrase</strong> of four or more randomly chosen words (Diceware) gives
          roughly 50+ bits that a human can remember. The words must be random: a famous quote is in
          the dictionary.
        </p>
        <p>
          A <strong>password manager</strong> lets every site get a long, unique, random password.
          That stops <strong>credential stuffing</strong>, where a password leaked from one site is
          tried on all the others. Combine it with multi-factor authentication where available.
        </p>
      </Explainer>
    </LocalToolLayout>
  );
}
