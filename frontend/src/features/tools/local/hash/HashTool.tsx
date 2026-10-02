import { CircleCheck, CircleX, FileUp } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Badge, Button, Card, Tabs, cn } from "../../../../components/ui";
import {
  Explainer,
  CopyButton,
  LocalToolLayout,
  TextAreaField,
  TransformComparison,
} from "../shared/ui";
import {
  ALGORITHMS,
  ALGORITHM_ORDER,
  MAX_FILE_BYTES,
  compareDigest,
  formatBytes,
  hashFile,
  hashText,
} from "./hashing";
import type { HashAlgorithm } from "./hashing";

type Digests = Partial<Record<HashAlgorithm, string>>;

function AlgorithmPicker({
  selected,
  onChange,
}: {
  selected: HashAlgorithm[];
  onChange: (next: HashAlgorithm[]) => void;
}) {
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="text-xs font-semibold tracking-wider text-muted uppercase">
        Algorithms
      </legend>
      <div className="flex flex-wrap gap-3">
        {ALGORITHM_ORDER.map((algorithm) => (
          <label key={algorithm} className="flex items-center gap-1.5 text-sm">
            <input
              type="checkbox"
              className="accent-accent"
              checked={selected.includes(algorithm)}
              onChange={(e) =>
                onChange(
                  e.target.checked
                    ? ALGORITHM_ORDER.filter((a) => a === algorithm || selected.includes(a))
                    : selected.filter((a) => a !== algorithm),
                )
              }
            />
            {algorithm}
            {ALGORITHMS[algorithm].legacy && <Badge tone="warn">legacy</Badge>}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function DigestList({ digests }: { digests: Digests }) {
  const entries = ALGORITHM_ORDER.filter((a) => digests[a]);
  if (entries.length === 0) return null;
  return (
    <dl className="flex flex-col gap-3">
      {entries.map((algorithm) => (
        <div key={algorithm} className="rounded border border-border bg-surface p-3">
          <dt className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="flex items-center gap-2 font-semibold">
              {algorithm}
              {ALGORITHMS[algorithm].legacy && (
                <Badge tone="warn">Legacy — not collision resistant</Badge>
              )}
            </span>
            <CopyButton value={digests[algorithm]!} label={`Copy ${algorithm}`} />
          </dt>
          <dd className="mt-1 text-sm break-all text-text">{digests[algorithm]}</dd>
          <dd className="mt-1 text-xs text-muted">{ALGORITHMS[algorithm].note}</dd>
        </div>
      ))}
    </dl>
  );
}

function Verify({ digests }: { digests: Digests }) {
  const [expected, setExpected] = useState("");
  const hasDigests = Object.keys(digests).length > 0;
  const result = expected.trim() && hasDigests ? compareDigest(expected, digests) : null;
  return (
    <div className="flex flex-col gap-2">
      <TextAreaField
        label="Expected hash (optional)"
        hint="Paste a published checksum. Case, spaces, a 'sha256:' prefix and sha256sum's filename are ignored."
        value={expected}
        onChange={(e) => setExpected(e.target.value)}
        rows={2}
        className="[&_textarea]:min-h-0"
      />
      {result && (
        <p
          role="status"
          className={cn(
            "flex items-start gap-2 rounded border p-2 text-sm",
            result.kind === "match"
              ? "border-ok/50 bg-ok/10 text-ok"
              : "border-fail/50 bg-fail/10 text-fail",
          )}
        >
          {result.kind === "match" ? (
            <CircleCheck size={18} aria-hidden="true" className="shrink-0" />
          ) : (
            <CircleX size={18} aria-hidden="true" className="shrink-0" />
          )}
          {result.kind === "match" && `Match: identical ${result.algorithm} digest.`}
          {result.kind === "invalid" && "That is not a hex digest."}
          {result.kind === "mismatch" &&
            (result.expectedAlgorithms.length === 0
              ? "No match, and the length does not fit any supported algorithm."
              : result.expectedAlgorithms.every((a) => digests[a])
                ? `No match. The data differs from what the checksum describes (expected a ${result.expectedAlgorithms.join("/")} digest).`
                : `No match yet: the expected value looks like ${result.expectedAlgorithms.join("/")}. Select that algorithm.`)}
        </p>
      )}
    </div>
  );
}

function TextMode({ algorithms }: { algorithms: HashAlgorithm[] }) {
  const [text, setText] = useState("");
  const [digests, setDigests] = useState<Digests>({});

  useEffect(() => {
    let cancelled = false;
    void Promise.all(algorithms.map(async (a) => [a, await hashText(a, text)] as const)).then(
      (pairs) => {
        if (!cancelled) setDigests(Object.fromEntries(pairs));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [text, algorithms]);

  return (
    <div className="flex flex-col gap-4">
      <TextAreaField
        label="Text to hash"
        hint="Hashed as UTF-8. Trailing spaces and newlines change the result."
        value={text}
        onChange={(e) => setText(e.target.value)}
        maxLength={1_000_000}
      />
      <DigestList digests={digests} />
      <Verify digests={digests} />
    </div>
  );
}

function FileMode({ algorithms }: { algorithms: HashAlgorithm[] }) {
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [digests, setDigests] = useState<Digests>({});
  const [error, setError] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  const run = async (selected: File) => {
    controller.current?.abort();
    const ctrl = new AbortController();
    controller.current = ctrl;
    setFile(selected);
    setDigests({});
    setError(null);
    setProgress(0);
    try {
      const result = await hashFile(selected, algorithms, {
        onProgress: setProgress,
        signal: ctrl.signal,
      });
      if (!ctrl.signal.aborted) setDigests(result);
    } catch (e) {
      if (!ctrl.signal.aborted) setError((e as Error).message);
    } finally {
      if (controller.current === ctrl) setProgress(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <label className="flex cursor-pointer flex-col items-center gap-2 rounded border border-dashed border-border-strong bg-surface p-6 text-center text-sm text-muted hover:border-accent has-focus-visible:outline-2 has-focus-visible:outline-accent">
        <FileUp size={24} aria-hidden="true" className="text-accent" />
        <span>
          Choose a file to hash. It is read in chunks inside your browser and never uploaded (limit{" "}
          {formatBytes(MAX_FILE_BYTES)}).
        </span>
        <input
          type="file"
          className="sr-only"
          onChange={(e) => {
            const selected = e.target.files?.[0];
            if (selected) void run(selected);
            e.target.value = "";
          }}
        />
      </label>
      {file && (
        <p className="text-sm">
          <span className="text-muted">File: </span>
          {file.name} <span className="text-muted">({formatBytes(file.size)})</span>
        </p>
      )}
      {progress !== null && (
        <div className="flex items-center gap-3">
          <progress
            value={progress}
            max={1}
            aria-label="Hashing progress"
            className="h-2 flex-1 accent-accent"
          />
          <span className="text-xs text-muted tabular-nums">{Math.round(progress * 100)}%</span>
          <Button size="sm" variant="ghost" onClick={() => controller.current?.abort()}>
            Cancel
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-fail">
          {error}
        </p>
      )}
      <DigestList digests={digests} />
      <Verify digests={digests} />
    </div>
  );
}

export default function HashTool() {
  const [algorithms, setAlgorithms] = useState<HashAlgorithm[]>(["SHA-256", "SHA-512"]);
  return (
    <LocalToolLayout
      title="Hash Generator & Verifier"
      description="Compute SHA-2 (and legacy SHA-1/MD5) digests of text or files and check them against a published checksum."
    >
      <Card title="Hash">
        <div className="flex flex-col gap-4">
          <AlgorithmPicker selected={algorithms} onChange={setAlgorithms} />
          <Tabs
            label="Input type"
            items={[
              { id: "text", label: "Text", content: <TextMode algorithms={algorithms} /> },
              { id: "file", label: "File", content: <FileMode algorithms={algorithms} /> },
            ]}
          />
        </div>
      </Card>

      <Explainer title="Hashing vs encryption vs encoding" defaultOpen>
        <TransformComparison />
        <p>
          A <strong>hash</strong> is a fixed-size fingerprint. Change one bit of the input and the
          digest changes completely, which is why vendors publish checksums for downloads: if your
          digest matches theirs, the file is the one they published (provided you got the checksum
          over a trusted channel).
        </p>
      </Explainer>
      <Explainer title="Why passwords need slow hashes, not SHA-256">
        <p>
          SHA-256 is designed to be <strong>fast</strong>: a single GPU computes billions per
          second. For a password database that is a gift to an attacker, who can try every likely
          password against a leaked hash at that speed.
        </p>
        <p>
          Password hashes such as <strong>Argon2id</strong> (what Sentinel itself uses), scrypt and
          bcrypt are deliberately <strong>slow and memory-hard</strong>, and add a per-user{" "}
          <strong>salt</strong> so identical passwords get different hashes and precomputed tables
          are useless.
        </p>
      </Explainer>
      <Explainer title="Why MD5 and SHA-1 are 'legacy'">
        <p>
          A <strong>collision</strong> is two different inputs with the same digest. For MD5 they
          take seconds; for SHA-1 they were demonstrated in 2017 (SHAttered). Anyone who can craft
          collisions can make a harmless and a malicious file share a checksum. They are still fine
          for spotting accidental corruption, but never for security decisions.
        </p>
      </Explainer>
    </LocalToolLayout>
  );
}
