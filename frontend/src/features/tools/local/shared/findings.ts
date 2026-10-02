import type { Severity } from "../../../../types/api";
import { SEVERITIES } from "../../../../types/api";

/**
 * A finding produced in the browser. It mirrors the backend `Finding` shape
 * (item, severity, rationale, explanation, remediation) so the local tools
 * speak the same Educational Translation Engine language as the backend ones.
 */
export interface LocalFinding {
  id: string;
  severity: Severity;
  title: string;
  /** What this means, in plain language. */
  explanation: string;
  /** Why it got this severity. */
  rationale?: string;
  remediation?: string;
  references?: string[];
}

/** Most severe first, stable within a severity. */
export function sortFindings(findings: LocalFinding[]): LocalFinding[] {
  return [...findings].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
  );
}
