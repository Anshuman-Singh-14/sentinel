/**
 * Wire types mirroring the backend's Pydantic response models.
 * Source of truth: backend/app/api/v1/*.py and backend/app/engine/schemas.py.
 */

export type Role = "admin" | "analyst" | "viewer";

export const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

/** Mirrors backend `role_allows`: roles are strictly hierarchical. */
export function roleAllows(actual: Role, required: Role): boolean {
  return ROLE_RANK[actual] >= ROLE_RANK[required];
}

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type ToolCategory = "RECON" | "WEB" | "INTEL" | "DIAGNOSTIC" | "FORENSIC";

export interface User {
  id: string;
  username: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
  locked_until: string | null;
}

export interface SessionInfo {
  user: User;
  session_id: string;
  access_expires_at: string;
  refresh_expires_at: string;
}

export interface ToolDescriptor {
  tool_id: string;
  name: string;
  description: string;
  version: string;
  category: ToolCategory;
  is_active: boolean;
  required_role: Role;
  params_schema: Record<string, unknown>;
}

export interface HealthResponse {
  status: "ok";
  version: string;
}

export interface AuditEvent {
  id: number;
  event_id: string;
  occurred_at: string;
  actor_type: string;
  user_id: string | null;
  username: string | null;
  role: string | null;
  session_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  service: string;
  hostname: string;
  process_user: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  target: string | null;
  outcome: string;
  reason: string | null;
  details: Record<string, unknown>;
  request_id: string | null;
  is_security_event: boolean;
  prev_hash: string;
  row_hash: string;
}

export interface AuditPage {
  events: AuditEvent[];
  next_before_id: number | null;
}

export interface VerifyResponse {
  ok: boolean;
  checked: number;
  head_hash: string;
  first_broken_id: number | null;
  reason: string | null;
}

export interface SecurityAlert {
  id: string;
  created_at: string;
  rule: string;
  severity: Severity;
  message: string;
  details: Record<string, unknown>;
  audit_event_id: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}

// --- tool runs (Phase 5) ---------------------------------------------------------

export const RUN_STATUSES = [
  "QUEUED",
  "RUNNING",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
  "TIMED_OUT",
] as const;
export type RunStatus = (typeof RUN_STATUSES)[number];

export function isTerminal(status: RunStatus): boolean {
  return status !== "QUEUED" && status !== "RUNNING";
}

export type FindingStatus =
  | "PASS"
  | "FAIL"
  | "MISSING"
  | "WEAK"
  | "DETECTED"
  | "CHANGED"
  | "ADDED"
  | "REMOVED"
  | "ERROR"
  | "INFO";

export interface Finding {
  finding_id: string;
  item: string;
  category: string;
  status: FindingStatus;
  severity: Severity;
  severity_rationale: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  explanation: string;
  remediation: string;
  evidence: Record<string, unknown>;
  references: string[];
  raw_data: Record<string, unknown>;
}

export interface ToolError {
  code: string;
  message: string;
}

/** The standard ToolResult (01-architecture.md) plus live progress fields. */
export interface RunDetail {
  run_id: string;
  tool_id: string;
  tool_name: string;
  tool_version: string;
  target: string | null;
  initiated_by: string | null;
  status: RunStatus;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  summary: { total: number; by_severity: Record<Severity, number> };
  findings: Finding[];
  errors: ToolError[];
  raw_data: Record<string, unknown>;
  params: Record<string, unknown>;
  user_id: string;
  created_at: string;
  progress_pct: number;
  progress_message: string | null;
  cancel_requested: boolean;
  /** False for runs that never left the queue (started_at then equals created_at). */
  was_started: boolean;
}

export interface RunSummary {
  run_id: string;
  tool_id: string;
  tool_name: string;
  target: string | null;
  status: RunStatus;
  initiated_by: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  finding_count: number;
  max_severity: Severity | null;
}

export interface RunPage {
  runs: RunSummary[];
  next_before: string | null;
}

/** A live update pushed over the run WebSocket. */
export interface RunEvent {
  type: "run.update";
  run_id: string;
  status: RunStatus;
  progress_pct: number;
  progress_message: string | null;
  finding_count: number;
  max_severity: Severity | null;
  ts: string;
}

// --- scope policy (Phase 6) -----------------------------------------------------

export interface ScopeRule {
  id: string | null;
  kind: "cidr" | "domain";
  value: string;
  description: string;
  source: "builtin" | "admin";
  enabled: boolean;
  created_at?: string | null;
}

export interface ScopeView {
  rules: ScopeRule[];
  /** Admin view only. */
  hard_deny: string[] | null;
}

export interface Acknowledgement {
  acknowledged: boolean;
  version: number;
  statement: string;
  acknowledged_at: string | null;
}

// --- playbooks (Phase 12) --------------------------------------------------------

export type StepStatus =
  "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "SKIPPED" | "CANCELLED" | "TIMED_OUT";

export interface PlaybookStepInfo {
  id: string;
  name: string;
  tool_id: string;
  tool_name: string | null;
  available: boolean;
  optional: boolean;
  on_failure: "stop" | "continue";
  is_active: boolean;
  description: string;
}

export interface PlaybookInfo {
  id: string;
  name: string;
  version: string;
  description: string;
  available: boolean;
  unavailable_reason: string | null;
  requires_authorization: boolean;
  required_role: Role;
  inputs_schema: Record<string, unknown>;
  steps: PlaybookStepInfo[];
}

export interface PlaybookStepOut {
  position: number;
  step_id: string;
  name: string;
  tool_id: string;
  on_failure: "stop" | "continue";
  status: StepStatus;
  run: RunSummary | null;
  resolved_params: Record<string, unknown> | null;
  error: { code: string; message: string } | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface AggregatedFinding extends Finding {
  step_id: string;
  tool_id: string;
  run_id: string;
  also_reported_by: string[];
}

export interface RiskSummary {
  total: number;
  by_severity: Record<Severity, number>;
  highest: Severity | null;
  headline: string;
}

export interface PlaybookRunSummary {
  playbook_run_id: string;
  playbook_id: string;
  playbook_name: string;
  target: string | null;
  status: RunStatus;
  initiated_by: string;
  created_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  finding_count: number;
  max_severity: Severity | null;
}

export interface PlaybookRunDetail extends PlaybookRunSummary {
  playbook_version: string;
  inputs: Record<string, unknown>;
  user_id: string;
  started_at: string | null;
  progress_pct: number;
  current_step: string | null;
  cancel_requested: boolean;
  error: { code: string; message: string } | null;
  steps: PlaybookStepOut[];
  risk: RiskSummary;
  findings: AggregatedFinding[];
}

export interface PlaybookRunPage {
  runs: PlaybookRunSummary[];
  next_before: string | null;
}

export interface PlaybookEvent {
  type: "playbook.update";
  playbook_run_id: string;
  status: RunStatus;
  progress_pct: number;
  current_step: string | null;
  steps: Array<{ step_id: string; status: StepStatus }>;
  ts: string;
}
