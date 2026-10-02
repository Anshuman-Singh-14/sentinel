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
