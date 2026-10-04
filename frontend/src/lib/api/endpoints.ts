/** Typed wrappers for each backend endpoint the frontend uses. */

import type {
  Acknowledgement,
  AuditPage,
  RunDetail,
  RunPage,
  RunStatus,
  ScopeRule,
  ScopeView,
  HealthResponse,
  PlaybookInfo,
  PlaybookRunDetail,
  PlaybookRunPage,
  Report,
  ReportFormat,
  ReportPage,
  ReportSourceType,
  SecurityAlert,
  SessionInfo,
  ToolDescriptor,
  User,
  VerifyResponse,
} from "../../types/api";
import { api, download } from "./client";

const V1 = "/api/v1";

export const authApi = {
  // Login and refresh never trigger the refresh-and-retry path: a 401 from
  // them is the final answer.
  login: (username: string, password: string) =>
    api.post<SessionInfo>(`${V1}/auth/login`, { username, password }, { skipRefresh: true }),
  logout: () => api.post<void>(`${V1}/auth/logout`, undefined, { skipRefresh: true }),
  me: (signal?: AbortSignal) => api.get<User>(`${V1}/auth/me`, { signal }),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post<void>(`${V1}/auth/password`, {
      current_password: currentPassword,
      new_password: newPassword,
    }),
};

export const toolsApi = {
  list: (signal?: AbortSignal) => api.get<ToolDescriptor[]>(`${V1}/tools`, { signal }),
};

export const healthApi = {
  // Short timeout: this drives a status indicator, not a user action.
  health: (signal?: AbortSignal) =>
    api.get<HealthResponse>("/health", { signal, timeoutMs: 3000, skipRefresh: true }),
};

export interface AuditFilters {
  username?: string;
  action?: string;
  outcome?: string;
  security_only?: boolean;
  since?: string;
  until?: string;
}

export const adminApi = {
  audit: (filters: AuditFilters, beforeId?: number, signal?: AbortSignal) =>
    api.get<AuditPage>(`${V1}/admin/audit`, {
      query: { ...filters, security_only: filters.security_only || undefined, before_id: beforeId },
      signal,
    }),
  verifyAudit: () =>
    api.post<VerifyResponse>(`${V1}/admin/audit/verify`, undefined, {
      // Verification walks the whole chain; give it longer than a normal call.
      timeoutMs: 60_000,
    }),
  alerts: (unacknowledgedOnly: boolean, signal?: AbortSignal) =>
    api.get<SecurityAlert[]>(`${V1}/admin/alerts`, {
      query: { unacknowledged_only: unacknowledgedOnly || undefined, limit: 50 },
      signal,
    }),
  exportAudit: (filters: AuditFilters, format: "csv" | "json") =>
    download(`${V1}/admin/audit/export`, {
      query: { ...filters, security_only: filters.security_only || undefined, format },
    }),
  acknowledgeAlert: (alertId: string) =>
    api.post<SecurityAlert>(`${V1}/admin/alerts/${encodeURIComponent(alertId)}/acknowledge`),
};

export interface RunFilters {
  mine?: boolean;
  tool_id?: string;
  status?: RunStatus;
}

export const runsApi = {
  create: (toolId: string, params: Record<string, unknown>) =>
    api.post<RunDetail>(`${V1}/tools/${encodeURIComponent(toolId)}/runs`, { params }),
  get: (runId: string, signal?: AbortSignal) =>
    api.get<RunDetail>(`${V1}/runs/${encodeURIComponent(runId)}`, { signal }),
  list: (filters: RunFilters, before?: string, signal?: AbortSignal) =>
    api.get<RunPage>(`${V1}/runs`, {
      query: { ...filters, mine: filters.mine || undefined, before, limit: 25 },
      signal,
    }),
  cancel: (runId: string) => api.post<RunDetail>(`${V1}/runs/${encodeURIComponent(runId)}/cancel`),
  wsTicket: (runId: string) =>
    api.post<{ ticket: string; expires_in: number }>(
      `${V1}/runs/${encodeURIComponent(runId)}/ws-ticket`,
    ),
};

export const scopeApi = {
  get: (signal?: AbortSignal) => api.get<ScopeView>(`${V1}/scope`, { signal }),
  acknowledgement: (signal?: AbortSignal) =>
    api.get<Acknowledgement>(`${V1}/scope/acknowledgement`, { signal }),
  acknowledge: (version: number) =>
    api.post<Acknowledgement>(`${V1}/scope/acknowledgement`, { statement_version: version }),
  adminGet: (signal?: AbortSignal) => api.get<ScopeView>(`${V1}/admin/scope`, { signal }),
  add: (kind: ScopeRule["kind"], value: string, description: string) =>
    api.post<ScopeRule>(`${V1}/admin/scope`, { kind, value, description }),
  setEnabled: (id: string, enabled: boolean) =>
    api.patch<ScopeRule>(`${V1}/admin/scope/${encodeURIComponent(id)}`, { enabled }),
  remove: (id: string) => api.delete<void>(`${V1}/admin/scope/${encodeURIComponent(id)}`),
};

export const playbooksApi = {
  list: (signal?: AbortSignal) => api.get<PlaybookInfo[]>(`${V1}/playbooks`, { signal }),
  start: (playbookId: string, inputs: Record<string, unknown>) =>
    api.post<PlaybookRunDetail>(`${V1}/playbooks/${encodeURIComponent(playbookId)}/runs`, {
      inputs,
    }),
  get: (id: string, signal?: AbortSignal) =>
    api.get<PlaybookRunDetail>(`${V1}/playbook-runs/${encodeURIComponent(id)}`, { signal }),
  runs: (mine: boolean, before?: string, signal?: AbortSignal) =>
    api.get<PlaybookRunPage>(`${V1}/playbook-runs`, {
      query: { mine: mine || undefined, before, limit: 20 },
      signal,
    }),
  cancel: (id: string) =>
    api.post<PlaybookRunDetail>(`${V1}/playbook-runs/${encodeURIComponent(id)}/cancel`),
  wsTicket: (id: string) =>
    api.post<{ ticket: string; expires_in: number }>(
      `${V1}/playbook-runs/${encodeURIComponent(id)}/ws-ticket`,
    ),
};

export interface ReportFilters {
  mine?: boolean;
  source_type?: ReportSourceType;
  source_id?: string;
}

export const reportsApi = {
  formats: (signal?: AbortSignal) => api.get<ReportFormat[]>(`${V1}/reports/formats`, { signal }),
  create: (sourceType: ReportSourceType, sourceId: string, format: string) =>
    api.post<Report>(`${V1}/reports`, { source_type: sourceType, source_id: sourceId, format }),
  get: (id: string, signal?: AbortSignal) =>
    api.get<Report>(`${V1}/reports/${encodeURIComponent(id)}`, { signal }),
  list: (filters: ReportFilters, before?: string, signal?: AbortSignal) =>
    api.get<ReportPage>(`${V1}/reports`, {
      query: { ...filters, mine: filters.mine || undefined, before, limit: 25 },
      signal,
    }),
  download: (id: string) => download(`${V1}/reports/${encodeURIComponent(id)}/download`),
};
