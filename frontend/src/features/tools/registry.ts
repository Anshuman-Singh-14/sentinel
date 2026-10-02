/**
 * Frontend tool manifest — the single list that drives navigation.
 *
 * Two kinds of tool exist (01-architecture.md, 02-modules.md):
 *
 * - **Local** tools run entirely in the browser; their input never reaches the
 *   backend (CLAUDE.md rule 2). They are declared here because the backend
 *   does not know about them.
 * - **Remote** tools come from the backend catalogue (`GET /api/v1/tools`).
 *   A new backend tool appears in the navigation automatically; the optional
 *   `REMOTE_TOOL_META` entry only adds an icon.
 *
 * Adding a tool therefore means one entry here at most, never a layout edit
 * (CLAUDE.md rule 9).
 */

import {
  Binary,
  Fingerprint,
  FileSearch,
  Globe,
  Hash,
  KeyRound,
  Network,
  Radar,
  ScanSearch,
  ShieldCheck,
  Terminal,
  Wrench,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { Role, ToolCategory, ToolDescriptor } from "../../types/api";
import { roleAllows } from "../../types/api";

export interface LocalToolManifest {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
  /** False until the tool's phase ships; shown in the nav as "soon". */
  available: boolean;
}

export const LOCAL_TOOLS: readonly LocalToolManifest[] = [
  {
    id: "password",
    name: "Password Analyzer",
    description: "Entropy, crack-time estimate and pattern detection.",
    icon: KeyRound,
    available: false,
  },
  {
    id: "jwt",
    name: "JWT Inspector",
    description: "Decode and sanity-check JSON Web Tokens.",
    icon: Fingerprint,
    available: false,
  },
  {
    id: "hash",
    name: "Hash Tool",
    description: "Generate and verify SHA-family digests.",
    icon: Hash,
    available: false,
  },
  {
    id: "encoder",
    name: "Encoder / Decoder",
    description: "Base64, hex, URL and HTML entity conversion.",
    icon: Binary,
    available: false,
  },
];

/** Optional presentation hints for backend tools, keyed by `tool_id`. */
export const REMOTE_TOOL_META: Record<string, { icon: LucideIcon }> = {
  echo: { icon: Terminal },
  dns_lookup: { icon: Globe },
  port_scanner: { icon: Radar },
  header_tls: { icon: ShieldCheck },
  threat_intel: { icon: ScanSearch },
  net_diag: { icon: Network },
  log_analyzer: { icon: FileSearch },
  fim: { icon: FileSearch },
};

export const CATEGORY_LABELS: Record<ToolCategory, string> = {
  RECON: "Reconnaissance",
  WEB: "Web security",
  INTEL: "Threat intel",
  DIAGNOSTIC: "Diagnostics",
  FORENSIC: "Forensics",
};

const CATEGORY_ORDER: ToolCategory[] = ["RECON", "WEB", "INTEL", "DIAGNOSTIC", "FORENSIC"];

export interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: LucideIcon;
  description?: string;
  disabled?: boolean;
  /** Short tag shown next to the label, e.g. "soon" or "active". */
  tag?: string;
  /** The user's role is below the tool's required role (they can view, not run). */
  locked?: boolean;
}

export interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
  /** Shown under the group label. */
  note?: string;
}

export function remoteToolPath(toolId: string): string {
  return `/tools/${encodeURIComponent(toolId)}`;
}

export function localToolPath(toolId: string): string {
  return `/local/${encodeURIComponent(toolId)}`;
}

/** Build the tool sections of the sidebar from both manifests. */
export function buildToolNavigation(catalogue: ToolDescriptor[], role: Role): NavGroup[] {
  const groups: NavGroup[] = [
    {
      id: "local",
      label: "Local utilities",
      note: "Runs in your browser only",
      items: LOCAL_TOOLS.map((tool) => ({
        id: `local:${tool.id}`,
        label: tool.name,
        path: localToolPath(tool.id),
        icon: tool.icon,
        description: tool.description,
        disabled: !tool.available,
        tag: tool.available ? undefined : "soon",
      })),
    },
  ];

  for (const category of CATEGORY_ORDER) {
    const tools = catalogue
      .filter((tool) => tool.category === category)
      .sort((a, b) => a.name.localeCompare(b.name));
    if (tools.length === 0) continue;
    groups.push({
      id: `remote:${category}`,
      label: CATEGORY_LABELS[category],
      items: tools.map((tool) => ({
        id: `remote:${tool.tool_id}`,
        label: tool.name,
        path: remoteToolPath(tool.tool_id),
        icon: REMOTE_TOOL_META[tool.tool_id]?.icon ?? Wrench,
        description: tool.description,
        tag: tool.is_active ? "active" : undefined,
        locked: !roleAllows(role, tool.required_role),
      })),
    });
  }
  return groups;
}
