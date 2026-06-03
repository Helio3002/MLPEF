// Mirrors the control-api response shapes (see control-plane/control-api/app/schemas.py
// and common/). Kept intentionally loose for the nested profile structure, which the
// UI edits as JSON.

export type Role = "superadmin" | "security-reviewer" | "approver" | "read-only";

export interface LoginResponse {
  token: string;
  role: Role;
  expires_at: string;
}

export interface Admin {
  id: string;
  username: string;
  role: Role;
}

export interface Agent {
  id: string;
  name: string;
  tenant: string;
  profile_id: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface AgentCredential extends Agent {
  api_key: string;
}

export interface PolicyProfile {
  profile_id: string;
  name: string;
  tenant: string;
  description: string;
  version: number;
  tool_allowlist: string[];
  rego_policy_ref: string;
  resource_scopes: unknown[];
  hitl_rules: unknown[];
  sandbox_limits: Record<string, unknown>;
  output_filter: Record<string, unknown>;
}

export interface ProfileOut {
  profile: PolicyProfile;
  agents_affected: number;
  updated_at: string;
}

export interface Tool {
  name: string;
  json_schema: Record<string, unknown>;
  default_allow: boolean;
}

export interface HitlRequest {
  id: string;
  agent_id: string;
  tenant: string;
  action: string;
  resource: string;
  status: string;
  approver: string | null;
  requested_at: string;
  decided_at: string | null;
}

export interface HitlApproval {
  hitl_request_id: string;
  token: string;
  expires_at: number;
}

export interface LayerDecision {
  layer: string;
  verdict: string;
  reason_code: string | null;
  reason: string;
  security_event: boolean;
  elapsed_ms: number;
  metadata: Record<string, unknown>;
}

export interface AuditEvent {
  correlation_id: string;
  timestamp: number;
  tenant: string;
  agent_id: string;
  ingress: string;
  tool: string;
  action: string;
  resource: string;
  final_verdict: string;
  reason_code: string | null;
  reason: string;
  security_event: boolean;
  layer_trace: LayerDecision[];
}

export interface AuditRecord {
  seq: number;
  prev_hash: string;
  recorded_at: number;
  event: AuditEvent;
  record_hash: string;
}

export interface ChainVerification {
  ok: boolean;
  records_checked: number;
  first_broken_seq: number | null;
  detail: string;
}
