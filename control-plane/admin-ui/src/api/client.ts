import type {
  Admin,
  Agent,
  AgentCredential,
  AuditRecord,
  ChainVerification,
  HitlApproval,
  HitlRequest,
  LoginResponse,
  PolicyProfile,
  ProfileOut,
  Tool,
} from "./types";

const BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

interface RequestOptions {
  method?: string;
  token?: string | null;
  body?: unknown;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(`${BASE}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = (await response.json()) as { detail?: unknown };
      if (typeof data.detail === "string") {
        detail = data.detail;
      }
    } catch {
      // non-JSON error body — keep statusText
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>("/auth/login", { method: "POST", body: { username, password } }),
  me: (token: string) => request<Admin>("/auth/me", { token }),

  listAgents: (token: string) => request<Agent[]>("/agents", { token }),
  registerAgent: (token: string, body: { name: string; tenant?: string; profile_id?: string | null }) =>
    request<AgentCredential>("/agents", { method: "POST", token, body }),
  setAgentStatus: (token: string, id: string, action: "suspend" | "activate") =>
    request<Agent>(`/agents/${id}/${action}`, { method: "POST", token }),
  assignProfile: (token: string, id: string, profileId: string) =>
    request<Agent>(`/agents/${id}/profile`, { method: "POST", token, body: { profile_id: profileId } }),

  listProfiles: (token: string) => request<PolicyProfile[]>("/profiles", { token }),
  getProfile: (token: string, id: string) => request<ProfileOut>(`/profiles/${id}`, { token }),
  createProfile: (token: string, profile: PolicyProfile) =>
    request<ProfileOut>("/profiles", { method: "POST", token, body: profile }),
  updateProfile: (token: string, id: string, profile: PolicyProfile) =>
    request<ProfileOut>(`/profiles/${id}`, { method: "PUT", token, body: profile }),
  deleteProfile: (token: string, id: string) =>
    request<void>(`/profiles/${id}`, { method: "DELETE", token }),

  listTools: (token: string) => request<Tool[]>("/tools", { token }),
  upsertTool: (token: string, name: string, body: { json_schema: Record<string, unknown>; default_allow: boolean }) =>
    request<Tool>(`/tools/${name}`, { method: "PUT", token, body }),
  deleteTool: (token: string, name: string) => request<void>(`/tools/${name}`, { method: "DELETE", token }),

  listHitl: (token: string, status?: string) =>
    request<HitlRequest[]>(`/hitl/requests${status ? `?status=${encodeURIComponent(status)}` : ""}`, { token }),
  approveHitl: (token: string, id: string) =>
    request<HitlApproval>(`/hitl/requests/${id}/approve`, { method: "POST", token }),
  denyHitl: (token: string, id: string) =>
    request<HitlRequest>(`/hitl/requests/${id}/deny`, { method: "POST", token }),

  listAudit: (token: string, query: string) => request<AuditRecord[]>(`/audit${query}`, { token }),
  verifyAudit: (token: string) => request<ChainVerification>("/audit/verify", { token }),
};
