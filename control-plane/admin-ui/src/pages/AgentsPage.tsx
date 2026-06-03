import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { Agent, AgentCredential, PolicyProfile } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { canWrite } from "../auth/roles";

export function AgentsPage() {
  const { token, role } = useAuth();
  const writable = canWrite(role);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [profiles, setProfiles] = useState<PolicyProfile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [profileId, setProfileId] = useState("");
  const [created, setCreated] = useState<AgentCredential | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [agentList, profileList] = await Promise.all([
        api.listAgents(token),
        api.listProfiles(token),
      ]);
      setAgents(agentList);
      setProfiles(profileList);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load agents");
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const register = async () => {
    if (!token) return;
    setError(null);
    try {
      const credential = await api.registerAgent(token, { name, profile_id: profileId || null });
      setCreated(credential);
      setName("");
      setProfileId("");
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration failed");
    }
  };

  const setStatus = async (id: string, action: "suspend" | "activate") => {
    if (!token) return;
    try {
      await api.setAgentStatus(token, id, action);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Update failed");
    }
  };

  const assign = async (id: string, newProfileId: string) => {
    if (!token || !newProfileId) return;
    try {
      await api.assignProfile(token, id, newProfileId);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Assign failed");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Agents</h1>
      {error && <div className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}

      {created && (
        <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm">
          <div className="font-medium">Agent registered — copy the API key now (shown once):</div>
          <code className="mt-1 block break-all rounded bg-white px-2 py-1">{created.api_key}</code>
        </div>
      )}

      {writable && (
        <div className="flex flex-wrap items-end gap-3 rounded border bg-white p-4">
          <label className="text-sm">
            <span className="text-gray-600">Name</span>
            <input
              className="mt-1 block rounded border px-3 py-2"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label className="text-sm">
            <span className="text-gray-600">Profile</span>
            <select
              className="mt-1 block rounded border px-3 py-2"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
            >
              <option value="">default (locked down)</option>
              {profiles.map((p) => (
                <option key={p.profile_id} value={p.profile_id}>
                  {p.profile_id}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            disabled={!name}
            onClick={() => void register()}
            className="rounded bg-gray-900 px-3 py-2 text-sm text-white disabled:opacity-50"
          >
            Register
          </button>
        </div>
      )}

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-2">Name</th>
            <th>Tenant</th>
            <th>Profile</th>
            <th>Status</th>
            {writable && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.id} className="border-b">
              <td className="py-2">{agent.name}</td>
              <td>{agent.tenant}</td>
              <td className="font-mono text-xs">{agent.profile_id}</td>
              <td>
                <span className={agent.status === "active" ? "text-green-700" : "text-red-700"}>
                  {agent.status}
                </span>
              </td>
              {writable && (
                <td className="flex flex-wrap items-center gap-2 py-2">
                  {agent.status === "active" ? (
                    <button
                      type="button"
                      onClick={() => void setStatus(agent.id, "suspend")}
                      className="rounded border px-2 py-1 text-xs"
                    >
                      Suspend
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void setStatus(agent.id, "activate")}
                      className="rounded border px-2 py-1 text-xs"
                    >
                      Activate
                    </button>
                  )}
                  <select
                    defaultValue=""
                    onChange={(e) => void assign(agent.id, e.target.value)}
                    className="rounded border px-2 py-1 text-xs"
                  >
                    <option value="">reassign…</option>
                    {profiles.map((p) => (
                      <option key={p.profile_id} value={p.profile_id}>
                        {p.profile_id}
                      </option>
                    ))}
                  </select>
                </td>
              )}
            </tr>
          ))}
          {agents.length === 0 && (
            <tr>
              <td colSpan={5} className="py-4 text-gray-400">
                No agents registered.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
