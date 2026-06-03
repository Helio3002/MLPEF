import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { PolicyProfile } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { canWrite } from "../auth/roles";

const TEMPLATE = JSON.stringify(
  {
    profile_id: "my-profile",
    name: "My Profile",
    tenant: "default",
    description: "",
    version: 1,
    tool_allowlist: [],
    rego_policy_ref: "mlpef.authz/default_deny",
    resource_scopes: [],
    hitl_rules: [],
    sandbox_limits: {},
    output_filter: {},
  },
  null,
  2,
);

export function ProfilesPage() {
  const { token, role } = useAuth();
  const writable = canWrite(role);
  const [profiles, setProfiles] = useState<PolicyProfile[]>([]);
  const [draft, setDraft] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [affected, setAffected] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      setProfiles(await api.listProfiles(token));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load profiles");
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const startNew = () => {
    setEditingId(null);
    setDraft(TEMPLATE);
    setAffected(null);
    setError(null);
    setNotice(null);
  };

  const edit = async (profile: PolicyProfile) => {
    setEditingId(profile.profile_id);
    setDraft(JSON.stringify(profile, null, 2));
    setError(null);
    setNotice(null);
    setAffected(null);
    if (token) {
      try {
        const out = await api.getProfile(token, profile.profile_id);
        setAffected(out.agents_affected);
      } catch {
        // best-effort impact count
      }
    }
  };

  const save = async () => {
    if (!token) return;
    setError(null);
    setNotice(null);
    let parsed: PolicyProfile;
    try {
      parsed = JSON.parse(draft) as PolicyProfile;
    } catch {
      setError("Draft is not valid JSON");
      return;
    }
    try {
      if (editingId) {
        await api.updateProfile(token, editingId, parsed);
        setNotice("Profile updated.");
      } else {
        await api.createProfile(token, parsed);
        setEditingId(parsed.profile_id);
        setNotice("Profile created.");
      }
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Save failed");
    }
  };

  const remove = async (id: string) => {
    if (!token) return;
    setError(null);
    setNotice(null);
    try {
      await api.deleteProfile(token, id);
      if (editingId === id) {
        startNew();
      }
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Delete failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Policy Profiles</h1>
        {writable && (
          <button type="button" onClick={startNew} className="rounded bg-gray-900 px-3 py-1 text-sm text-white">
            New profile
          </button>
        )}
      </div>
      {error && <div className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}
      {notice && <div className="rounded bg-green-50 px-3 py-2 text-sm text-green-700">{notice}</div>}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="space-y-2">
          {profiles.map((profile) => (
            <div key={profile.profile_id} className="flex items-center justify-between rounded border bg-white p-3">
              <div>
                <div className="font-medium">{profile.name}</div>
                <div className="font-mono text-xs text-gray-500">
                  {profile.profile_id} · {profile.tool_allowlist.length} tool(s) · v{profile.version}
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => void edit(profile)}
                  className="rounded border px-2 py-1 text-xs"
                >
                  {writable ? "Edit" : "View"}
                </button>
                {writable && (
                  <button
                    type="button"
                    onClick={() => void remove(profile.profile_id)}
                    className="rounded border border-red-300 px-2 py-1 text-xs text-red-700"
                  >
                    Delete
                  </button>
                )}
              </div>
            </div>
          ))}
          {profiles.length === 0 && <div className="text-gray-400">No profiles.</div>}
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-600">{editingId ? `Editing ${editingId}` : "New profile (JSON)"}</span>
            {affected !== null && (
              <span className="rounded bg-amber-50 px-2 py-0.5 text-amber-700">
                {affected} agent(s) affected
              </span>
            )}
          </div>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            spellCheck={false}
            readOnly={!writable}
            className="h-96 w-full rounded border bg-white p-3 font-mono text-xs"
          />
          {writable && (
            <button type="button" onClick={() => void save()} className="rounded bg-gray-900 px-3 py-2 text-sm text-white">
              Save profile
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
