import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { HitlRequest } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { canApprove } from "../auth/roles";

export function HitlQueuePage() {
  const { token, role } = useAuth();
  const approver = canApprove(role);
  const [requests, setRequests] = useState<HitlRequest[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [minted, setMinted] = useState<{ id: string; token: string } | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      setRequests(await api.listHitl(token, "pending"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load the queue");
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const approve = async (id: string) => {
    if (!token) return;
    setError(null);
    try {
      const approval = await api.approveHitl(token, id);
      setMinted({ id, token: approval.token });
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Approve failed");
    }
  };

  const deny = async (id: string) => {
    if (!token) return;
    setError(null);
    try {
      await api.denyHitl(token, id);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Deny failed");
    }
  };

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">HITL Approval Queue</h1>
      {error && <div className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}
      {!approver && (
        <div className="rounded bg-gray-100 px-3 py-2 text-sm text-gray-600">
          View only — your role cannot approve or deny.
        </div>
      )}
      {minted && (
        <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm">
          <div className="font-medium">Approval token minted (scoped, single-use, short-lived):</div>
          <code className="mt-1 block break-all rounded bg-white px-2 py-1">{minted.token}</code>
          <div className="mt-1 text-xs text-gray-500">
            The agent retries the action with this token; the proxy verifies it at Layer 2.
          </div>
        </div>
      )}

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-2">Agent</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Requested</th>
            {approver && <th>Decision</th>}
          </tr>
        </thead>
        <tbody>
          {requests.map((req) => (
            <tr key={req.id} className="border-b">
              <td className="py-2 font-mono text-xs">{req.agent_id}</td>
              <td className="font-mono text-xs">{req.action}</td>
              <td className="font-mono text-xs">{req.resource}</td>
              <td className="text-xs text-gray-500">{req.requested_at}</td>
              {approver && (
                <td className="flex gap-2 py-2">
                  <button
                    type="button"
                    onClick={() => void approve(req.id)}
                    className="rounded bg-green-700 px-2 py-1 text-xs text-white"
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    onClick={() => void deny(req.id)}
                    className="rounded border border-red-300 px-2 py-1 text-xs text-red-700"
                  >
                    Deny
                  </button>
                </td>
              )}
            </tr>
          ))}
          {requests.length === 0 && (
            <tr>
              <td colSpan={5} className="py-4 text-gray-400">
                No pending requests.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
