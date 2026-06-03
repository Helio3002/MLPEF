import { Fragment, useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { AuditRecord, ChainVerification } from "../api/types";
import { useAuth } from "../auth/AuthContext";

function download(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function toCsv(records: AuditRecord[]): string {
  const header = [
    "seq", "correlation_id", "agent_id", "tool", "action", "resource",
    "verdict", "reason_code", "security_event", "timestamp",
  ];
  const rows = records.map((r) =>
    [
      r.seq, r.event.correlation_id, r.event.agent_id, r.event.tool, r.event.action,
      r.event.resource, r.event.final_verdict, r.event.reason_code ?? "",
      r.event.security_event, r.event.timestamp,
    ]
      .map((value) => `"${String(value).replace(/"/g, '""')}"`)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

export function AuditPage() {
  const { token } = useAuth();
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [agentId, setAgentId] = useState("");
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [verification, setVerification] = useState<ChainVerification | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    const params = new URLSearchParams();
    if (agentId) params.set("agent_id", agentId);
    if (action) params.set("action", action);
    if (outcome) params.set("outcome", outcome);
    const query = params.toString();
    try {
      setRecords(await api.listAudit(token, query ? `?${query}` : ""));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load audit log");
    }
  }, [token, agentId, action, outcome]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const verify = async () => {
    if (!token) return;
    setError(null);
    try {
      setVerification(await api.verifyAudit(token));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Chain verification failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Audit Explorer</h1>
        <div className="flex gap-2 text-sm">
          <button type="button" onClick={() => void verify()} className="rounded border px-3 py-1">
            Verify chain
          </button>
          <button
            type="button"
            onClick={() => download("audit.json", JSON.stringify(records, null, 2), "application/json")}
            className="rounded border px-3 py-1"
          >
            Export JSON
          </button>
          <button
            type="button"
            onClick={() => download("audit.csv", toCsv(records), "text/csv")}
            className="rounded border px-3 py-1"
          >
            Export CSV
          </button>
        </div>
      </div>

      {error && <div className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}
      {verification && (
        <div
          className={`rounded px-3 py-2 text-sm ${
            verification.ok ? "bg-green-50 text-green-700" : "bg-red-50 text-red-700"
          }`}
        >
          Chain {verification.ok ? "intact" : "BROKEN"} — {verification.records_checked} record(s)
          checked. {verification.detail}
        </div>
      )}

      <div className="flex flex-wrap gap-2 text-sm">
        <input
          placeholder="agent id"
          className="rounded border px-3 py-1"
          value={agentId}
          onChange={(e) => setAgentId(e.target.value)}
        />
        <input
          placeholder="action"
          className="rounded border px-3 py-1"
          value={action}
          onChange={(e) => setAction(e.target.value)}
        />
        <select className="rounded border px-3 py-1" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">any outcome</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
          <option value="hitl_required">hitl_required</option>
        </select>
      </div>

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-2">#</th>
            <th>Time</th>
            <th>Agent</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => (
            <Fragment key={record.seq}>
              <tr
                className="cursor-pointer border-b hover:bg-gray-50"
                onClick={() => setExpanded(expanded === record.seq ? null : record.seq)}
              >
                <td className="py-2">{record.seq}</td>
                <td className="text-xs text-gray-500">
                  {new Date(record.event.timestamp * 1000).toISOString()}
                </td>
                <td className="font-mono text-xs">{record.event.agent_id}</td>
                <td className="font-mono text-xs">{record.event.action}</td>
                <td className="font-mono text-xs">{record.event.resource}</td>
                <td>
                  <span className={record.event.final_verdict === "allow" ? "text-green-700" : "text-red-700"}>
                    {record.event.final_verdict}
                  </span>
                  {record.event.security_event && (
                    <span className="ml-2 rounded bg-red-100 px-1 text-xs text-red-700">security</span>
                  )}
                </td>
              </tr>
              {expanded === record.seq && (
                <tr className="border-b bg-gray-50">
                  <td colSpan={6} className="p-3">
                    <div className="mb-1 text-xs text-gray-500">
                      correlation {record.event.correlation_id} · reason {record.event.reason || "—"}
                    </div>
                    <table className="w-full text-xs">
                      <tbody>
                        {record.event.layer_trace.map((decision, index) => (
                          <tr key={index}>
                            <td className="pr-3 font-mono">{decision.layer}</td>
                            <td className="pr-3">{decision.verdict}</td>
                            <td className="pr-3">{decision.reason_code ?? ""}</td>
                            <td className="pr-3">{decision.elapsed_ms.toFixed(2)} ms</td>
                            <td>{decision.security_event ? "security" : ""}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
          {records.length === 0 && (
            <tr>
              <td colSpan={6} className="py-4 text-gray-400">
                No audit records.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
