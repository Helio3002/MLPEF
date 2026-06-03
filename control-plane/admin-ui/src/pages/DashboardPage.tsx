import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { AuditRecord } from "../api/types";
import { useAuth } from "../auth/AuthContext";

function percentile(values: number[], p: number): number {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[index];
}

function decisionMs(record: AuditRecord): number {
  return record.event.layer_trace
    .filter((d) => d.layer === "l1_validation" || d.layer === "l2_policy")
    .reduce((sum, d) => sum + d.elapsed_ms, 0);
}

function Card({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded border bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-gray-400">{hint}</div>}
    </div>
  );
}

export function DashboardPage() {
  const { token } = useAuth();
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      setRecords(await api.listAudit(token, "?limit=1000"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load audit data");
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const total = records.length;
  const denials = records.filter((r) => r.event.final_verdict === "deny").length;
  const securityEvents = records.filter((r) => r.event.security_event).length;
  const denialRate = total > 0 ? Math.round((denials / total) * 100) : 0;
  const latencies = records.map(decisionMs).filter((ms) => ms > 0);

  const attacks: Record<string, number> = {};
  for (const record of records) {
    if (record.event.security_event && record.event.reason_code) {
      attacks[record.event.reason_code] = (attacks[record.event.reason_code] ?? 0) + 1;
    }
  }
  const attackRows = Object.entries(attacks).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Dashboard</h1>
      {error && <div className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card label="Decisions" value={String(total)} hint="recent (last 1000)" />
        <Card label="Denial rate" value={`${denialRate}%`} hint={`${denials} denied`} />
        <Card label="Security events" value={String(securityEvents)} hint="injection / replay / traversal …" />
        <Card
          label="Decision path"
          value={`${percentile(latencies, 50).toFixed(1)} / ${percentile(latencies, 99).toFixed(1)} ms`}
          hint="L1+L2 p50 / p99"
        />
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold text-gray-600">Blocked attack attempts (by reason)</h2>
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b text-left text-gray-500">
              <th className="py-2">Reason code</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {attackRows.map(([reason, count]) => (
              <tr key={reason} className="border-b">
                <td className="py-2 font-mono text-xs">{reason}</td>
                <td>{count}</td>
              </tr>
            ))}
            {attackRows.length === 0 && (
              <tr>
                <td colSpan={2} className="py-4 text-gray-400">
                  No security events recorded.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-gray-400">
        Latencies are computed from the audited layer trace. Sandbox-checkout latency is measured by
        the benchmark suite (Phase 11), not persisted to the audit log. These are observed numbers, not
        guarantees.
      </p>
    </div>
  );
}
