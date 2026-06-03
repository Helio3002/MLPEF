import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { Tool } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { canWrite } from "../auth/roles";

export function ToolsPage() {
  const { token, role } = useAuth();
  const writable = canWrite(role);
  const [tools, setTools] = useState<Tool[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [schema, setSchema] = useState("{}");
  const [defaultAllow, setDefaultAllow] = useState(false);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      setTools(await api.listTools(token));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load tools");
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const save = async () => {
    if (!token || !name) return;
    setError(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(schema) as Record<string, unknown>;
    } catch {
      setError("Schema is not valid JSON");
      return;
    }
    try {
      await api.upsertTool(token, name, { json_schema: parsed, default_allow: defaultAllow });
      setName("");
      setSchema("{}");
      setDefaultAllow(false);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Save failed");
    }
  };

  const remove = async (toolName: string) => {
    if (!token) return;
    try {
      await api.deleteTool(token, toolName);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Delete failed");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Tools</h1>
      {error && <div className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}

      {writable && (
        <div className="space-y-2 rounded border bg-white p-4">
          <div className="flex flex-wrap items-center gap-3">
            <input
              placeholder="tool name (e.g. fs.read)"
              className="rounded border px-3 py-2 text-sm"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={defaultAllow}
                onChange={(e) => setDefaultAllow(e.target.checked)}
              />
              default allow
            </label>
            <button
              type="button"
              disabled={!name}
              onClick={() => void save()}
              className="rounded bg-gray-900 px-3 py-2 text-sm text-white disabled:opacity-50"
            >
              Save tool
            </button>
          </div>
          <textarea
            value={schema}
            onChange={(e) => setSchema(e.target.value)}
            spellCheck={false}
            className="h-32 w-full rounded border p-3 font-mono text-xs"
          />
        </div>
      )}

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-2">Name</th>
            <th>Default allow</th>
            {writable && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {tools.map((tool) => (
            <tr key={tool.name} className="border-b">
              <td className="py-2 font-mono text-xs">{tool.name}</td>
              <td>{tool.default_allow ? "yes" : "no"}</td>
              {writable && (
                <td>
                  <button
                    type="button"
                    onClick={() => void remove(tool.name)}
                    className="rounded border border-red-300 px-2 py-1 text-xs text-red-700"
                  >
                    Delete
                  </button>
                </td>
              )}
            </tr>
          ))}
          {tools.length === 0 && (
            <tr>
              <td colSpan={3} className="py-4 text-gray-400">
                No tools registered.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
