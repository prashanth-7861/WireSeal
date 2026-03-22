import { useState, useEffect, useCallback } from "react";
import { ScrollText, RefreshCw, AlertTriangle } from "lucide-react";
import { api, type AuditEntry } from "../api";

const ACTION_LABELS: Record<string, { label: string; color: string }> = {
  "init":              { label: "Vault Init",       color: "bg-blue-100 text-blue-700" },
  "unlock-web":        { label: "Unlocked",         color: "bg-green-100 text-green-700" },
  "add-client":        { label: "Client Added",     color: "bg-green-100 text-green-700" },
  "remove-client":     { label: "Client Removed",   color: "bg-red-100 text-red-700" },
  "change-passphrase": { label: "Passphrase Changed", color: "bg-yellow-100 text-yellow-700" },
  "terminate":         { label: "Server Stopped",   color: "bg-orange-100 text-orange-700" },
  "fresh-start":       { label: "Fresh Start",      color: "bg-red-100 text-red-700" },
  "update-endpoint":   { label: "Endpoint Updated", color: "bg-purple-100 text-purple-700" },
};

function formatTs(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function formatMetadata(metadata: Record<string, unknown>): string {
  return Object.entries(metadata)
    .map(([k, v]) => `${k}: ${v}`)
    .join(" · ");
}

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchLog = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.auditLog();
      setEntries(res.entries);
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLog();
  }, [fetchLog]);

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Audit Log</h1>
          <p className="text-gray-500 mt-1">Last 100 vault and server events</p>
        </div>
        <button
          onClick={fetchLog}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-gray-700 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
          <p className="text-red-800">{error}</p>
        </div>
      )}

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {loading && entries.length === 0 ? (
          <div className="p-12 text-center text-gray-500">Loading audit log…</div>
        ) : entries.length === 0 ? (
          <div className="p-12 text-center">
            <ScrollText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="font-medium text-gray-900 mb-2">No audit entries yet</h3>
            <p className="text-gray-500">Events will appear here as you use WireSeal</p>
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Time</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Event</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {entries.map((entry, i) => {
                const meta = ACTION_LABELS[entry.action] ?? {
                  label: entry.action,
                  color: "bg-gray-100 text-gray-700",
                };
                return (
                  <tr key={i} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm text-gray-500 whitespace-nowrap">
                      {formatTs(entry.timestamp)}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-flex px-2.5 py-1 rounded-full text-xs font-medium ${meta.color}`}
                        >
                          {meta.label}
                        </span>
                        {!entry.success && (
                          <span className="inline-flex px-2 py-0.5 rounded text-xs bg-red-100 text-red-700">
                            failed
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {formatMetadata(entry.metadata)}
                      {entry.error && (
                        <span className="ml-2 text-red-500">— {entry.error}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
