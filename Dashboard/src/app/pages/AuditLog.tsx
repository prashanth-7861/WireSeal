import { useState, useEffect, useCallback } from "react";
import {
  ScrollText, RefreshCw, AlertTriangle, Clock, BarChart3,
  Users, FileDown, Lock, Unlock, Activity,
  FolderOpen, FileText, FilePlus, FileX, FolderPlus, PenLine,
} from "lucide-react";
import { api, type AuditEntry, type SessionSummary, type FileActivityEvent } from "../api";

const ACTION_LABELS: Record<string, { label: string; color: string }> = {
  "init":              { label: "Vault Init",         color: "bg-blue-100 text-blue-700" },
  "unlock-web":        { label: "Vault Unlocked",     color: "bg-green-100 text-green-700" },
  "lock":              { label: "Vault Locked",       color: "bg-gray-100 text-gray-700" },
  "add-client":        { label: "Client Added",       color: "bg-green-100 text-green-700" },
  "remove-client":     { label: "Client Removed",     color: "bg-red-100 text-red-700" },
  "export-qr":         { label: "QR Exported",        color: "bg-indigo-100 text-indigo-700" },
  "export-config":     { label: "Config Exported",    color: "bg-cyan-100 text-cyan-700" },
  "change-passphrase": { label: "Passphrase Changed", color: "bg-yellow-100 text-yellow-700" },
  "terminate":         { label: "Server Stopped",     color: "bg-orange-100 text-orange-700" },
  "fresh-start":       { label: "Fresh Start",        color: "bg-red-100 text-red-700" },
  "update-endpoint":   { label: "Endpoint Updated",   color: "bg-purple-100 text-purple-700" },
  "status":            { label: "Status Check",       color: "bg-gray-100 text-gray-500" },
  "list-clients":      { label: "Clients Listed",     color: "bg-gray-100 text-gray-500" },
  "show-qr":           { label: "QR Viewed",          color: "bg-indigo-100 text-indigo-700" },
  "rotate-keys":       { label: "Keys Rotated",       color: "bg-amber-100 text-amber-700" },
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

function formatDuration(start: string, end: string | null): string {
  if (!end) return "Active now";
  try {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    const mins = Math.floor(ms / 60000);
    const hours = Math.floor(mins / 60);
    if (hours > 0) return `${hours}h ${mins % 60}m`;
    if (mins > 0) return `${mins}m`;
    return "< 1m";
  } catch {
    return "—";
  }
}

const FILE_OP_LABELS: Record<string, { label: string; icon: typeof FileText; color: string }> = {
  "file_open":        { label: "File Opened",      icon: FileText,   color: "text-blue-600" },
  "file_read":        { label: "File Read",         icon: FileText,   color: "text-blue-500" },
  "file_write":       { label: "File Written",      icon: PenLine,    color: "text-green-600" },
  "file_close":       { label: "File Closed",       icon: FileText,   color: "text-gray-400" },
  "file_remove":      { label: "File Deleted",      icon: FileX,      color: "text-red-600" },
  "file_rename":      { label: "File Renamed",      icon: PenLine,    color: "text-amber-600" },
  "file_permissions": { label: "Permissions Changed", icon: Lock,     color: "text-purple-600" },
  "dir_create":       { label: "Directory Created", icon: FolderPlus, color: "text-green-600" },
  "dir_remove":       { label: "Directory Deleted", icon: FileX,      color: "text-red-600" },
  "dir_open":         { label: "Directory Listed",  icon: FolderOpen, color: "text-blue-500" },
  "file_stat":        { label: "File Info",         icon: FileText,   color: "text-gray-500" },
};

type Tab = "events" | "sessions" | "files";

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [summary, setSummary] = useState<SessionSummary | null>(null);
  const [fileEvents, setFileEvents] = useState<FileActivityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("events");

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [logRes, sumRes, fileRes] = await Promise.all([
        api.auditLog(),
        api.sessionSummary(),
        api.fileActivity(),
      ]);
      setEntries(logRes.entries);
      setSummary(sumRes);
      setFileEvents(fileRes.events);
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Audit Log</h1>
          <p className="text-gray-500 mt-1">Server events and session history</p>
        </div>
        <button
          onClick={fetchAll}
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

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-4 h-4 text-blue-500" />
              <span className="text-sm text-gray-500">Total Events</span>
            </div>
            <p className="text-2xl font-semibold text-gray-900">{summary.summary.total_events}</p>
          </div>
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Clock className="w-4 h-4 text-green-500" />
              <span className="text-sm text-gray-500">Sessions</span>
            </div>
            <p className="text-2xl font-semibold text-gray-900">{summary.summary.total_sessions}</p>
          </div>
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Users className="w-4 h-4 text-purple-500" />
              <span className="text-sm text-gray-500">Clients Added</span>
            </div>
            <p className="text-2xl font-semibold text-gray-900">{summary.summary.clients_added}</p>
          </div>
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-2 mb-2">
              <FileDown className="w-4 h-4 text-cyan-500" />
              <span className="text-sm text-gray-500">Configs Exported</span>
            </div>
            <p className="text-2xl font-semibold text-gray-900">
              {summary.summary.configs_exported + summary.summary.qr_codes_generated}
            </p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-gray-100 rounded-lg p-1 w-fit">
        <button
          onClick={() => setTab("events")}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === "events" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
          }`}
        >
          <span className="flex items-center gap-2">
            <ScrollText className="w-4 h-4" />
            Events
          </span>
        </button>
        <button
          onClick={() => setTab("sessions")}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === "sessions" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
          }`}
        >
          <span className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4" />
            Sessions
          </span>
        </button>
        <button
          onClick={() => setTab("files")}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === "files" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
          }`}
        >
          <span className="flex items-center gap-2">
            <FolderOpen className="w-4 h-4" />
            File Activity
          </span>
        </button>
      </div>

      {/* Events tab */}
      {tab === "events" && (
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
      )}

      {/* Sessions tab */}
      {tab === "sessions" && (
        <div className="space-y-4">
          {!summary || summary.sessions.length === 0 ? (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12 text-center">
              <Clock className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="font-medium text-gray-900 mb-2">No sessions recorded</h3>
              <p className="text-gray-500">Session history will appear after you unlock and lock the vault</p>
            </div>
          ) : (
            summary.sessions.map((session, i) => (
              <div key={i} className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                      session.end === null ? "bg-green-100" : "bg-gray-100"
                    }`}>
                      {session.end === null
                        ? <Unlock className="w-5 h-5 text-green-600" />
                        : <Lock className="w-5 h-5 text-gray-500" />}
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">
                        {session.end === null ? "Current Session" : "Session"}
                      </p>
                      <p className="text-sm text-gray-500">{formatTs(session.start)}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-gray-700">
                      {formatDuration(session.start, session.end)}
                    </p>
                    <p className="text-xs text-gray-400">{session.event_count} events</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(session.event_types).map(([action, count]) => {
                    const meta = ACTION_LABELS[action] ?? { label: action, color: "bg-gray-100 text-gray-600" };
                    return (
                      <span key={action} className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${meta.color}`}>
                        {meta.label}
                        {count > 1 && <span className="opacity-70">×{count}</span>}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* File Activity tab */}
      {tab === "files" && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          {fileEvents.length === 0 ? (
            <div className="p-12 text-center">
              <FolderOpen className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="font-medium text-gray-900 mb-2">No file activity detected</h3>
              <p className="text-gray-500 text-sm max-w-md mx-auto">
                File activity from SFTP/SSH connections will appear here.
                Make sure SFTP logging is enabled in your SSH config
                (<span className="font-mono text-xs">LogLevel VERBOSE</span> in sshd_config).
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Time</th>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Operation</th>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Path</th>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {fileEvents.map((event, i) => {
                  const opMeta = FILE_OP_LABELS[event.type] ?? {
                    label: event.operation, icon: FileText, color: "text-gray-500",
                  };
                  const Icon = opMeta.icon;
                  return (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-6 py-3 text-sm text-gray-500 whitespace-nowrap">
                        {event.timestamp ? formatTs(event.timestamp) : "—"}
                      </td>
                      <td className="px-6 py-3">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-4 h-4 ${opMeta.color}`} />
                          <span className="text-sm font-medium text-gray-700">{opMeta.label}</span>
                        </div>
                      </td>
                      <td className="px-6 py-3 text-sm font-mono text-gray-600 max-w-xs truncate" title={event.details.path}>
                        {event.details.path}
                      </td>
                      <td className="px-6 py-3 text-sm text-gray-500">
                        {event.type === "file_rename" && event.details.to && (
                          <span>→ <span className="font-mono">{event.details.to}</span></span>
                        )}
                        {event.details.user && (
                          <span className="text-xs bg-gray-100 px-2 py-0.5 rounded ml-1">
                            {event.details.user}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
