import { useState, useEffect, useCallback, useMemo } from "react";
import {
  ScrollText, RefreshCw, AlertTriangle, Clock, BarChart3,
  Users, FileDown, Lock, Unlock, Activity, Server, Shield,
  UserPlus, UserX, RotateCw, Download, KeyRound, Smartphone,
  Settings, LogOut, Eye, Search, X, ChevronDown, ChevronRight,
  FolderOpen, FileText, FilePlus, FileX, FolderPlus, PenLine,
  Trash2, Copy, Edit3,
} from "lucide-react";
import { api, type AuditEntry, type SessionSummary, type FileActivityEvent } from "../api";

const ACTION_META: Record<string, { label: string; icon: typeof ScrollText; color: string; category: string }> = {
  "init":              { label: "Vault Init",         icon: Server,     color: "bg-blue-100 text-blue-700 border-blue-200",      category: "system" },
  "unlock-web":        { label: "Vault Unlocked",     icon: Unlock,     color: "bg-green-100 text-green-700 border-green-200",   category: "auth" },
  "lock":              { label: "Vault Locked",       icon: Lock,       color: "bg-gray-100 text-gray-700 border-gray-200",     category: "auth" },
  "add-client":        { label: "Client Added",       icon: UserPlus,   color: "bg-green-100 text-green-700 border-green-200",   category: "client" },
  "remove-client":     { label: "Client Removed",     icon: UserX,      color: "bg-red-100 text-red-700 border-red-200",         category: "client" },
  "export-qr":         { label: "QR Exported",        icon: Eye,        color: "bg-indigo-100 text-indigo-700 border-indigo-200",category: "client" },
  "export-config":     { label: "Config Exported",    icon: Download,   color: "bg-cyan-100 text-cyan-700 border-cyan-200",      category: "client" },
  "change-passphrase": { label: "Passphrase Changed", icon: KeyRound,   color: "bg-yellow-100 text-yellow-700 border-yellow-200",category: "admin" },
  "terminate":         { label: "Server Stopped",     icon: LogOut,     color: "bg-orange-100 text-orange-700 border-orange-200",category: "system" },
  "fresh-start":       { label: "Fresh Start",        icon: Trash2,     color: "bg-red-100 text-red-700 border-red-200",         category: "system" },
  "update-endpoint":   { label: "Endpoint Updated",   icon: Settings,   color: "bg-purple-100 text-purple-700 border-purple-200",category: "config" },
  "status":            { label: "Status Check",       icon: Activity,   color: "bg-gray-100 text-gray-500 border-gray-200",      category: "system" },
  "list-clients":      { label: "Clients Listed",     icon: Users,      color: "bg-gray-100 text-gray-500 border-gray-200",      category: "client" },
  "show-qr":           { label: "QR Viewed",          icon: Eye,        color: "bg-indigo-100 text-indigo-700 border-indigo-200",category: "client" },
  "rotate-keys":       { label: "Keys Rotated",       icon: RotateCw,   color: "bg-amber-100 text-amber-700 border-amber-200",   category: "client" },
  "rotate-server-keys":{ label: "Server Keys Rotated",icon: RotateCw,   color: "bg-red-100 text-red-700 border-red-200",         category: "admin" },
  "unlock-failed":     { label: "Unlock Failed",      icon: Lock,       color: "bg-red-100 text-red-700 border-red-200",         category: "auth" },
  "totp-enrolled":     { label: "TOTP Enrolled",      icon: Smartphone, color: "bg-green-100 text-green-700 border-green-200",   category: "admin" },
  "totp-disabled":     { label: "TOTP Disabled",      icon: Smartphone, color: "bg-red-100 text-red-700 border-red-200",        category: "admin" },
  "totp-failed":       { label: "TOTP Failed",        icon: Smartphone, color: "bg-red-100 text-red-700 border-red-200",        category: "auth" },
  "add-admin":         { label: "Admin Added",        icon: UserPlus,   color: "bg-purple-100 text-purple-700 border-purple-200",category: "admin" },
  "remove-admin":      { label: "Admin Removed",      icon: UserX,      color: "bg-red-100 text-red-700 border-red-200",         category: "admin" },
  "backup-vault":      { label: "Vault Backup",       icon: Download,   color: "bg-blue-100 text-blue-700 border-blue-200",      category: "admin" },
  "restore-vault":     { label: "Vault Restore",      icon: Download,   color: "bg-amber-100 text-amber-700 border-amber-200",   category: "admin" },
  "sftp-connect":      { label: "SFTP Connected",     icon: Server,     color: "bg-green-100 text-green-700 border-green-200",   category: "sftp" },
  "sftp-write":        { label: "SFTP Write",         icon: Edit3,      color: "bg-green-100 text-green-700 border-green-200",   category: "sftp" },
  "sftp-delete":       { label: "SFTP Delete",        icon: Trash2,     color: "bg-red-100 text-red-700 border-red-200",         category: "sftp" },
  "sftp-mkdir":        { label: "SFTP Mkdir",         icon: FolderPlus, color: "bg-blue-100 text-blue-700 border-blue-200",      category: "sftp" },
  "sftp-rename":       { label: "SFTP Rename",        icon: PenLine,    color: "bg-amber-100 text-amber-700 border-amber-200",   category: "sftp" },
  "sftp-copy":         { label: "SFTP Copy",          icon: Copy,       color: "bg-purple-100 text-purple-700 border-purple-200",category: "sftp" },
};

const CATEGORIES = [
  { key: "all", label: "All Events", color: "bg-gray-100 text-gray-700" },
  { key: "auth", label: "Authentication", color: "bg-green-100 text-green-700" },
  { key: "client", label: "Client Management", color: "bg-blue-100 text-blue-700" },
  { key: "admin", label: "Admin Actions", color: "bg-purple-100 text-purple-700" },
  { key: "sftp", label: "File Operations", color: "bg-amber-100 text-amber-700" },
  { key: "config", label: "Configuration", color: "bg-cyan-100 text-cyan-700" },
  { key: "system", label: "System", color: "bg-gray-100 text-gray-600" },
];

const PAGE_SIZE = 50;

function formatTs(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}
function relativeTs(ts: string): string {
  try {
    const diff = Date.now() - new Date(ts).getTime();
    if (diff < 60000) return "just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch { return ts; }
}

function formatDuration(start: string, end: string | null): string {
  if (!end) return "Active now";
  try {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins >= 60) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
    if (mins > 0) return `${mins}m`;
    return "< 1m";
  } catch { return "\u2014"; }
}

const FILE_OP_LABELS: Record<string, { label: string; icon: typeof FileText; color: string }> = {
  file_open:    { label: "Opened",     icon: FileText,   color: "text-blue-600" },
  file_read:    { label: "Read",       icon: FileText,   color: "text-blue-500" },
  file_write:   { label: "Written",    icon: PenLine,    color: "text-green-600" },
  file_close:   { label: "Closed",     icon: FileText,   color: "text-gray-400" },
  file_remove:  { label: "Deleted",    icon: FileX,      color: "text-red-600" },
  file_rename:  { label: "Renamed",    icon: PenLine,    color: "text-amber-600" },
  dir_create:   { label: "Dir Created",icon: FolderPlus,  color: "text-green-600" },
  dir_remove:   { label: "Dir Deleted",icon: FileX,      color: "text-red-600" },
  dir_open:     { label: "Dir Listed", icon: FolderOpen,  color: "text-blue-500" },
};

type Tab = "events" | "sessions" | "files";

let _auditCache: { entries: AuditEntry[]; summary: SessionSummary | null; fileEvents: FileActivityEvent[] } | null = null;

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>(_auditCache?.entries ?? []);
  const [summary, setSummary] = useState<SessionSummary | null>(_auditCache?.summary ?? null);
  const [fileEvents, setFileEvents] = useState<FileActivityEvent[]>(_auditCache?.fileEvents ?? []);
  const [loading, setLoading] = useState(_auditCache === null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("events");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [logRes, sumRes, fileRes] = await Promise.all([
        api.auditLog(), api.sessionSummary(), api.fileActivity(),
      ]);
      _auditCache = { entries: logRes.entries, summary: sumRes, fileEvents: fileRes.events };
      setEntries(logRes.entries); setSummary(sumRes); setFileEvents(fileRes.events); setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const filtered = useMemo(() => {
    let items = entries;
    if (categoryFilter !== "all") {
      const actionKeys = Object.entries(ACTION_META)
        .filter(([, v]) => v.category === categoryFilter).map(([k]) => k);
      items = items.filter(e => actionKeys.includes(e.action));
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(e =>
        e.action.toLowerCase().includes(q) ||
        JSON.stringify(e.metadata).toLowerCase().includes(q) ||
        (e.error || "").toLowerCase().includes(q)
      );
    }
    return items;
  }, [entries, categoryFilter, search]);

  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const toggleExpand = (i: number) => {
    setExpanded(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });
  };

  return (
    <div className="p-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
          <p className="text-sm text-gray-500 mt-1">Track every action across the system</p>
        </div>
        <div className="flex items-center gap-3">
          {tab === "sessions" && summary && (
            <span className="text-xs text-gray-400 tabular-nums">{summary.sessions.length} sessions</span>
          )}
          {tab === "events" && (
            <span className="text-xs text-gray-400 tabular-nums">{filtered.length} events</span>
          )}
          <button onClick={fetchAll} disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50 disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3 flex items-center gap-2 text-sm text-red-700">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          {[
            { icon: Activity, label: "Total Events", value: summary.summary.total_events, color: "text-blue-600" },
            { icon: Clock, label: "Sessions", value: summary.summary.total_sessions, color: "text-green-600" },
            { icon: UserPlus, label: "Clients Added", value: summary.summary.clients_added, color: "text-purple-600" },
            { icon: Download, label: "Configs Exported", value: summary.summary.configs_exported + summary.summary.qr_codes_generated, color: "text-cyan-600" },
          ].map((card, i) => (
            <div key={i} className="bg-white rounded-xl border p-4">
              <div className="flex items-center gap-2 mb-1.5">
                <card.icon className={`w-4 h-4 ${card.color}`} />
                <span className="text-xs text-gray-500">{card.label}</span>
              </div>
              <p className="text-2xl font-bold text-gray-900">{card.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-gray-100 rounded-lg p-1 w-fit">
        {(["events", "sessions", "files"] as Tab[]).map(t => (
          <button key={t} onClick={() => { setTab(t); setPage(0); }}
            className={`flex items-center gap-1.5 px-3.5 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
            }`}>
            {t === "events" && <ScrollText className="w-4 h-4" />}
            {t === "sessions" && <BarChart3 className="w-4 h-4" />}
            {t === "files" && <FolderOpen className="w-4 h-4" />}
            {t === "events" ? "Events" : t === "sessions" ? "Sessions" : "File Activity"}
          </button>
        ))}
      </div>

      {/* ───── EVENTS TAB ───── */}
      {tab === "events" && (
        <div>
          {/* Filters */}
          <div className="flex gap-3 mb-3 flex-wrap items-center">
            <div className="flex gap-1 flex-wrap">
              {CATEGORIES.map(c => (
                <button key={c.key} onClick={() => { setCategoryFilter(c.key); setPage(0); }}
                  className={`px-2.5 py-1 text-xs font-medium rounded-full border transition-colors ${
                    categoryFilter === c.key
                      ? `${c.color} border-current`
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300"
                  }`}>
                  {c.label}
                </button>
              ))}
            </div>
            <div className="relative flex-1 max-w-xs ml-auto">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" />
              <input value={search} onChange={e => { setSearch(e.target.value); setPage(0); }}
                className="w-full pl-8 pr-8 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Search events..." />
              {search && (
                <button onClick={() => setSearch("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Table */}
          <div className="bg-white rounded-xl border overflow-hidden">
            {loading && paged.length === 0 ? (
              <div className="p-12 text-center text-gray-400">Loading...</div>
            ) : paged.length === 0 ? (
              <div className="p-12 text-center"><ScrollText className="w-10 h-10 text-gray-300 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">No matching events</p></div>
            ) : (
              <>
                <table className="w-full">
                  <thead>
                    <tr className="bg-gray-50 text-left text-xs text-gray-500 uppercase tracking-wider">
                      <th className="px-4 py-3 border-b font-medium">Time</th>
                      <th className="px-4 py-3 border-b font-medium">Event</th>
                      <th className="px-4 py-3 border-b font-medium">Actor</th>
                      <th className="px-4 py-3 border-b font-medium">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {paged.map((entry, i) => {
                      const globalIdx = page * PAGE_SIZE + i;
                      const meta = ACTION_META[entry.action] ?? { label: entry.action, icon: ScrollText, color: "bg-gray-100 text-gray-700 border-gray-200", category: "" };
                      const Icon = meta.icon;
                      const actor = entry.metadata?.actor || entry.metadata?.admin_id || entry.metadata?.name || "\u2014";
                      const isExpanded = expanded.has(globalIdx);
                      const metaEntries = Object.entries(entry.metadata).filter(([k]) => !["actor", "admin_id", "name"].includes(k));
                      return (
                        <tr key={globalIdx} className="hover:bg-gray-50/50 transition-colors">
                          <td className="px-4 py-3 text-sm whitespace-nowrap">
                            <span className="text-gray-900">{relativeTs(entry.timestamp)}</span>
                            <br /><span className="text-xs text-gray-400">{formatTs(entry.timestamp)}</span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <Icon className={`w-3.5 h-3.5 ${meta.color.split(" ")[0]?.replace("bg-", "text-") || "text-gray-500"}`} />
                              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${meta.color}`}>
                                {meta.label}
                              </span>
                              {!entry.success && <span className="text-xs text-red-600 font-medium">failed</span>}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-sm">
                            <span className="font-mono text-xs bg-gray-100 px-1.5 py-0.5 rounded">{actor}</span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1 flex-wrap">
                              {metaEntries.slice(0, isExpanded ? undefined : 2).map(([k, v]) => (
                                <span key={k} className="text-xs text-gray-500 bg-gray-50 px-1.5 py-0.5 rounded">
                                  {k}: <span className="text-gray-700 font-medium">{String(v)}</span>
                                </span>
                              ))}
                              {metaEntries.length > 2 && (
                                <button onClick={() => toggleExpand(globalIdx)} className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-0.5">
                                  {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                                  {isExpanded ? "less" : `${metaEntries.length - 2} more`}
                                </button>
                              )}
                              {entry.error && <span className="text-xs text-red-600 ml-1">{entry.error}</span>}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {/* Pagination */}
                {pageCount > 1 && (
                  <div className="flex items-center justify-between px-4 py-3 border-t bg-gray-50">
                    <span className="text-xs text-gray-500">Page {page + 1} of {pageCount}</span>
                    <div className="flex gap-1">
                      <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                        className="px-3 py-1 text-xs border rounded hover:bg-white disabled:opacity-30">Prev</button>
                      {Array.from({ length: Math.min(pageCount, 7) }, (_, i) => {
                        const p = pageCount <= 7 ? i : Math.max(0, Math.min(page - 3, pageCount - 7)) + i;
                        return (
                          <button key={p} onClick={() => setPage(p)}
                            className={`px-3 py-1 text-xs border rounded ${page === p ? "bg-blue-600 text-white border-blue-600" : "hover:bg-white"}`}>
                            {p + 1}
                          </button>
                        );
                      })}
                      <button disabled={page >= pageCount - 1} onClick={() => setPage(p => p + 1)}
                        className="px-3 py-1 text-xs border rounded hover:bg-white disabled:opacity-30">Next</button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* ───── SESSIONS TAB ───── */}
      {tab === "sessions" && (
        <div className="space-y-3">
          {!summary?.sessions.length ? (
            <div className="bg-white rounded-xl border p-12 text-center">
              <Clock className="w-10 h-10 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">No sessions recorded yet</p>
            </div>
          ) : (
            summary.sessions.map((session, i) => (
              <div key={i} className="bg-white rounded-xl border p-4 hover:shadow-sm transition-shadow">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <div className={`w-9 h-9 rounded-full flex items-center justify-center ${session.end === null ? "bg-green-100" : "bg-gray-100"}`}>
                      {session.end === null ? <Unlock className="w-4 h-4 text-green-600" /> : <Lock className="w-4 h-4 text-gray-500" />}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{session.end === null ? "Active Session" : "Session"}</p>
                      <p className="text-xs text-gray-400">{formatTs(session.start)}</p>
                    </div>
                  </div>
                  <div className="text-right text-xs text-gray-500">
                    <p className="font-medium text-gray-700">{formatDuration(session.start, session.end)}</p>
                    <p>{session.event_count} events</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(session.event_types).map(([action, count]) => {
                    const m = ACTION_META[action] ?? { label: action, color: "bg-gray-100 text-gray-600 border-gray-200" };
                    return (
                      <span key={action} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${m.color}`}>
                        {m.label} {count > 1 && <span className="opacity-60">×{count}</span>}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ───── FILE ACTIVITY TAB ───── */}
      {tab === "files" && (
        <div className="bg-white rounded-xl border overflow-hidden">
          {fileEvents.length === 0 ? (
            <div className="p-12 text-center">
              <FolderOpen className="w-10 h-10 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">No file activity detected yet</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50 text-left text-xs text-gray-500 uppercase tracking-wider">
                  <th className="px-4 py-3 border-b font-medium">Time</th>
                  <th className="px-4 py-3 border-b font-medium">Operation</th>
                  <th className="px-4 py-3 border-b font-medium">Path</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {fileEvents.map((event, i) => {
                  const op = FILE_OP_LABELS[event.type] ?? { label: event.operation, icon: FileText, color: "text-gray-500" };
                  const Icon = op.icon;
                  return (
                    <tr key={i} className="hover:bg-gray-50/50">
                      <td className="px-4 py-3 text-sm whitespace-nowrap text-gray-500">{event.timestamp ? formatTs(event.timestamp) : "\u2014"}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-3.5 h-3.5 ${op.color}`} />
                          <span className="text-sm font-medium text-gray-700">{op.label}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-600 max-w-md truncate">{event.details.path}</td>
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
