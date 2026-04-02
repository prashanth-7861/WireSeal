import { useState, useEffect, useRef } from "react";
import {
  Terminal, Server, FileText, Play, Square, RotateCcw,
  AlertCircle, CheckCircle, ChevronRight, Loader2,
  FolderOpen, Save, RefreshCw, Shield,
} from "lucide-react";
import { api, type ServiceInfo, type ExecResult } from "../api";

type Tab = "terminal" | "services" | "files";

// ─── Terminal Tab ────────────────────────────────────────────────────────────

function TerminalTab() {
  const [input, setInput]       = useState("");
  const [history, setHistory]   = useState<{ cmd: string; result: ExecResult }[]>([]);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");
  const outputRef               = useRef<HTMLDivElement>(null);

  const run = async () => {
    const trimmed = input.trim();
    if (!trimmed) return;
    // Simple split — no shell expansion, no quoting support
    const parts = trimmed.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)
      ?.map(t => t.replace(/^["']|["']$/g, "")) ?? [];
    if (!parts.length) return;

    setLoading(true);
    setError("");
    try {
      const result = await api.adminExec(parts, "", 60);
      setHistory(prev => [...prev, { cmd: trimmed, result }]);
      setInput("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Execution failed");
    } finally {
      setLoading(false);
      setTimeout(() => outputRef.current?.scrollTo(0, outputRef.current.scrollHeight), 50);
    }
  };

  return (
    <div className="flex flex-col h-full gap-4">
      {/* Output */}
      <div
        ref={outputRef}
        className="flex-1 bg-gray-950 text-green-400 font-mono text-sm rounded-lg p-4 overflow-y-auto min-h-0 max-h-[500px]"
      >
        {history.length === 0 && (
          <p className="text-gray-600 text-xs">Run a command to see output here.</p>
        )}
        {history.map((entry, i) => (
          <div key={i} className="mb-3">
            <div className="flex items-center gap-1 text-blue-400 mb-1">
              <ChevronRight className="w-3 h-3" />
              <span>{entry.cmd}</span>
              <span className={`ml-auto text-xs ${entry.result.returncode === 0 ? "text-green-500" : "text-red-400"}`}>
                [{entry.result.returncode}]
              </span>
            </div>
            {entry.result.stdout && (
              <pre className="whitespace-pre-wrap break-all text-green-400">{entry.result.stdout}</pre>
            )}
            {entry.result.stderr && (
              <pre className="whitespace-pre-wrap break-all text-red-400">{entry.result.stderr}</pre>
            )}
          </div>
        ))}
        {loading && (
          <div className="flex items-center gap-2 text-yellow-400 text-xs">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>Running...</span>
          </div>
        )}
      </div>

      {/* Input */}
      {error && (
        <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 border border-red-200 p-3 rounded-lg">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
      <div className="flex gap-2">
        <div className="flex-1 flex items-center bg-gray-900 border border-gray-700 rounded-lg px-3 gap-2 focus-within:border-blue-500">
          <ChevronRight className="w-4 h-4 text-green-500 flex-shrink-0" />
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !loading && run()}
            placeholder="ls -la /etc  or  systemctl status wg-quick@wg0"
            className="flex-1 bg-transparent text-white font-mono text-sm py-2.5 outline-none placeholder-gray-600"
            disabled={loading}
            autoFocus
          />
        </div>
        <button
          onClick={run}
          disabled={loading || !input.trim()}
          className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center gap-2 text-sm"
        >
          <Play className="w-4 h-4" />
          Run
        </button>
        {history.length > 0 && (
          <button
            onClick={() => setHistory([])}
            className="px-3 py-2.5 border border-gray-300 hover:bg-gray-50 text-gray-600 rounded-lg transition-colors text-sm"
            title="Clear output"
          >
            Clear
          </button>
        )}
      </div>
      <p className="text-xs text-gray-400">
        Commands run as root. Simple whitespace splitting — use the API directly for complex quoting.
        Max timeout: 120 s.
      </p>
    </div>
  );
}

// ─── Services Tab ────────────────────────────────────────────────────────────

function ServicesTab() {
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading]   = useState(false);
  const [actionMsg, setActionMsg] = useState<{ unit: string; msg: string; ok: boolean } | null>(null);
  const [filter, setFilter]     = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const { services: list } = await api.adminServices();
      setServices(list);
    } catch {
      // ignore — will show empty
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const doAction = async (unit: string, action: string) => {
    setActionMsg(null);
    try {
      const res = await api.adminServiceAction(unit, action);
      setActionMsg({ unit, msg: `${action}: ${res.ok ? "OK" : "failed"} [${res.returncode}]`, ok: res.ok });
      await load(); // refresh
    } catch (err) {
      setActionMsg({ unit, msg: err instanceof Error ? err.message : "Action failed", ok: false });
    }
  };

  const filtered = services.filter(s =>
    !filter || s.unit.toLowerCase().includes(filter.toLowerCase()) ||
    s.description.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <input
          type="text"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter services..."
          className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
        <button
          onClick={load}
          disabled={loading}
          className="p-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          title="Refresh"
        >
          <RefreshCw className={`w-4 h-4 text-gray-600 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {actionMsg && (
        <div className={`flex items-center gap-2 text-sm p-3 rounded-lg border ${
          actionMsg.ok
            ? "bg-green-50 border-green-200 text-green-700"
            : "bg-red-50 border-red-200 text-red-700"
        }`}>
          {actionMsg.ok
            ? <CheckCircle className="w-4 h-4 flex-shrink-0" />
            : <AlertCircle className="w-4 h-4 flex-shrink-0" />
          }
          <span><strong>{actionMsg.unit}</strong> — {actionMsg.msg}</span>
        </div>
      )}

      {loading && services.length === 0 ? (
        <div className="flex items-center gap-2 text-gray-500 text-sm py-8 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span>Loading services...</span>
        </div>
      ) : (
        <div className="border border-gray-200 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium text-gray-700">Unit</th>
                <th className="text-left px-4 py-2.5 font-medium text-gray-700">State</th>
                <th className="text-left px-4 py-2.5 font-medium text-gray-700 hidden md:table-cell">Description</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.slice(0, 200).map(svc => (
                <tr key={svc.unit} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-mono text-xs text-gray-800 max-w-[220px] truncate">{svc.unit}</td>
                  <td className="px-4 py-2">
                    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium ${
                      svc.active === "active"
                        ? "bg-green-100 text-green-700"
                        : svc.active === "failed"
                        ? "bg-red-100 text-red-700"
                        : "bg-gray-100 text-gray-600"
                    }`}>
                      {svc.active} ({svc.sub})
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-500 text-xs hidden md:table-cell max-w-[240px] truncate">{svc.description}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-1 justify-end">
                      {svc.active !== "active" && (
                        <button
                          onClick={() => doAction(svc.unit, "start")}
                          className="p-1 rounded hover:bg-green-50 text-green-600 hover:text-green-700 transition-colors"
                          title="Start"
                        >
                          <Play className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {svc.active === "active" && (
                        <>
                          <button
                            onClick={() => doAction(svc.unit, "restart")}
                            className="p-1 rounded hover:bg-blue-50 text-blue-600 hover:text-blue-700 transition-colors"
                            title="Restart"
                          >
                            <RotateCcw className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => doAction(svc.unit, "stop")}
                            className="p-1 rounded hover:bg-red-50 text-red-600 hover:text-red-700 transition-colors"
                            title="Stop"
                          >
                            <Square className="w-3.5 h-3.5" />
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-gray-400 text-sm">
                    {filter ? "No matching services." : "No services found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {filtered.length > 200 && (
        <p className="text-xs text-gray-400 text-center">
          Showing first 200 of {filtered.length} services. Use the filter to narrow results.
        </p>
      )}
    </div>
  );
}

// ─── Files Tab ───────────────────────────────────────────────────────────────

function FilesTab() {
  const [path, setPath]         = useState("/etc/wireguard/wg0.conf");
  const [content, setContent]   = useState("");
  const [loading, setLoading]   = useState(false);
  const [saving, setSaving]     = useState(false);
  const [dirty, setDirty]       = useState(false);
  const [message, setMessage]   = useState<{ text: string; ok: boolean } | null>(null);

  const readFile = async () => {
    if (!path.trim()) return;
    setLoading(true);
    setMessage(null);
    try {
      const res = await api.adminReadFile(path.trim());
      setContent(res.content);
      setDirty(false);
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Read failed", ok: false });
      setContent("");
    } finally {
      setLoading(false);
    }
  };

  const saveFile = async () => {
    if (!path.trim()) return;
    setSaving(true);
    setMessage(null);
    try {
      await api.adminWriteFile(path.trim(), content);
      setMessage({ text: "File saved.", ok: true });
      setDirty(false);
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Write failed", ok: false });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Path bar */}
      <div className="flex gap-2">
        <div className="flex-1 flex items-center border border-gray-300 rounded-lg px-3 gap-2 focus-within:border-blue-500">
          <FolderOpen className="w-4 h-4 text-gray-400 flex-shrink-0" />
          <input
            type="text"
            value={path}
            onChange={e => setPath(e.target.value)}
            onKeyDown={e => e.key === "Enter" && readFile()}
            placeholder="/etc/wireguard/wg0.conf"
            className="flex-1 py-2.5 text-sm font-mono outline-none bg-transparent text-gray-900"
          />
        </div>
        <button
          onClick={readFile}
          disabled={loading}
          className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm flex items-center gap-2"
        >
          {loading
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <FolderOpen className="w-4 h-4" />
          }
          Open
        </button>
        <button
          onClick={saveFile}
          disabled={saving || !content || !dirty}
          className="px-4 py-2.5 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm flex items-center gap-2"
        >
          {saving
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <Save className="w-4 h-4" />
          }
          Save
        </button>
      </div>

      {message && (
        <div className={`flex items-center gap-2 text-sm p-3 rounded-lg border ${
          message.ok
            ? "bg-green-50 border-green-200 text-green-700"
            : "bg-red-50 border-red-200 text-red-700"
        }`}>
          {message.ok
            ? <CheckCircle className="w-4 h-4 flex-shrink-0" />
            : <AlertCircle className="w-4 h-4 flex-shrink-0" />
          }
          <span>{message.text}</span>
        </div>
      )}

      <textarea
        value={content}
        onChange={e => { setContent(e.target.value); setDirty(true); }}
        placeholder="Open a file to view and edit it..."
        className="w-full h-96 font-mono text-sm bg-gray-950 text-green-300 border border-gray-700 rounded-lg p-4 outline-none resize-y focus:border-blue-500 placeholder-gray-700"
        spellCheck={false}
      />
      {dirty && (
        <p className="text-xs text-amber-600 flex items-center gap-1">
          <AlertCircle className="w-3 h-3" />
          Unsaved changes
        </p>
      )}
    </div>
  );
}

// ─── Admin Panel ─────────────────────────────────────────────────────────────

export function Admin() {
  const [tab, setTab] = useState<Tab>("terminal");

  const tabs: { id: Tab; label: string; icon: typeof Terminal }[] = [
    { id: "terminal", label: "Terminal",  icon: Terminal },
    { id: "services", label: "Services",  icon: Server   },
    { id: "files",    label: "Files",     icon: FileText  },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center">
          <Shield className="w-5 h-5 text-red-600" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Admin Panel</h1>
          <p className="text-sm text-gray-500">Full system access — commands run as root</p>
        </div>
      </div>

      {/* Warning */}
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-amber-800">
          <strong>Admin mode is active.</strong> All operations in this panel run with root privileges.
          Changes are immediate and permanent. Use with care.
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="flex border-b border-gray-200">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-2 px-5 py-3.5 text-sm font-medium transition-colors ${
                tab === id
                  ? "text-blue-600 border-b-2 border-blue-600 bg-blue-50/50"
                  : "text-gray-500 hover:text-gray-700 hover:bg-gray-50"
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>
        <div className="p-6">
          {tab === "terminal" && <TerminalTab />}
          {tab === "services" && <ServicesTab />}
          {tab === "files"    && <FilesTab />}
        </div>
      </div>
    </div>
  );
}
