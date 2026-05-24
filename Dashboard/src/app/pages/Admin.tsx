import { useState, useEffect, useRef } from "react";
import {
  Terminal, Server, FileText, Play, Square, RotateCcw,
  AlertCircle, CheckCircle, ChevronRight, Loader2,
  FolderOpen, Save, RefreshCw, Shield, Users, Plus,
  Trash2, KeyRound, Smartphone, User,
} from "lucide-react";
import { api, type AdminInfo, type ServiceInfo, type ExecResult } from "../api";
import { AdminRoleBadge } from "../components/AdminRoleBadge";

type Tab = "accounts" | "terminal" | "services" | "files";

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

// ─── Accounts Tab ────────────────────────────────────────────────────────────

function AccountsTab() {
  const [admins, setAdmins] = useState<AdminInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [showAddDialog, setShowAddDialog] = useState(false);
  const [addId, setAddId] = useState("");
  const [addPassphrase, setAddPassphrase] = useState("");
  const [addRole, setAddRole] = useState<"admin" | "readonly">("admin");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);

  const [showPassDialog, setShowPassDialog] = useState<string | null>(null);
  const [newAdminPass, setNewAdminPass] = useState("");
  const [changingPass, setChangingPass] = useState(false);
  const [passError, setPassError] = useState("");

  const [showTOTPReset, setShowTOTPReset] = useState<string | null>(null);
  const [totpResetLoading, setTotpResetLoading] = useState(false);

  const currentId = api.getCurrentAdminId();
  const isOwner = currentId === "owner";

  const flash = (msg: string) => {
    setSuccess(msg); setError("");
    setTimeout(() => setSuccess(""), 4000);
  };
  const flashError = (msg: string) => {
    setError(msg); setSuccess("");
  };

  const load = () => {
    setLoading(true); setError("");
    api.listAdmins()
      .then(d => setAdmins(d.admins))
      .catch((e: unknown) => flashError(e instanceof Error ? e.message : "Failed to load admins"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!addId || addPassphrase.length < 12) {
      setAddError("Admin ID required and passphrase must be 12+ characters");
      return;
    }
    setAdding(true); setAddError("");
    try {
      await api.addAdmin(addId, addPassphrase, addRole);
      setShowAddDialog(false);
      setAddId(""); setAddPassphrase(""); setAddRole("admin");
      flash(`Admin "${addId}" added`);
      load();
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : "Failed to add admin");
    } finally { setAdding(false); }
  };

  const handleRemove = async (id: string) => {
    setRemoving(true);
    try {
      await api.removeAdmin(id);
      setConfirmRemove(null);
      flash(`Admin "${id}" removed`);
      load();
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Failed to remove admin");
    } finally { setRemoving(false); }
  };

  const handleChangePassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!showPassDialog) return;
    if (newAdminPass.length < 12) { setPassError("Passphrase must be 12+ characters"); return; }
    setChangingPass(true); setPassError("");
    try {
      await api.changeAdminPassphrase(showPassDialog, newAdminPass);
      setShowPassDialog(null); setNewAdminPass("");
      flash(`Passphrase changed for "${showPassDialog}"`);
    } catch (e: unknown) {
      setPassError(e instanceof Error ? e.message : "Failed");
    } finally { setChangingPass(false); }
  };

  const handleTOTPReset = async (id: string) => {
    setTotpResetLoading(true);
    try {
      await api.totpReset(id);
      setShowTOTPReset(null);
      flash(`TOTP reset for "${id}"`);
      load();
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Failed to reset TOTP");
    } finally { setTotpResetLoading(false); }
  };

  if (loading) return (
    <div className="flex items-center gap-3 text-gray-500 py-8 justify-center">
      <div className="w-5 h-5 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
      <span>Loading admins...</span>
    </div>
  );

  return (
    <div className="space-y-4">
      {success && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-3 flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-green-600 flex-shrink-0" />
          <p className="text-sm text-green-800">{success}</p>
        </div>
      )}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
          <p className="text-sm text-red-800">{error}</p>
        </div>
      )}

      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">{admins.length} admin account{admins.length !== 1 ? "s" : ""}</p>
        {isOwner && (
          <button onClick={() => setShowAddDialog(true)}
            className="bg-indigo-600 text-white px-3 py-1.5 rounded-lg hover:bg-indigo-700 transition-colors text-sm flex items-center gap-1.5">
            <Plus className="w-4 h-4" /> Add Admin
          </button>
        )}
      </div>

      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="text-left px-4 py-2.5 font-medium text-gray-700">Admin ID</th>
              <th className="text-left px-4 py-2.5 font-medium text-gray-700">Role</th>
              <th className="text-left px-4 py-2.5 font-medium text-gray-700">TOTP</th>
              <th className="text-left px-4 py-2.5 font-medium text-gray-700 hidden sm:table-cell">Last Unlock</th>
              <th className="text-right px-4 py-2.5 font-medium text-gray-700">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {admins.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-400 text-sm">
                  No admin accounts found.
                </td>
              </tr>
            ) : (
              admins.map((admin) => (
                <tr key={admin.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 bg-indigo-100 rounded-full flex items-center justify-center">
                        <User className="w-3.5 h-3.5 text-indigo-600" />
                      </div>
                      <span className="font-medium text-gray-900 font-mono text-xs">{admin.id}</span>
                      {admin.id === currentId && (
                        <span className="text-[10px] bg-indigo-100 text-indigo-700 px-1.5 py-0.5 rounded font-medium">You</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3"><AdminRoleBadge role={admin.role} /></td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 text-xs font-medium ${admin.totp_enrolled ? "text-green-700" : "text-gray-400"}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${admin.totp_enrolled ? "bg-green-500" : "bg-gray-300"}`} />
                      {admin.totp_enrolled ? "Enrolled" : "Not enrolled"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 hidden sm:table-cell">
                    {admin.last_unlock ? new Date(admin.last_unlock).toLocaleString() : "Never"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-0.5">
                      <button onClick={() => { setNewAdminPass(""); setPassError(""); setShowPassDialog(admin.id); }}
                        className="p-1.5 text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-md transition-colors"
                        title="Change passphrase">
                        <KeyRound className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setShowTOTPReset(admin.id)}
                        className="p-1.5 text-gray-400 hover:text-amber-600 hover:bg-amber-50 rounded-md transition-colors"
                        title="Reset TOTP">
                        <Smartphone className="w-3.5 h-3.5" />
                      </button>
                      {admin.id !== "owner" && admin.id !== currentId && isOwner && (
                        <button onClick={() => setConfirmRemove(admin.id)}
                          className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                          title="Remove admin">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add Admin Dialog */}
      {showAddDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Add New Admin</h2>
            <form onSubmit={handleAdd} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Admin ID</label>
                <input type="text" value={addId}
                  onChange={e => setAddId(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 font-mono"
                  placeholder="e.g., alice" required disabled={adding} />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Passphrase (min 12 chars)</label>
                <input type="password" value={addPassphrase}
                  onChange={e => setAddPassphrase(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500"
                  placeholder="Min. 12 characters" required disabled={adding} />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
                <div className="flex gap-4">
                  {(["admin", "readonly"] as const).map(r => (
                    <label key={r} className="flex items-center gap-1.5 cursor-pointer text-sm">
                      <input type="radio" name="role" value={r}
                        checked={addRole === r}
                        onChange={() => setAddRole(r)}
                        disabled={adding} />
                      <span className="capitalize">{r}</span>
                    </label>
                  ))}
                </div>
              </div>
              {addError && <p className="text-red-600 text-sm">{addError}</p>}
              <div className="flex gap-3 pt-1">
                <button type="button" onClick={() => { setShowAddDialog(false); setAddError(""); }}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm hover:bg-gray-50" disabled={adding}>
                  Cancel
                </button>
                <button type="submit" disabled={adding || !addId || addPassphrase.length < 12}
                  className="flex-1 bg-indigo-600 text-white px-3 py-2 rounded-lg text-sm hover:bg-indigo-700 disabled:opacity-60">
                  {adding ? "Adding..." : "Add Admin"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Remove Confirmation */}
      {confirmRemove && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-sm">
            <div className="flex items-center gap-3 mb-3">
              <AlertCircle className="w-5 h-5 text-red-600" />
              <h3 className="text-lg font-semibold text-gray-900">Remove Admin</h3>
            </div>
            <p className="text-sm text-gray-600 mb-4">
              Remove admin <strong className="font-mono">{confirmRemove}</strong>? They will no longer be able to unlock the vault.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setConfirmRemove(null)}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm hover:bg-gray-50" disabled={removing}>
                Cancel
              </button>
              <button onClick={() => handleRemove(confirmRemove)} disabled={removing}
                className="flex-1 bg-red-600 text-white px-3 py-2 rounded-lg text-sm hover:bg-red-700 disabled:opacity-60">
                {removing ? "Removing..." : "Remove"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Change Passphrase Dialog */}
      {showPassDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-1">Change Passphrase</h3>
            <p className="text-sm text-gray-500 mb-4">for <strong className="font-mono">{showPassDialog}</strong></p>
            <form onSubmit={handleChangePassphrase}>
              <input type="password" value={newAdminPass}
                onChange={e => { setNewAdminPass(e.target.value); setPassError(""); }}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 mb-3"
                placeholder="New passphrase (12+ chars)" autoFocus required disabled={changingPass} />
              {passError && <p className="text-red-600 text-sm mb-2">{passError}</p>}
              <div className="flex gap-3">
                <button type="button" onClick={() => { setShowPassDialog(null); setNewAdminPass(""); setPassError(""); }}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm hover:bg-gray-50" disabled={changingPass}>
                  Cancel
                </button>
                <button type="submit" disabled={changingPass || newAdminPass.length < 12}
                  className="flex-1 bg-indigo-600 text-white px-3 py-2 rounded-lg text-sm hover:bg-indigo-700 disabled:opacity-60">
                  {changingPass ? "Updating..." : "Update"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* TOTP Reset Confirmation */}
      {showTOTPReset && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-sm">
            <div className="flex items-center gap-3 mb-3">
              <Smartphone className="w-5 h-5 text-amber-600" />
              <h3 className="text-lg font-semibold text-gray-900">Reset TOTP</h3>
            </div>
            <p className="text-sm text-gray-600 mb-4">
              Reset two-factor authentication for <strong className="font-mono">{showTOTPReset}</strong>?
              They will need to re-enroll.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setShowTOTPReset(null)}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm hover:bg-gray-50" disabled={totpResetLoading}>
                Cancel
              </button>
              <button onClick={() => handleTOTPReset(showTOTPReset)} disabled={totpResetLoading}
                className="flex-1 bg-amber-600 text-white px-3 py-2 rounded-lg text-sm hover:bg-amber-700 disabled:opacity-60">
                {totpResetLoading ? "Resetting..." : "Reset TOTP"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Admin Panel ─────────────────────────────────────────────────────────────

export function Admin() {
  const [tab, setTab] = useState<Tab>("accounts");

  const tabs: { id: Tab; label: string; icon: typeof Terminal }[] = [
    { id: "accounts", label: "Accounts",  icon: Users    },
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
          <p className="text-sm text-gray-500">Manage accounts, run commands, and configure system services</p>
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
          {tab === "accounts" && <AccountsTab />}
          {tab === "terminal" && <TerminalTab />}
          {tab === "services" && <ServicesTab />}
          {tab === "files"    && <FilesTab />}
        </div>
      </div>
    </div>
  );
}
