import { useState, useEffect } from "react";
import { Shield, Plus, Trash2, X, AlertTriangle, CheckCircle2 } from "lucide-react";
import { api, type AclRule, type ClientAcl } from "../../api";

interface Props {
  clientName: string;
  clientIp: string;
  onClose: () => void;
  onSaved?: () => void;
}

const EMPTY_RULE: AclRule = { dest: "", port: null, proto: "any" };

export function ClientAclEditor({ clientName, clientIp, onClose, onSaved }: Props) {
  const [mode, setMode] = useState<ClientAcl["mode"]>("allow_all");
  const [rules, setRules] = useState<AclRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.getClientAcl(clientName);
        setMode(res.acl.mode);
        setRules(res.acl.rules || []);
      } catch { /* default allow_all */ }
      finally { setLoading(false); }
    })();
  }, [clientName]);

  const setRule = (i: number, patch: Partial<AclRule>) =>
    setRules(rs => rs.map((r, idx) => idx === i ? { ...r, ...patch } : r));

  const save = async () => {
    setSaving(true); setMsg(null);
    try {
      const clean = mode === "restricted"
        ? rules.filter(r => r.dest.trim()).map(r => ({
            dest: r.dest.trim(),
            port: r.port ? Number(r.port) : null,
            proto: r.port && r.proto === "any" ? "tcp" : r.proto,
          }))
        : [];
      const res = await api.setClientAcl(clientName, { mode, rules: clean });
      if (!res.applied && res.warning) {
        setMsg({ kind: "err", text: `Saved, but not enforced: ${res.warning}` });
      } else {
        setMsg({ kind: "ok", text: "Saved and enforced." });
        onSaved?.();
      }
    } catch (e: unknown) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Save failed" });
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b">
          <h3 className="flex items-center gap-2 text-base font-semibold text-gray-900">
            <Shield className="w-4 h-4 text-blue-600" /> Access control — {clientName}
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-5 space-y-4">
          <p className="text-xs text-gray-500">
            Client IP <span className="font-mono">{clientIp}</span>. Restricted mode drops all
            traffic from this client except the destinations you allow below.
          </p>

          {msg && (
            <div className={`rounded-lg px-3 py-2 text-sm flex items-center gap-2 ${
              msg.kind === "ok" ? "bg-green-50 border border-green-200 text-green-800"
                                : "bg-amber-50 border border-amber-200 text-amber-800"}`}>
              {msg.kind === "ok" ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
              {msg.text}
            </div>
          )}

          {loading ? <p className="text-sm text-gray-400">Loading…</p> : (
            <>
              <div className="flex gap-2">
                {(["allow_all", "restricted"] as const).map(m => (
                  <button key={m} onClick={() => setMode(m)}
                    className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                      mode === m ? "bg-blue-600 text-white border-blue-600" : "bg-white text-gray-600 border-gray-200 hover:bg-gray-50"}`}>
                    {m === "allow_all" ? "Allow all (open)" : "Restricted"}
                  </button>
                ))}
              </div>

              {mode === "restricted" && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-gray-600">Allowed destinations</span>
                    <button onClick={() => setRules(rs => [...rs, { ...EMPTY_RULE }])}
                      className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800">
                      <Plus className="w-3.5 h-3.5" /> Add
                    </button>
                  </div>
                  {rules.length === 0 && (
                    <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1.5">
                      No rules — this client will be fully blocked. Add at least one destination.
                    </p>
                  )}
                  {rules.map((r, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <input value={r.dest} onChange={e => setRule(i, { dest: e.target.value })}
                        placeholder="10.0.0.10 or 10.0.0.0/24"
                        className="flex-1 border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
                      <select value={r.proto} onChange={e => setRule(i, { proto: e.target.value as AclRule["proto"] })}
                        className="border border-gray-300 rounded-lg px-2 py-1.5 text-sm bg-white">
                        <option value="any">any</option><option value="tcp">tcp</option><option value="udp">udp</option>
                      </select>
                      <input type="number" value={r.port ?? ""} onChange={e => setRule(i, { port: e.target.value ? Number(e.target.value) : null })}
                        placeholder="port" className="w-20 border border-gray-300 rounded-lg px-2 py-1.5 text-sm" />
                      <button onClick={() => setRules(rs => rs.filter((_, idx) => idx !== i))}
                        className="text-gray-400 hover:text-red-600 p-1"><Trash2 className="w-4 h-4" /></button>
                    </div>
                  ))}
                  <p className="text-xs text-gray-400">Tip: a port requires tcp or udp. Leave port blank to allow all ports on a host/subnet.</p>
                </div>
              )}
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 px-5 py-3 border-t bg-gray-50">
          <button onClick={onClose} className="px-4 py-2 text-sm border rounded-lg hover:bg-white">Cancel</button>
          <button onClick={save} disabled={saving || loading}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
