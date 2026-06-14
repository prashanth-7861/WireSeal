import { useState, useEffect, useCallback } from "react";
import { Bell, Send, RefreshCw, CheckCircle2, AlertTriangle } from "lucide-react";
import { api, type NotificationConfig } from "../api";

const SENTINEL = "__SET__";

const EVENT_LABELS: Record<string, string> = {
  client_connect:  "Client connects",
  unlock_failed:   "Failed unlock attempt",
  backup_done:     "Backup completed",
  backup_failed:   "Backup failed",
  ttl_expiring:    "Client expiring soon",
  tamper_detected: "Audit tampering detected",
};

const EMPTY: NotificationConfig = {
  enabled: false,
  events: {},
  channels: {
    ntfy:    { enabled: false, url: "https://ntfy.sh", topic: "", token: "" },
    webhook: { enabled: false, url: "" },
    smtp:    { enabled: false, host: "", port: 587, user: "", pass: "", from: "", to: "" },
  },
};

export function Notifications() {
  const [cfg, setCfg] = useState<NotificationConfig>(EMPTY);
  const [events, setEvents] = useState<string[]>(Object.keys(EVENT_LABELS));
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getNotifications();
      setCfg({ ...EMPTY, ...res.notifications, channels: { ...EMPTY.channels, ...res.notifications.channels } });
      if (res.events?.length) setEvents(res.events);
    } catch { /* vault may be locked */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    setSaving(true); setMsg(null);
    try {
      await api.setNotifications(cfg);
      setMsg({ kind: "ok", text: "Saved." });
      load();
    } catch (e: unknown) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Save failed" });
    } finally { setSaving(false); }
  };

  const test = async () => {
    setTesting(true); setMsg(null);
    try {
      const res = await api.testNotifications();
      if (res.sent.length === 0 && res.errors.length === 0) {
        setMsg({ kind: "err", text: "No channels enabled. Enable & save a channel first." });
      } else if (res.errors.length) {
        setMsg({ kind: "err", text: `Sent: ${res.sent.join(", ") || "none"}. Errors: ${res.errors.join("; ")}` });
      } else {
        setMsg({ kind: "ok", text: `Test sent via ${res.sent.join(", ")}.` });
      }
    } catch (e: unknown) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Test failed" });
    } finally { setTesting(false); }
  };

  const setCh = <K extends keyof NotificationConfig["channels"]>(
    name: K, patch: Partial<NotificationConfig["channels"][K]>,
  ) => setCfg(c => ({ ...c, channels: { ...c.channels, [name]: { ...c.channels[name], ...patch } } }));

  // Secret input: show empty when value is the sentinel; placeholder signals "saved".
  const secretProps = (val: string | undefined) => ({
    value: val === SENTINEL ? "" : (val ?? ""),
    placeholder: val === SENTINEL ? "•••••••• (saved — leave blank to keep)" : "",
  });

  if (loading) return <div className="p-6 text-gray-500 text-sm">Loading…</div>;

  return (
    <div className="p-6 max-w-3xl space-y-6">
      <div className="flex items-center gap-3">
        <Bell className="w-7 h-7 text-blue-600" />
        <h1 className="text-2xl font-bold text-gray-900">Notifications</h1>
      </div>
      <p className="text-sm text-gray-500 -mt-2">
        Get pushed when things happen — a client connects, a backup runs, an unlock fails,
        or the audit log is tampered with. Sends via ntfy, a webhook, or email.
      </p>

      {msg && (
        <div className={`rounded-lg px-4 py-3 text-sm flex items-center gap-2 ${
          msg.kind === "ok" ? "bg-green-50 border border-green-200 text-green-800"
                            : "bg-red-50 border border-red-200 text-red-800"}`}>
          {msg.kind === "ok" ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {msg.text}
        </div>
      )}

      {/* Master toggle */}
      <label className="flex items-center gap-2 text-sm font-medium text-gray-800">
        <input type="checkbox" checked={cfg.enabled} onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} className="rounded" />
        Enable notifications
      </label>

      {/* Events */}
      <section className="bg-white rounded-xl border border-gray-200 p-5">
        <h2 className="text-sm font-semibold text-gray-800 mb-3">Notify me when…</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {events.map(ev => (
            <label key={ev} className="flex items-center gap-2 text-sm text-gray-700">
              <input type="checkbox" checked={!!cfg.events[ev]}
                onChange={e => setCfg(c => ({ ...c, events: { ...c.events, [ev]: e.target.checked } }))}
                className="rounded" />
              {EVENT_LABELS[ev] ?? ev}
            </label>
          ))}
        </div>
      </section>

      {/* ntfy */}
      <ChannelCard title="ntfy" enabled={cfg.channels.ntfy.enabled}
        onToggle={v => setCh("ntfy", { enabled: v })}>
        <Field label="Server URL">
          <input className={inputCls} value={cfg.channels.ntfy.url}
            onChange={e => setCh("ntfy", { url: e.target.value })} placeholder="https://ntfy.sh" />
        </Field>
        <Field label="Topic">
          <input className={inputCls} value={cfg.channels.ntfy.topic}
            onChange={e => setCh("ntfy", { topic: e.target.value })} placeholder="my-wireseal-alerts" />
        </Field>
        <Field label="Access token (optional)">
          <input type="password" className={inputCls} {...secretProps(cfg.channels.ntfy.token)}
            onChange={e => setCh("ntfy", { token: e.target.value })} autoComplete="new-password" />
        </Field>
      </ChannelCard>

      {/* webhook */}
      <ChannelCard title="Webhook (JSON POST)" enabled={cfg.channels.webhook.enabled}
        onToggle={v => setCh("webhook", { enabled: v })}>
        <Field label="URL">
          <input className={inputCls} value={cfg.channels.webhook.url}
            onChange={e => setCh("webhook", { url: e.target.value })} placeholder="https://example.com/hook" />
        </Field>
      </ChannelCard>

      {/* smtp */}
      <ChannelCard title="Email (SMTP)" enabled={cfg.channels.smtp.enabled}
        onToggle={v => setCh("smtp", { enabled: v })}>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Host"><input className={inputCls} value={cfg.channels.smtp.host} onChange={e => setCh("smtp", { host: e.target.value })} placeholder="smtp.gmail.com" /></Field>
          <Field label="Port"><input type="number" className={inputCls} value={cfg.channels.smtp.port} onChange={e => setCh("smtp", { port: parseInt(e.target.value) || 587 })} /></Field>
          <Field label="Username"><input className={inputCls} value={cfg.channels.smtp.user} onChange={e => setCh("smtp", { user: e.target.value })} /></Field>
          <Field label="Password"><input type="password" className={inputCls} {...secretProps(cfg.channels.smtp.pass)} onChange={e => setCh("smtp", { pass: e.target.value })} autoComplete="new-password" /></Field>
          <Field label="From"><input className={inputCls} value={cfg.channels.smtp.from} onChange={e => setCh("smtp", { from: e.target.value })} placeholder="wireseal@example.com" /></Field>
          <Field label="To"><input className={inputCls} value={cfg.channels.smtp.to} onChange={e => setCh("smtp", { to: e.target.value })} placeholder="you@example.com" /></Field>
        </div>
      </ChannelCard>

      <div className="flex items-center gap-3">
        <button onClick={save} disabled={saving}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50">
          {saving ? "Saving…" : "Save"}
        </button>
        <button onClick={test} disabled={testing || !cfg.enabled}
          className="px-4 py-2 border rounded-lg text-sm font-medium hover:bg-gray-50 disabled:opacity-50 flex items-center gap-1.5">
          {testing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          Send test
        </button>
      </div>
    </div>
  );
}

const inputCls = "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
      {children}
    </div>
  );
}

function ChannelCard({ title, enabled, onToggle, children }: {
  title: string; enabled: boolean; onToggle: (v: boolean) => void; children: React.ReactNode;
}) {
  return (
    <section className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
      <label className="flex items-center gap-2 text-sm font-semibold text-gray-800">
        <input type="checkbox" checked={enabled} onChange={e => onToggle(e.target.checked)} className="rounded" />
        {title}
      </label>
      {enabled && <div className="space-y-3 pl-6">{children}</div>}
    </section>
  );
}
