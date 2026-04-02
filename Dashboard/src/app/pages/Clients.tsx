import { useState, useEffect, useCallback, useRef } from "react";
import {
  Plus, Monitor, Trash2, QrCode, X, AlertTriangle, CheckCircle, RefreshCw,
  Download,
} from "lucide-react";
import { api, type Client, type Status } from "../api";

const QR_TTL = 60; // seconds before QR auto-dismisses

interface QrPanel {
  name: string;
  qr: string;
  format: string; // "png" or "svg+xml"
  expiresAt: number; // Date.now() + QR_TTL * 1000
}

export function Clients() {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [peerStatus, setPeerStatus] = useState<Status | null>(null);

  // Add dialog
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newName, setNewName] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  // QR side panel
  const [qrPanel, setQrPanel] = useState<QrPanel | null>(null);
  const [qrCountdown, setQrCountdown] = useState(0);
  const [qrRefreshing, setQrRefreshing] = useState(false);
  const countdownRef = useRef<number | null>(null);

  // ── Countdown timer ───────────────────────────────────────────────────────
  const startCountdown = useCallback((expiresAt: number) => {
    if (countdownRef.current) clearInterval(countdownRef.current);
    const tick = () => {
      const remaining = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
      setQrCountdown(remaining);
      if (remaining === 0) {
        clearInterval(countdownRef.current!);
        setQrPanel(null);
      }
    };
    tick();
    countdownRef.current = window.setInterval(tick, 1000);
  }, []);

  useEffect(() => () => { if (countdownRef.current) clearInterval(countdownRef.current); }, []);

  // ── Load clients ──────────────────────────────────────────────────────────
  const fetchClients = useCallback(async () => {
    try {
      setClients(await api.listClients());
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load clients");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchClients(); }, [fetchClients]);

  // Poll /api/status every 5 s for live connection data
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const s = await api.status();
        if (!cancelled) setPeerStatus(s);
      } catch {
        // Status unavailable — keep previous peerStatus, don't clear it
      }
    };
    poll();
    const id = window.setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  // ── Open QR panel ─────────────────────────────────────────────────────────
  const openQr = useCallback(async (name: string) => {
    setQrRefreshing(true);
    try {
      const res = await api.clientQr(name);
      const expiresAt = Date.now() + QR_TTL * 1000;
      setQrPanel({ name: res.name, qr: res.qr_png_b64, format: res.format || "png", expiresAt });
      startCountdown(expiresAt);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load QR code");
    } finally {
      setQrRefreshing(false);
    }
  }, [startCountdown]);

  const closeQr = () => {
    if (countdownRef.current) clearInterval(countdownRef.current);
    setQrPanel(null);
  };

  // ── Add client ────────────────────────────────────────────────────────────
  const handleAddClient = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddError("");
    setAdding(true);
    try {
      const client = await api.addClient(newName.trim());
      setClients((prev) => [...prev, client]);
      setNewName("");
      setShowAddDialog(false);
      setSuccess(`Client "${client.name}" added — scan the QR code to connect`);
      setTimeout(() => setSuccess(""), 5000);
      // Auto-open QR for the new client
      openQr(client.name);
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : "Failed to add client");
    } finally {
      setAdding(false);
    }
  };

  // ── Delete client ─────────────────────────────────────────────────────────
  const handleDelete = async (name: string) => {
    if (!confirm(`Remove "${name}"? This will revoke their WireGuard access immediately.`)) return;
    try {
      await api.removeClient(name);
      setClients((prev) => prev.filter((c) => c.name !== name));
      if (qrPanel?.name === name) closeQr();
      setSuccess(`Client "${name}" removed`);
      setTimeout(() => setSuccess(""), 4000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to remove client");
    }
  };

  // ── Download config ──────────────────────────────────────────────────────
  const handleDownloadConfig = async (name: string) => {
    try {
      const res = await api.clientConfig(name);
      const blob = new Blob([res.config], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${name}.conf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to download config");
    }
  };

  // ── Progress ring for countdown ───────────────────────────────────────────
  const ringProgress = qrCountdown / QR_TTL;
  const circumference = 2 * Math.PI * 18; // r=18
  const dashOffset = circumference * (1 - ringProgress);

  // Build a Map from WireGuard peer IP (without /32 suffix) → Peer for O(1) badge lookup
  const peerMap = new Map(
    (peerStatus?.peers ?? []).map((p) => [
      p.allowed_ips.split("/")[0],
      p,
    ])
  );

  // Badge helpers (same thresholds as Dashboard.tsx)
  const badgeClass = (secs: number): string => {
    if (secs >= 0 && secs < 180)   return "bg-green-100 text-green-700";
    if (secs >= 180 && secs < 600) return "bg-yellow-100 text-yellow-700";
    return "bg-gray-100 text-gray-600";
  };
  const dotClass = (secs: number): string => {
    if (secs >= 0 && secs < 180)   return "bg-green-500 animate-pulse";
    if (secs >= 180 && secs < 600) return "bg-yellow-500";
    return "bg-gray-400";
  };
  const badgeLabel = (secs: number): string => {
    if (secs >= 0 && secs < 180)   return "Connected";
    if (secs >= 180 && secs < 600) return "Recent";
    return "Idle";
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Clients</h1>
          <p className="text-gray-500 mt-1">Manage WireGuard clients</p>
        </div>
        <button
          onClick={() => setShowAddDialog(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
        >
          <Plus className="w-5 h-5" />
          Add Client
        </button>
      </div>

      {success && (
        <div className="mb-6 bg-green-50 border border-green-200 rounded-lg p-4 flex items-center gap-3">
          <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
          <p className="text-green-800">{success}</p>
        </div>
      )}
      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* ── Main layout: list + QR panel side by side ── */}
      <div className={`flex gap-6 items-start transition-all duration-300`}>

        {/* Client list */}
        <div className="flex-1 min-w-0 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          {loading ? (
            <div className="p-12 text-center text-gray-500">Loading clients…</div>
          ) : clients.length === 0 ? (
            <div className="p-12 text-center">
              <Monitor className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="font-medium text-gray-900 mb-2">No clients yet</h3>
              <p className="text-gray-500 mb-4">Add your first WireGuard client to get started</p>
              <button
                onClick={() => setShowAddDialog(true)}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors inline-flex items-center gap-2"
              >
                <Plus className="w-5 h-5" />
                Add Client
              </button>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Name</th>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Assigned IP</th>
                  <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Status</th>
                  <th className="text-right px-6 py-3 text-sm font-medium text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {clients.map((client) => (
                  <tr
                    key={client.name}
                    className={`hover:bg-gray-50 transition-colors ${qrPanel?.name === client.name ? "bg-blue-50" : ""}`}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <Monitor className="w-5 h-5 text-gray-400 flex-shrink-0" />
                        <span className="font-medium text-gray-900">{client.name}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-700 font-mono text-sm">{client.ip}</td>
                    <td className="px-6 py-4">
                      {(() => {
                        const ip = client.ip.split("/")[0];
                        const peer = peerMap.get(ip);
                        const secs = peer?.last_handshake_seconds ?? -1;
                        if (!peerStatus) {
                          return (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-400">
                              <span className="w-1.5 h-1.5 rounded-full bg-gray-300" />
                              —
                            </span>
                          );
                        }
                        return (
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${badgeClass(secs)}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${dotClass(secs)}`} />
                            {badgeLabel(secs)}
                          </span>
                        );
                      })()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openQr(client.name)}
                          disabled={qrRefreshing}
                          className={`p-2 rounded-lg transition-colors ${
                            qrPanel?.name === client.name
                              ? "text-blue-700 bg-blue-100 hover:bg-blue-200"
                              : "text-blue-600 hover:text-blue-700 hover:bg-blue-50"
                          }`}
                          title="Show QR code"
                        >
                          <QrCode className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => handleDownloadConfig(client.name)}
                          className="text-green-600 hover:text-green-700 p-2 rounded-lg hover:bg-green-50 transition-colors"
                          title="Download config file"
                        >
                          <Download className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => handleDelete(client.name)}
                          className="text-red-600 hover:text-red-700 p-2 rounded-lg hover:bg-red-50 transition-colors"
                          title="Remove client"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* QR side panel */}
        {qrPanel && (
          <div className="w-72 flex-shrink-0 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 bg-gray-50">
              <div>
                <p className="font-medium text-gray-900 text-sm">{qrPanel.name}</p>
                <p className="text-xs text-gray-500">Scan with WireGuard app</p>
              </div>
              <button
                onClick={closeQr}
                className="text-gray-400 hover:text-gray-600 p-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* QR image */}
            <div className="p-4">
              <img
                src={`data:image/${qrPanel.format};base64,${qrPanel.qr}`}
                alt={`QR code for ${qrPanel.name}`}
                className="w-full rounded-lg border border-gray-100"
              />
            </div>

            {/* Countdown + regenerate */}
            <div className="px-4 pb-4 flex items-center justify-between">
              {/* Circular countdown */}
              <div className="flex items-center gap-2">
                <svg width="44" height="44" className="-rotate-90">
                  <circle cx="22" cy="22" r="18" fill="none" stroke="#e5e7eb" strokeWidth="3" />
                  <circle
                    cx="22" cy="22" r="18" fill="none"
                    stroke={qrCountdown > 15 ? "#3b82f6" : "#ef4444"}
                    strokeWidth="3"
                    strokeDasharray={circumference}
                    strokeDashoffset={dashOffset}
                    strokeLinecap="round"
                    style={{ transition: "stroke-dashoffset 0.9s linear, stroke 0.3s" }}
                  />
                </svg>
                <div>
                  <p className={`text-lg font-semibold leading-none ${qrCountdown > 15 ? "text-gray-900" : "text-red-600"}`}>
                    {qrCountdown}s
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5">expires</p>
                </div>
              </div>

              {/* Regenerate button */}
              <button
                onClick={() => openQr(qrPanel.name)}
                disabled={qrRefreshing}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-gray-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${qrRefreshing ? "animate-spin" : ""}`} />
                Regenerate
              </button>
            </div>

            {/* Download config button */}
            <div className="px-4 pb-4">
              <button
                onClick={() => handleDownloadConfig(qrPanel.name)}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-sm bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
              >
                <Download className="w-4 h-4" />
                Download Config File
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Add Client Dialog ─────────────────────────────────────────────── */}
      {showAddDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
            <h2 className="text-xl font-semibold text-gray-900 mb-1">Add New Client</h2>
            <p className="text-sm text-gray-500 mb-5">
              A WireGuard keypair and config will be generated automatically.
            </p>
            <form onSubmit={handleAddClient} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Client Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="e.g., laptop-home"
                  pattern="[a-zA-Z0-9\-]{1,32}"
                  title="Alphanumeric and hyphens only, max 32 characters"
                  required
                  autoFocus
                  disabled={adding}
                />
                <p className="text-xs text-gray-400 mt-1.5">
                  Alphanumeric and hyphens only, max 32 chars
                </p>
              </div>

              {addError && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span>{addError}</span>
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => { setShowAddDialog(false); setAddError(""); setNewName(""); }}
                  className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={adding}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 text-white px-4 py-2.5 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60"
                  disabled={adding}
                >
                  {adding ? "Generating…" : "Add Client"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
