import { useState, useEffect, useCallback } from "react";
import {
  Wifi, WifiOff, Upload, Trash2, Play, Square, RefreshCw, Plus,
  Server, Globe, Clock, AlertTriangle, CheckCircle, Pencil, X,
} from "lucide-react";
import { api, ClientConfig, ClientTunnelStatus } from "../../api";

// Pretty-print byte counts for the status banner.
function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

export function Connect() {
  const [configs, setConfigs] = useState<ClientConfig[]>([]);
  const [tunnel, setTunnel] = useState<ClientTunnelStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Import dialog state
  const [showImport, setShowImport] = useState(false);
  const [importName, setImportName] = useState("");
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState("");

  // Edit dialog state — used when the server admin rotates keys or
  // changes the WireGuard port and the client receives a fresh .conf.
  const [editName, setEditName] = useState<string | null>(null);
  const [editText, setEditText] = useState("");
  const [editing, setEditing] = useState(false);
  const [editError, setEditError] = useState("");

  // Action state
  const [connecting, setConnecting] = useState("");
  const [disconnecting, setDisconnecting] = useState(false);
  const [deleting, setDeleting] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [cfgRes, tunnelRes] = await Promise.all([
        api.clientListConfigs(),
        api.clientTunnelStatus(),
      ]);
      setConfigs(cfgRes.configs);
      setTunnel(tunnelRes);
      setError("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Poll tunnel status: 5s connected (live RX/TX + handshake age),
  // 15s disconnected (catches external `wg-quick up` / kill events).
  useEffect(() => {
    const intervalMs = tunnel?.connected ? 5000 : 15000;
    const id = setInterval(async () => {
      try {
        const s = await api.clientTunnelStatus();
        setTunnel(s);
      } catch { /* ignore */ }
    }, intervalMs);
    return () => clearInterval(id);
  }, [tunnel?.connected]);

  const handleImport = async () => {
    setImporting(true);
    setImportError("");
    try {
      await api.clientImportConfig(importName.trim(), importText);
      setShowImport(false);
      setImportName("");
      setImportText("");
      await refresh();
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setImportText(reader.result as string);
      if (!importName) {
        setImportName(file.name.replace(/\.conf$/i, ""));
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleConnect = async (name: string) => {
    setConnecting(name);
    setError("");
    try {
      await api.clientTunnelUp(name);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Connect failed");
    } finally {
      setConnecting("");
    }
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    setError("");
    try {
      await api.clientTunnelDown();
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Disconnect failed");
    } finally {
      setDisconnecting(false);
    }
  };

  const handleDelete = async (name: string) => {
    if (tunnel?.connected && tunnel.profile === name) {
      setError("Disconnect the tunnel before deleting this profile");
      return;
    }
    setDeleting(name);
    try {
      await api.clientDeleteConfig(name);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setDeleting("");
    }
  };

  // Edit handler — opens a modal pre-filled with the profile's redacted
  // config text. User pastes the fresh .conf received from the admin and
  // submits.
  const openEdit = async (name: string) => {
    if (tunnel?.connected && tunnel.profile === name) {
      setError("Disconnect the tunnel before editing this profile");
      return;
    }
    setEditError("");
    setEditing(false);
    setEditName(name);
    try {
      const full = await api.clientGetConfig(name);
      // The backend redacts PrivateKey by default. User must paste a fresh
      // .conf that includes their PrivateKey, so seed the textarea with the
      // redacted text as a hint of what to replace.
      setEditText(full.config_text || "");
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : "Failed to load profile");
      setEditText("");
    }
  };

  const closeEdit = () => {
    setEditName(null);
    setEditText("");
    setEditError("");
  };

  const handleEditSubmit = async () => {
    if (!editName) return;
    if (!editText.trim()) {
      setEditError("Paste the new .conf content");
      return;
    }
    if (/PrivateKey\s*=\s*<redacted>/i.test(editText)) {
      setEditError("Replace the redacted PrivateKey line with the actual key from your fresh .conf");
      return;
    }
    setEditing(true);
    setEditError("");
    try {
      await api.clientUpdateConfig(editName, editText);
      closeEdit();
      await refresh();
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setEditing(false);
    }
  };

  const handleEditFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setEditText(reader.result as string);
    reader.readAsText(file);
    e.target.value = "";
  };

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Connect</h1>
          <p className="text-gray-500 mt-1">
            Import a WireGuard config and connect to your server
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={refresh}
            className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
          <button
            onClick={() => setShowImport(true)}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Import Config
          </button>
        </div>
      </div>

      {/* Tunnel status banner — live stats from `wg show` parsed by backend.
          Color flips to amber when the interface is up but no handshake has
          been received — typical signature of an unreachable endpoint, wrong
          server key, or NAT/firewall blocking UDP. */}
      {tunnel?.connected && (
        <div
          className={`mb-6 rounded-lg p-4 space-y-3 border ${
            tunnel.handshake_ok === false
              ? "bg-amber-50 border-amber-300"
              : "bg-emerald-50 border-emerald-200"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div
                className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                  tunnel.handshake_ok === false ? "bg-amber-100" : "bg-emerald-100"
                }`}
              >
                <Wifi
                  className={`w-5 h-5 ${
                    tunnel.handshake_ok === false ? "text-amber-600" : "text-emerald-600"
                  }`}
                />
              </div>
              <div>
                <p
                  className={`text-sm font-medium ${
                    tunnel.handshake_ok === false ? "text-amber-900" : "text-emerald-900"
                  }`}
                >
                  {tunnel.handshake_ok === false
                    ? `Tunnel up, no handshake — ${tunnel.profile}`
                    : `VPN Connected — ${tunnel.profile}`}
                </p>
                <p
                  className={`text-xs ${
                    tunnel.handshake_ok === false ? "text-amber-700" : "text-emerald-600"
                  }`}
                >
                  Interface: <span className="font-mono">{tunnel.interface}</span>
                  {tunnel.handshake_ok === false && (
                    <span className="ml-2">
                      · No peer response. Check server reachability + key match.
                    </span>
                  )}
                </p>
              </div>
            </div>
            <button
              onClick={handleDisconnect}
              disabled={disconnecting}
              className="flex items-center gap-2 px-3 py-1.5 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors text-sm disabled:opacity-50"
            >
              <Square className="w-3.5 h-3.5" />
              {disconnecting ? "Disconnecting..." : "Disconnect"}
            </button>
          </div>
          {tunnel.stats?.peer && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-emerald-200">
              {tunnel.stats.peer.endpoint && (
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-emerald-700">Endpoint</p>
                  <p className="text-xs font-mono text-emerald-900 truncate" title={tunnel.stats.peer.endpoint}>
                    {tunnel.stats.peer.endpoint}
                  </p>
                </div>
              )}
              {tunnel.stats.peer.latest_handshake && (
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-emerald-700">Last handshake</p>
                  <p className="text-xs font-mono text-emerald-900 truncate" title={tunnel.stats.peer.latest_handshake}>
                    {tunnel.stats.peer.latest_handshake}
                  </p>
                </div>
              )}
              {tunnel.stats.peer.rx_bytes !== undefined && (
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-emerald-700">Received</p>
                  <p className="text-xs font-mono text-emerald-900">
                    {formatBytes(tunnel.stats.peer.rx_bytes)}
                  </p>
                </div>
              )}
              {tunnel.stats.peer.tx_bytes !== undefined && (
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-emerald-700">Sent</p>
                  <p className="text-xs font-mono text-emerald-900">
                    {formatBytes(tunnel.stats.peer.tx_bytes)}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {/* Config profiles list */}
      {loading ? (
        <div className="text-center py-12 text-gray-400">Loading...</div>
      ) : configs.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-8">
          <div className="flex flex-col items-center text-center gap-4 py-8">
            <div className="w-14 h-14 bg-gray-100 rounded-xl flex items-center justify-center">
              <Upload className="w-7 h-7 text-gray-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900 mb-1">
                No Connection Profiles
              </h2>
              <p className="text-gray-500 text-sm">
                Import a <code className="bg-gray-100 px-1.5 py-0.5 rounded text-xs">.conf</code> file
                from your WireSeal server to get started.
              </p>
            </div>
            <button
              onClick={() => setShowImport(true)}
              className="flex items-center gap-2 px-4 py-2.5 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors text-sm font-medium"
            >
              <Upload className="w-4 h-4" />
              Import Config File
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {configs.map((cfg) => {
            const isActive = tunnel?.connected && tunnel.profile === cfg.name;
            const isConnecting = connecting === cfg.name;

            return (
              <div
                key={cfg.name}
                className={`bg-white rounded-lg border p-4 transition-colors ${
                  isActive
                    ? "border-emerald-300 bg-emerald-50/30"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                        isActive ? "bg-emerald-100" : "bg-gray-100"
                      }`}
                    >
                      {isActive ? (
                        <CheckCircle className="w-5 h-5 text-emerald-600" />
                      ) : (
                        <Server className="w-5 h-5 text-gray-400" />
                      )}
                    </div>
                    <div>
                      <h3 className="font-medium text-gray-900">{cfg.name}</h3>
                      <div className="flex items-center gap-4 mt-0.5">
                        {cfg.server_endpoint && (
                          <span className="flex items-center gap-1 text-xs text-gray-500">
                            <Globe className="w-3 h-3" />
                            {cfg.server_endpoint}
                          </span>
                        )}
                        {cfg.interface_ip && (
                          <span className="flex items-center gap-1 text-xs text-gray-500">
                            <Wifi className="w-3 h-3" />
                            {cfg.interface_ip}
                          </span>
                        )}
                        {cfg.imported_at && (
                          <span className="flex items-center gap-1 text-xs text-gray-400">
                            <Clock className="w-3 h-3" />
                            {new Date(cfg.imported_at).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {isActive ? (
                      <button
                        onClick={handleDisconnect}
                        disabled={disconnecting}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors text-sm disabled:opacity-50"
                      >
                        <Square className="w-3.5 h-3.5" />
                        {disconnecting ? "..." : "Disconnect"}
                      </button>
                    ) : (
                      <button
                        onClick={() => handleConnect(cfg.name)}
                        disabled={!!connecting || tunnel?.connected === true}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors text-sm disabled:opacity-50"
                      >
                        <Play className="w-3.5 h-3.5" />
                        {isConnecting ? "Connecting..." : "Connect"}
                      </button>
                    )}
                    <button
                      onClick={() => openEdit(cfg.name)}
                      disabled={isActive}
                      className="p-1.5 text-gray-400 hover:text-blue-600 transition-colors disabled:opacity-30"
                      title="Edit profile (paste new .conf)"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(cfg.name)}
                      disabled={isActive || deleting === cfg.name}
                      className="p-1.5 text-gray-400 hover:text-red-500 transition-colors disabled:opacity-30"
                      title="Delete profile"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Import dialog */}
      {showImport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">
              Import WireGuard Config
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Profile Name
                </label>
                <input
                  type="text"
                  value={importName}
                  onChange={(e) => setImportName(e.target.value)}
                  placeholder="e.g. my-server"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
                  maxLength={32}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Config File
                </label>
                <div className="flex gap-2">
                  <label className="flex items-center gap-2 px-3 py-2 border border-gray-300 rounded-lg text-sm text-gray-600 hover:bg-gray-50 cursor-pointer transition-colors">
                    <Upload className="w-4 h-4" />
                    Choose .conf file
                    <input
                      type="file"
                      accept=".conf"
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                  </label>
                  <span className="text-xs text-gray-400 self-center">or paste below</span>
                </div>
              </div>

              <div>
                <textarea
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                  placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 10.0.0.2/32&#10;&#10;[Peer]&#10;PublicKey = ...&#10;Endpoint = ..."
                  rows={8}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent resize-none"
                />
              </div>

              {importError && (
                <p className="text-sm text-red-600">{importError}</p>
              )}
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setShowImport(false);
                  setImportName("");
                  setImportText("");
                  setImportError("");
                }}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleImport}
                disabled={importing || !importName.trim() || !importText.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors text-sm font-medium disabled:opacity-50"
              >
                {importing ? "Importing..." : "Import"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit dialog — paste new .conf when server endpoint/port/keys change. */}
      {editName && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
          onClick={(e) => {
            if (e.target === e.currentTarget && !editing) closeEdit();
          }}
        >
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
            <div className="flex items-start justify-between p-6 border-b border-gray-100 flex-shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Pencil className="w-5 h-5 text-blue-700" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-gray-900">Edit profile: {editName}</h2>
                  <p className="text-xs text-gray-500">
                    Paste the fresh <code>.conf</code> received from your server admin.
                  </p>
                </div>
              </div>
              <button
                onClick={closeEdit}
                disabled={editing}
                className="p-1 rounded hover:bg-gray-100 transition-colors flex-shrink-0"
                aria-label="Close"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>

            <div className="p-6 space-y-4 flex-1 overflow-y-auto">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-900">
                <p className="font-medium mb-1">When to use this:</p>
                <ul className="list-disc list-inside space-y-0.5">
                  <li>Server admin changed the WireGuard port</li>
                  <li>Server endpoint moved to a new IP / DDNS hostname</li>
                  <li>Server keypair was rotated</li>
                  <li>Your client keys were rotated</li>
                </ul>
                <p className="mt-1.5">
                  The current <code>PrivateKey</code> shows as <code>&lt;redacted&gt;</code> below — replace it with the value from the fresh .conf you received.
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-sm font-medium text-gray-700">New config (paste or upload)</label>
                  <label className="text-xs text-blue-600 hover:text-blue-700 cursor-pointer">
                    Upload .conf
                    <input
                      type="file"
                      accept=".conf,text/plain"
                      onChange={handleEditFile}
                      disabled={editing}
                      className="hidden"
                    />
                  </label>
                </div>
                <textarea
                  value={editText}
                  onChange={(e) => setEditText(e.target.value)}
                  className="w-full h-72 px-3 py-2 border border-gray-300 rounded-lg font-mono text-xs focus:ring-2 focus:ring-blue-500"
                  placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 10.0.0.2/32&#10;DNS = 1.1.1.1&#10;&#10;[Peer]&#10;PublicKey = ...&#10;PresharedKey = ...&#10;Endpoint = vpn.example.com:51820&#10;AllowedIPs = 0.0.0.0/0, ::/0"
                  disabled={editing}
                />
              </div>

              {editError && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-red-700">{editError}</p>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 p-6 border-t border-gray-100 flex-shrink-0 bg-white rounded-b-lg">
              <button
                onClick={closeEdit}
                disabled={editing}
                className="px-4 py-2 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-60"
              >
                Cancel
              </button>
              <button
                onClick={handleEditSubmit}
                disabled={editing || !editText.trim()}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium disabled:opacity-60 flex items-center gap-2"
              >
                <Pencil className="w-4 h-4" />
                {editing ? "Saving..." : "Save changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
