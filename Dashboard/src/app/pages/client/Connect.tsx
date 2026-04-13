import { useState, useEffect, useCallback } from "react";
import {
  Wifi, WifiOff, Upload, Trash2, Play, Square, RefreshCw, Plus,
  Server, Globe, Clock, AlertTriangle, CheckCircle,
} from "lucide-react";
import { api, ClientConfig, ClientTunnelStatus } from "../../api";

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

  // Poll tunnel status every 5s when connected
  useEffect(() => {
    if (!tunnel?.connected) return;
    const id = setInterval(async () => {
      try {
        const s = await api.clientTunnelStatus();
        setTunnel(s);
      } catch { /* ignore */ }
    }, 5000);
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

      {/* Tunnel status banner */}
      {tunnel?.connected && (
        <div className="mb-6 bg-emerald-50 border border-emerald-200 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-emerald-100 rounded-lg flex items-center justify-center">
              <Wifi className="w-5 h-5 text-emerald-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-emerald-900">
                VPN Connected — {tunnel.profile}
              </p>
              <p className="text-xs text-emerald-600">
                Interface: {tunnel.interface}
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
    </div>
  );
}
