import { useState, useEffect, useCallback, useRef } from "react";
import {
  Server, Play, Activity, Monitor, Clock, Wifi, WifiOff,
  Lock, Eye, EyeOff, AlertCircle, ShieldCheck, Users, CheckCircle,
} from "lucide-react";
import { api, VAULT_LOCKED_EVENT, type Status } from "../api";

type VaultState = "loading" | "uninitialized" | "locked" | "unlocked";

export function Dashboard() {
  const [vaultState, setVaultState] = useState<VaultState>("loading");
  const [status, setStatus] = useState<Status | null>(null);
  const [uptime, setUptime] = useState(0);
  const uptimeRef = useRef(0);

  // Passphrase dialog state
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [passphraseMode, setPassphraseMode] = useState<"setup" | "unlock">("unlock");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  // Post-init success state
  const [initResult, setInitResult] = useState<{
    server_ip: string; subnet: string; public_key: string; endpoint: string | null;
    warnings?: string[] | null;
  } | null>(null);

  // ── Vault info probe ─────────────────────────────────────────────────────
  const probeVault = useCallback(async () => {
    try {
      const info = await api.vaultInfo();
      if (!info.initialized) {
        setVaultState("uninitialized");
      } else if (info.locked) {
        setVaultState("locked");
      } else {
        setVaultState("unlocked");
      }
    } catch {
      // API server not reachable → treat as locked so user sees the start button
      setVaultState("locked");
    }
  }, []);

  useEffect(() => { probeVault(); }, [probeVault]);

  // If the backend vault gets locked (server restart, etc.) reset to locked state
  useEffect(() => {
    const handler = () => {
      setVaultState("locked");
      setStatus(null);
    };
    window.addEventListener(VAULT_LOCKED_EVENT, handler);
    return () => window.removeEventListener(VAULT_LOCKED_EVENT, handler);
  }, []);

  // ── Status polling (only when unlocked) ──────────────────────────────────
  const fetchStatus = useCallback(async () => {
    try {
      const s = await api.status();
      setStatus(s);
    } catch {
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    if (vaultState !== "unlocked") return;
    fetchStatus();
    const id = window.setInterval(fetchStatus, 5000);
    return () => clearInterval(id);
  }, [vaultState, fetchStatus]);

  // ── Uptime counter ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!status?.running) { uptimeRef.current = 0; setUptime(0); return; }
    const id = window.setInterval(() => {
      uptimeRef.current += 1;
      setUptime(uptimeRef.current);
    }, 1000);
    return () => clearInterval(id);
  }, [status?.running]);

  // ── Auth handlers ─────────────────────────────────────────────────────────
  const openStartDialog = () => {
    setPassphraseMode(vaultState === "uninitialized" ? "setup" : "unlock");
    setPassphrase("");
    setConfirmPassphrase("");
    setAuthError("");
    setShowPassphrase(true);
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");

    if (passphraseMode === "setup") {
      if (passphrase.length < 12) { setAuthError("Passphrase must be at least 12 characters"); return; }
      if (passphrase !== confirmPassphrase) { setAuthError("Passphrases do not match"); return; }
    }

    setAuthLoading(true);
    try {
      if (passphraseMode === "setup") {
        const result = await api.init(passphrase);
        setInitResult({
          server_ip: result.server_ip,
          subnet: result.subnet,
          public_key: result.public_key,
          endpoint: result.endpoint,
          warnings: result.warnings,
        });
      } else {
        await api.unlock(passphrase);
      }
      setShowPassphrase(false);
      setVaultState("unlocked");
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      // Always wipe passphrase from React state after the attempt
      setPassphrase("");
      setConfirmPassphrase("");
      setAuthLoading(false);
    }
  };

  // ── Helpers ───────────────────────────────────────────────────────────────
  const formatUptime = (s: number) => {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  };

  const connectedPeers = status?.peers.filter((p) => p.connected).length ?? 0;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Monitor and control your WireGuard server</p>
      </div>

      {/* ── Loading ─────────────────────────────────────────────────────── */}
      {vaultState === "loading" && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12 text-center text-gray-500">
          Connecting to WireSeal server…
        </div>
      )}

      {/* ── Locked / Uninitialized — "Start Server" card ────────────────── */}
      {(vaultState === "locked" || vaultState === "uninitialized") && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-10 flex flex-col items-center text-center gap-6">
          <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center">
            <Lock className="w-10 h-10 text-gray-400" />
          </div>
          <div>
            <h2 className="text-2xl font-semibold text-gray-900 mb-2">
              {vaultState === "uninitialized" ? "Initialize WireSeal" : "Server is offline"}
            </h2>
            <p className="text-gray-500 max-w-sm">
              {vaultState === "uninitialized"
                ? "Set up your vault passphrase to get started. Your keys and config will be encrypted at rest."
                : "Unlock the vault with your passphrase to start managing WireGuard."}
            </p>
          </div>
          <button
            onClick={openStartDialog}
            className="flex items-center gap-3 px-8 py-3 bg-blue-600 text-white text-lg font-medium rounded-xl hover:bg-blue-700 transition-colors shadow-sm"
          >
            <Play className="w-6 h-6" />
            {vaultState === "uninitialized" ? "Initialize & Start" : "Start Server"}
          </button>
        </div>
      )}

      {/* ── Unlocked — full dashboard ────────────────────────────────────── */}
      {vaultState === "unlocked" && (
        <>
          {/* Post-init success banner */}
          {initResult && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center flex-shrink-0">
                  <CheckCircle className="w-7 h-7 text-green-600" />
                </div>
                <div className="flex-1">
                  <h2 className="text-xl font-semibold text-green-900 mb-1">Server Initialized Successfully</h2>
                  <p className="text-green-700 text-sm mb-4">Your WireSeal vault has been created and the WireGuard tunnel is configured.</p>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <span className="text-green-600">Server IP:</span>{" "}
                      <span className="font-mono text-green-900">{initResult.server_ip}</span>
                    </div>
                    <div>
                      <span className="text-green-600">Subnet:</span>{" "}
                      <span className="font-mono text-green-900">{initResult.subnet}</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-green-600">Public Key:</span>{" "}
                      <span className="font-mono text-green-900 text-xs break-all">{initResult.public_key}</span>
                    </div>
                    {initResult.endpoint && (
                      <div className="col-span-2">
                        <span className="text-green-600">Endpoint:</span>{" "}
                        <span className="font-mono text-green-900">{initResult.endpoint}</span>
                      </div>
                    )}
                  </div>
                  {initResult.warnings && initResult.warnings.length > 0 && (
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 mt-3">
                      <p className="text-yellow-800 text-sm font-medium mb-1">Setup warnings:</p>
                      <ul className="text-yellow-700 text-xs space-y-1 list-disc list-inside">
                        {initResult.warnings.map((w, i) => <li key={i}>{w}</li>)}
                      </ul>
                      <p className="text-yellow-600 text-xs mt-2">
                        The vault was created successfully. Run WireSeal as Administrator to complete WireGuard setup.
                      </p>
                    </div>
                  )}
                  <p className="text-green-600 text-sm mt-4">Head to the <strong>Clients</strong> page to add your first VPN client.</p>
                </div>
                <button
                  onClick={() => setInitResult(null)}
                  className="text-green-400 hover:text-green-600 text-lg leading-none"
                  title="Dismiss"
                >&times;</button>
              </div>
            </div>
          )}

          {/* Server status card */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <div className={`w-16 h-16 rounded-full flex items-center justify-center ${
                  status?.running ? "bg-green-100" : "bg-gray-100"
                }`}>
                  <Server className={`w-8 h-8 ${status?.running ? "text-green-700" : "text-gray-400"}`} />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">Server Status</h2>
                  <div className="flex items-center gap-2 mt-1">
                    <div className={`w-2 h-2 rounded-full ${status?.running ? "bg-green-500" : "bg-gray-400"}`} />
                    <span className={`text-sm font-medium ${status?.running ? "text-green-700" : "text-gray-500"}`}>
                      {status === null ? "Fetching…" : status.running ? "Running" : "Stopped"}
                    </span>
                  </div>
                </div>
              </div>

              {status && (
                <div className="text-right text-sm text-gray-500 space-y-1">
                  <div>Interface: <span className="font-mono text-gray-700">{status.interface}</span></div>
                  {status.endpoint && (
                    <div>Endpoint: <span className="font-mono text-gray-700">{status.endpoint}:{status.port}</span></div>
                  )}
                  {status.server_ip && (
                    <div>Server IP: <span className="font-mono text-gray-700">{status.server_ip}</span></div>
                  )}
                </div>
              )}
            </div>

            {status?.running && (
              <div className="grid grid-cols-3 gap-4 pt-6 border-t border-gray-200">
                <div className="flex items-center gap-3">
                  <Clock className="w-5 h-5 text-gray-400" />
                  <div>
                    <p className="text-sm text-gray-500">Uptime</p>
                    <p className="text-lg font-semibold text-gray-900">{formatUptime(uptime)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Activity className="w-5 h-5 text-gray-400" />
                  <div>
                    <p className="text-sm text-gray-500">Connected Peers</p>
                    <p className="text-lg font-semibold text-gray-900">{connectedPeers}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Monitor className="w-5 h-5 text-gray-400" />
                  <div>
                    <p className="text-sm text-gray-500">Total Clients</p>
                    <p className="text-lg font-semibold text-gray-900">{status.total_clients}</p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Stats grid */}
          <div className="grid grid-cols-3 gap-6 mb-6">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Monitor className="w-5 h-5 text-blue-700" />
                </div>
                <h3 className="font-medium text-gray-900">Clients</h3>
              </div>
              <p className="text-3xl font-semibold text-gray-900">{status?.total_clients ?? "—"}</p>
              <p className="text-sm text-gray-500 mt-1">{connectedPeers} connected</p>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${status?.running ? "bg-green-100" : "bg-gray-100"}`}>
                  {status?.running
                    ? <Wifi className="w-5 h-5 text-green-700" />
                    : <WifiOff className="w-5 h-5 text-gray-500" />}
                </div>
                <h3 className="font-medium text-gray-900">Interface</h3>
              </div>
              <p className="text-3xl font-semibold text-gray-900">{status?.running ? "Up" : "Down"}</p>
              <p className="text-sm text-gray-500 mt-1">{status?.interface ?? "wg0"}</p>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
                  <Users className="w-5 h-5 text-purple-700" />
                </div>
                <h3 className="font-medium text-gray-900">Active Peers</h3>
              </div>
              <p className="text-3xl font-semibold text-gray-900">{connectedPeers}</p>
              <p className="text-sm text-gray-500 mt-1">Recent handshake</p>
            </div>
          </div>

          {/* Peers table */}
          {status?.peers && status.peers.length > 0 && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <div className="p-4 border-b border-gray-200">
                <h2 className="font-semibold text-gray-900">Live Peers</h2>
              </div>
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Client</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Allowed IPs</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Last Handshake</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Transfer ↓ / ↑</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {status.peers.map((peer, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="font-medium text-gray-900">{peer.name}</div>
                        <div className="text-xs text-gray-400 font-mono">{peer.public_key_short}</div>
                      </td>
                      <td className="px-6 py-4 text-sm font-mono text-gray-700">{peer.allowed_ips}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{peer.last_handshake}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{peer.transfer_rx} / {peer.transfer_tx}</td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                          peer.connected ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-600"
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${peer.connected ? "bg-green-500" : "bg-gray-400"}`} />
                          {peer.connected ? "Connected" : "Idle"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Empty state when running but no peers */}
          {status?.running && status.peers.length === 0 && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-10 text-center">
              <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
              <h3 className="font-medium text-gray-900 mb-1">WireGuard is running</h3>
              <p className="text-gray-500 text-sm">No peers connected yet. Add clients from the Clients page.</p>
            </div>
          )}

          {/* Guidance when vault is unlocked but WireGuard is not running */}
          {status !== null && !status.running && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-10 text-center">
              <Server className="w-12 h-12 text-gray-400 mx-auto mb-3" />
              <h3 className="font-medium text-gray-900 mb-1">Vault Unlocked</h3>
              <p className="text-gray-500 text-sm max-w-md mx-auto">
                The vault is unlocked and ready. The WireGuard tunnel service may still be starting up,
                or it may need to be started manually. Add clients from the Clients page to get started.
              </p>
            </div>
          )}
        </>
      )}

      {/* ── Start Server / Init dialog ───────────────────────────────────── */}
      {showPassphrase && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                <Lock className="w-6 h-6 text-blue-700" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-gray-900">
                  {passphraseMode === "setup" ? "Initialize Vault" : "Unlock Vault"}
                </h2>
                <p className="text-sm text-gray-500">
                  {passphraseMode === "setup"
                    ? "Create a passphrase to encrypt your vault"
                    : "Enter your passphrase to unlock and start"}
                </p>
              </div>
            </div>

            <form onSubmit={handleAuth} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Passphrase</label>
                <div className="relative">
                  <input
                    type={showPw ? "text" : "password"}
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder={passphraseMode === "setup" ? "Min. 12 characters" : "Enter your passphrase"}
                    autoFocus
                    disabled={authLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(!showPw)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showPw ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {passphraseMode === "setup" && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Confirm Passphrase</label>
                  <input
                    type={showPw ? "text" : "password"}
                    value={confirmPassphrase}
                    onChange={(e) => setConfirmPassphrase(e.target.value)}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="Confirm passphrase"
                    disabled={authLoading}
                  />
                </div>
              )}

              {authError && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{authError}</span>
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => { setShowPassphrase(false); setAuthError(""); setPassphrase(""); setConfirmPassphrase(""); }}
                  className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={authLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={authLoading}
                  className="flex-1 bg-blue-600 text-white px-4 py-2.5 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60 flex items-center justify-center gap-2"
                >
                  <Play className="w-4 h-4" />
                  {authLoading
                    ? (passphraseMode === "setup" ? "Initializing…" : "Starting…")
                    : (passphraseMode === "setup" ? "Initialize & Start" : "Start Server")}
                </button>
              </div>

              {passphraseMode === "setup" && (
                <p className="text-xs text-gray-400 text-center">
                  Your passphrase encrypts all vault data using dual-layer AEAD encryption. It cannot be recovered.
                </p>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
