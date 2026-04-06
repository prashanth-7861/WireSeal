import { useState, useEffect, useCallback, useRef } from "react";
import {
  Server, Activity, Monitor, Clock, Wifi, WifiOff,
  ShieldCheck, Users, PowerOff, Play, RefreshCw,
  ArrowDownCircle, ArrowUpCircle, Globe, Zap,
} from "lucide-react";
import { api, type Status } from "../api";

// Module-level — survives navigation between pages
let _statusCache: Status | null = null;
// Snapshot of server uptime at the moment we last fetched it, plus when we fetched it
let _uptimeSnap: { uptime_seconds: number; fetchedAt: number } | null = null;

function _computeUptime(): number {
  if (!_uptimeSnap) return 0;
  return _uptimeSnap.uptime_seconds + Math.floor((Date.now() - _uptimeSnap.fetchedAt) / 1000);
}

export function Dashboard() {
  const [status, setStatus] = useState<Status | null>(_statusCache);
  const initialUptime = _computeUptime();
  const [uptime, setUptime] = useState(initialUptime);
  const uptimeRef = useRef(initialUptime);
  const [stopping, setStopping] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  // ── Status polling ──────────────────────────────────────────────────────
  const fetchStatus = useCallback(async () => {
    try {
      const s = await api.status();
      _statusCache = s;
      setStatus(s);
      setError("");
    } catch {
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = window.setInterval(fetchStatus, 3000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  // ── Uptime counter ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!status?.running) {
      _uptimeSnap = null;
      uptimeRef.current = 0;
      setUptime(0);
      return;
    }

    const startTicking = () => {
      return window.setInterval(() => {
        const v = _computeUptime();
        uptimeRef.current = v;
        setUptime(v);
      }, 1000);
    };

    if (_uptimeSnap) {
      // Already have a snapshot — resume counting immediately, no flash
      const id = startTicking();
      return () => clearInterval(id);
    }

    // First time running: fetch real uptime from server, then tick
    let id: number;
    api.health().then((h) => {
      _uptimeSnap = { uptime_seconds: h.uptime_seconds, fetchedAt: Date.now() };
      const v = _computeUptime();
      uptimeRef.current = v;
      setUptime(v);
    }).catch(() => {
      // Fallback: start counting from 0 if health unavailable
      _uptimeSnap = { uptime_seconds: 0, fetchedAt: Date.now() };
    }).finally(() => {
      id = startTicking();
    });
    return () => clearInterval(id);
  }, [status?.running]);

  // ── Helpers ───────────────────────────────────────────────────────────────
  const formatUptime = (s: number) => {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  };

  const formatBytes = (b: string) => {
    if (!b || b === "0 B") return "0 B";
    return b;
  };

  const formatHandshakeAge = (secs: number): string => {
    if (secs < 0) return "never";
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) {
      const m = Math.floor(secs / 60);
      const s = secs % 60;
      return s > 0 ? `${m}m ${s}s ago` : `${m}m ago`;
    }
    if (secs < 86400) {
      const h = Math.floor(secs / 3600);
      const m = Math.floor((secs % 3600) / 60);
      return m > 0 ? `${h}h ${m}m ago` : `${h}h ago`;
    }
    const d = Math.floor(secs / 86400);
    return `${d}d ago`;
  };

  const handshakeBadgeClass = (secs: number): string => {
    if (secs >= 0 && secs < 180)   return "bg-green-100 text-green-700";
    if (secs >= 180 && secs < 600) return "bg-yellow-100 text-yellow-700";
    return "bg-gray-100 text-gray-600";
  };

  const handshakeDotClass = (secs: number): string => {
    if (secs >= 0 && secs < 180)   return "bg-green-500 animate-pulse";
    if (secs >= 180 && secs < 600) return "bg-yellow-500";
    return "bg-gray-400";
  };

  const handshakeBadgeLabel = (secs: number): string => {
    if (secs >= 0 && secs < 180)   return "Connected";
    if (secs >= 180 && secs < 600) return "Recent";
    return "Idle";
  };

  const connectedPeers =
    status?.peers.filter(
      (p) => p.last_handshake_seconds >= 0 && p.last_handshake_seconds < 180
    ).length ?? 0;

  // ── Start server ─────────────────────────────────────────────────────────
  const handleStart = async () => {
    setStarting(true);
    setError("");
    try {
      await api.startServer();
      // Poll quickly to get updated status
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        await fetchStatus();
        if (status?.running) break;
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start server");
    } finally {
      setStarting(false);
    }
  };

  // ── Stop server ─────────────────────────────────────────────────────────
  const handleStop = async () => {
    if (!confirm("Stop the WireGuard tunnel? Connected clients will be disconnected.")) return;
    setStopping(true);
    setError("");
    try {
      await api.terminate();
      await fetchStatus();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to stop server");
    } finally {
      setStopping(false);
    }
  };

  // ── Render ──────────────────────────────────────────────────────────────
  const isRunning = status?.running ?? false;
  const isLoading = status === null;

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Monitor and control your WireGuard server</p>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">{error}</span>
          <button onClick={() => setError("")} className="text-red-400 hover:text-red-600 text-lg">&times;</button>
        </div>
      )}

      {/* ── Server status card ──────────────────────────────────────────── */}
      <div className={`rounded-lg shadow-sm border p-6 mb-6 transition-colors ${
        isRunning ? "bg-white border-green-200" : "bg-white border-gray-200"
      }`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center transition-colors ${
              isRunning ? "bg-green-100" : isLoading ? "bg-yellow-50" : "bg-red-50"
            }`}>
              {isRunning
                ? <Wifi className="w-8 h-8 text-green-600" />
                : isLoading
                  ? <RefreshCw className="w-8 h-8 text-yellow-500 animate-spin" />
                  : <WifiOff className="w-8 h-8 text-red-400" />}
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900">WireGuard Tunnel</h2>
              <div className="flex items-center gap-2 mt-1">
                <div className={`w-2.5 h-2.5 rounded-full transition-colors ${
                  isLoading ? "bg-yellow-400 animate-pulse" : isRunning ? "bg-green-500" : "bg-red-400"
                }`} />
                <span className={`text-sm font-medium ${
                  isLoading ? "text-yellow-600" : isRunning ? "text-green-700" : "text-red-500"
                }`}>
                  {isLoading ? "Checking…" : isRunning ? "Running" : "Stopped"}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {status && (
              <div className="text-right text-sm text-gray-500 space-y-1 mr-2">
                <div>Interface: <span className="font-mono text-gray-700">{status.interface}</span></div>
                {(status.endpoint || status.server_ip) && (
                  <div>
                    Public IP:{" "}
                    <span className="font-mono text-gray-700">
                      {status.endpoint || status.server_ip}:{status.port}
                    </span>
                  </div>
                )}
                {status.endpoint && status.server_ip && (
                  <div>
                    VPN IP:{" "}
                    <span className="font-mono text-gray-500">{status.server_ip}</span>
                  </div>
                )}
              </div>
            )}

            {/* Start / Stop button */}
            {status && isRunning && (
              <button
                onClick={handleStop}
                disabled={stopping}
                className="flex items-center gap-2 px-5 py-2.5 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700 transition-colors disabled:opacity-60 shadow-sm"
              >
                <PowerOff className="w-4 h-4" />
                {stopping ? "Stopping…" : "Stop Server"}
              </button>
            )}
            {status && !isRunning && (
              <button
                onClick={handleStart}
                disabled={starting}
                className="flex items-center gap-2 px-5 py-2.5 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 transition-colors disabled:opacity-60 shadow-sm"
              >
                <Play className="w-4 h-4" />
                {starting ? "Starting…" : "Start Server"}
              </button>
            )}
          </div>
        </div>

        {/* Service status indicators */}
        <div className="grid grid-cols-2 gap-3 pt-4 border-t border-gray-100">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-green-500" : "bg-red-400"}`} />
            <span className="text-sm text-gray-600">WireGuard Tunnel</span>
            <span className={`text-xs font-medium ml-auto ${isRunning ? "text-green-600" : "text-red-500"}`}>
              {isRunning ? "Online" : "Offline"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-sm text-gray-600">API Server</span>
            <span className="text-xs font-medium ml-auto text-green-600">
              {status ? "Online" : "Checking…"}
            </span>
          </div>
        </div>

        {/* Running stats row */}
        {isRunning && (
          <div className="grid grid-cols-4 gap-4 pt-4 mt-4 border-t border-gray-100">
            <div className="flex items-center gap-3">
              <Clock className="w-5 h-5 text-blue-400" />
              <div>
                <p className="text-xs text-gray-500">Uptime</p>
                <p className="text-base font-semibold text-gray-900 font-mono">{formatUptime(uptime)}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Users className="w-5 h-5 text-purple-400" />
              <div>
                <p className="text-xs text-gray-500">Peers</p>
                <p className="text-base font-semibold text-gray-900">{connectedPeers} / {status!.total_clients}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Globe className="w-5 h-5 text-cyan-400" />
              <div>
                <p className="text-xs text-gray-500">Port</p>
                <p className="text-base font-semibold text-gray-900">{status!.port}/UDP</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Zap className="w-5 h-5 text-amber-400" />
              <div>
                <p className="text-xs text-gray-500">Interface</p>
                <p className="text-base font-semibold text-gray-900">{status!.interface}</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Stats cards ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-6 mb-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
              <Monitor className="w-5 h-5 text-blue-700" />
            </div>
            <h3 className="font-medium text-gray-900">Total Clients</h3>
          </div>
          <p className="text-3xl font-semibold text-gray-900">{status?.total_clients ?? "—"}</p>
          <p className="text-sm text-gray-500 mt-1">Registered in vault</p>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              connectedPeers > 0 ? "bg-green-100" : "bg-gray-100"
            }`}>
              <Activity className={`w-5 h-5 ${connectedPeers > 0 ? "text-green-700" : "text-gray-500"}`} />
            </div>
            <h3 className="font-medium text-gray-900">Connected Now</h3>
          </div>
          <p className="text-3xl font-semibold text-gray-900">{connectedPeers}</p>
          <p className="text-sm text-gray-500 mt-1">Active handshakes</p>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              isRunning ? "bg-green-100" : "bg-red-50"
            }`}>
              {isRunning
                ? <ShieldCheck className="w-5 h-5 text-green-700" />
                : <WifiOff className="w-5 h-5 text-red-400" />}
            </div>
            <h3 className="font-medium text-gray-900">Server Status</h3>
          </div>
          <p className={`text-3xl font-semibold ${isRunning ? "text-green-600" : "text-red-500"}`}>
            {isRunning ? "Online" : "Offline"}
          </p>
          <p className="text-sm text-gray-500 mt-1">{isRunning ? "All systems operational" : "Tunnel is down"}</p>
        </div>
      </div>

      {/* ── Peers table ────────────────────────────────────────────────── */}
      {status?.peers && status.peers.length > 0 && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="font-semibold text-gray-900">Live Peers</h2>
            <span className="text-xs text-gray-400">Auto-refreshes every 3s</span>
          </div>
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Client</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">IP</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Last Handshake</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">
                  <span className="flex items-center gap-1">
                    <ArrowDownCircle className="w-3.5 h-3.5 text-green-500" />
                    Rx
                    <span className="mx-1 text-gray-300">/</span>
                    <ArrowUpCircle className="w-3.5 h-3.5 text-blue-500" />
                    Tx
                  </span>
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {status.peers.map((peer, i) => (
                <tr key={i} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="font-medium text-gray-900">{peer.name}</div>
                    <div className="text-xs text-gray-400 font-mono">{peer.public_key_short}</div>
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-700">{peer.allowed_ips}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{peer.last_handshake}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    <span className="text-green-600">{formatBytes(peer.transfer_rx)}</span>
                    <span className="mx-1 text-gray-300">/</span>
                    <span className="text-blue-600">{formatBytes(peer.transfer_tx)}</span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-col gap-0.5 items-start">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                        handshakeBadgeClass(peer.last_handshake_seconds)
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          handshakeDotClass(peer.last_handshake_seconds)
                        }`} />
                        {handshakeBadgeLabel(peer.last_handshake_seconds)}
                      </span>
                      <span className="text-xs text-gray-400 pl-1">
                        {formatHandshakeAge(peer.last_handshake_seconds)}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty state — running, no peers */}
      {isRunning && status?.peers.length === 0 && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-10 text-center">
          <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
          <h3 className="font-medium text-gray-900 mb-1">WireGuard is running</h3>
          <p className="text-gray-500 text-sm">No peers connected yet. Add clients from the Clients page.</p>
        </div>
      )}

      {/* Empty state — stopped */}
      {status !== null && !isRunning && (
        <div className="bg-red-50 rounded-lg border border-red-200 p-10 text-center">
          <WifiOff className="w-12 h-12 text-red-300 mx-auto mb-3" />
          <h3 className="font-medium text-gray-900 mb-2">WireGuard Tunnel Stopped</h3>
          <p className="text-gray-500 text-sm max-w-md mx-auto mb-4">
            The API server is online but the WireGuard tunnel is not running.
            Connected clients are disconnected.
          </p>
          <button
            onClick={handleStart}
            disabled={starting}
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 transition-colors disabled:opacity-60 shadow-sm"
          >
            <Play className="w-4 h-4" />
            {starting ? "Starting…" : "Start Server"}
          </button>
        </div>
      )}
    </div>
  );
}
