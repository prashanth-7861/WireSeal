import { useState, useEffect, useCallback, useRef } from "react";
import {
  Server, Activity, Monitor, Clock, Wifi, WifiOff,
  ShieldCheck, Users,
} from "lucide-react";
import { api, type Status } from "../api";

export function Dashboard() {
  const [status, setStatus] = useState<Status | null>(null);
  const [uptime, setUptime] = useState(0);
  const uptimeRef = useRef(0);

  // ── Status polling ──────────────────────────────────────────────────────
  const fetchStatus = useCallback(async () => {
    try {
      const s = await api.status();
      setStatus(s);
    } catch {
      // 401 is handled globally by _fetch → VAULT_LOCKED_EVENT
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = window.setInterval(fetchStatus, 5000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  // ── Uptime counter ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!status?.running) { uptimeRef.current = 0; setUptime(0); return; }
    const id = window.setInterval(() => {
      uptimeRef.current += 1;
      setUptime(uptimeRef.current);
    }, 1000);
    return () => clearInterval(id);
  }, [status?.running]);

  // ── Helpers ───────────────────────────────────────────────────────────────
  const formatUptime = (s: number) => {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  };

  const connectedPeers = status?.peers.filter((p) => p.connected).length ?? 0;

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Monitor and control your WireGuard server</p>
      </div>

      {/* WireGuard tunnel status card */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center ${
              status?.running ? "bg-green-100" : "bg-gray-100"
            }`}>
              {status?.running
                ? <Wifi className="w-8 h-8 text-green-700" />
                : <WifiOff className="w-8 h-8 text-gray-400" />}
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900">WireGuard Tunnel</h2>
              <div className="flex items-center gap-2 mt-1">
                <div className={`w-2.5 h-2.5 rounded-full ${
                  status === null ? "bg-yellow-400 animate-pulse" : status.running ? "bg-green-500" : "bg-red-400"
                }`} />
                <span className={`text-sm font-medium ${
                  status === null ? "text-yellow-600" : status.running ? "text-green-700" : "text-red-500"
                }`}>
                  {status === null ? "Checking…" : status.running ? "Running" : "Not Running"}
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

      {/* Guidance when vault is unlocked but WireGuard tunnel is not running */}
      {status !== null && !status.running && (
        <div className="bg-amber-50 rounded-lg border border-amber-200 p-10 text-center">
          <WifiOff className="w-12 h-12 text-amber-400 mx-auto mb-3" />
          <h3 className="font-medium text-gray-900 mb-1">WireGuard Tunnel Not Active</h3>
          <p className="text-gray-500 text-sm max-w-md mx-auto">
            The API server is online and the vault is unlocked. The WireGuard tunnel is not running —
            it may need to be started manually or requires administrator privileges.
            Add clients from the Clients page to get started.
          </p>
        </div>
      )}
    </div>
  );
}
