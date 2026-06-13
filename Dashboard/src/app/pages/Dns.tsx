import { useState, useEffect } from "react";
import { Globe, Plus, Trash2, AlertTriangle } from "lucide-react";
import { api } from "../api";

// Module-level cache — survives navigation, avoids blank loading flash
let _dnsCache: {
  mappings: Record<string, string>;
  dnsmasqAvailable: boolean;
  dnsmasqRunning: boolean;
  platform: string;
} | null = null;

// Hostname: letters/digits/hyphen labels, dot-separated. IPv4: 4 octets 0-255.
const HOSTNAME_RE = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$/;
const IPV4_RE = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/;

export function Dns() {
  const [mappings, setMappings] = useState<Record<string, string>>(_dnsCache?.mappings ?? {});
  const [dnsmasqAvailable, setDnsmasqAvailable] = useState(_dnsCache?.dnsmasqAvailable ?? false);
  const [dnsmasqRunning, setDnsmasqRunning] = useState(_dnsCache?.dnsmasqRunning ?? false);
  const [platform, setPlatform] = useState(_dnsCache?.platform ?? "");
  const [newHostname, setNewHostname] = useState("");
  const [newIp, setNewIp] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const isWindows = platform === "win32";

  const fetchDns = async () => {
    try {
      const res = await api.getDns();
      _dnsCache = {
        mappings: res.mappings,
        dnsmasqAvailable: res.dnsmasq_available,
        dnsmasqRunning: res.dnsmasq_running,
        platform: res.platform ?? "",
      };
      setMappings(res.mappings);
      setDnsmasqAvailable(res.dnsmasq_available);
      setDnsmasqRunning(res.dnsmasq_running);
      setPlatform(res.platform ?? "");
    } catch {
      // Vault may be locked — silently skip
    }
  };

  useEffect(() => {
    fetchDns();
  }, []);

  const handleAdd = async () => {
    setError("");
    setSuccess("");
    const hostname = newHostname.trim();
    const ip = newIp.trim();
    if (!hostname || !ip) {
      setError("Both hostname and IP address are required.");
      return;
    }
    if (!HOSTNAME_RE.test(hostname)) {
      setError("Invalid hostname. Use letters, digits, hyphens and dots (e.g. plex.home).");
      return;
    }
    if (!IPV4_RE.test(ip)) {
      setError("Invalid IPv4 address (e.g. 10.0.0.10).");
      return;
    }
    try {
      await api.addDnsMapping(hostname, ip);
      setNewHostname("");
      setNewIp("");
      setSuccess(`Added ${hostname} → ${ip}`);
      fetchDns();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to add mapping.");
    }
  };

  const handleRemove = async (hostname: string) => {
    setError("");
    setSuccess("");
    try {
      await api.removeDnsMapping(hostname);
      setSuccess(`Removed ${hostname}`);
      fetchDns();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to remove mapping.");
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleAdd();
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center gap-3 mb-2">
        <Globe className="w-7 h-7 text-blue-600" />
        <h1 className="text-3xl font-semibold text-gray-900">Split DNS</h1>
        {isWindows ? (
          <span className="text-xs px-2.5 py-1 rounded-full bg-blue-100 text-blue-700">Windows mode</span>
        ) : dnsmasqRunning ? (
          <span className="text-xs px-2.5 py-1 rounded-full bg-green-100 text-green-700">● dnsmasq running</span>
        ) : dnsmasqAvailable ? (
          <span className="text-xs px-2.5 py-1 rounded-full bg-amber-100 text-amber-700">○ dnsmasq installed, stopped</span>
        ) : (
          <span className="text-xs px-2.5 py-1 rounded-full bg-gray-100 text-gray-500">dnsmasq not installed</span>
        )}
      </div>
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6 text-sm text-blue-900 space-y-1.5">
        <p className="font-medium">How this is used</p>
        <p className="text-blue-800">
          Map a friendly name to an internal IP — e.g. <code className="px-1 bg-blue-100 rounded">plex.home → 10.0.0.10</code>.
          VPN clients can then reach <code className="px-1 bg-blue-100 rounded">http://plex.home</code> instead of
          memorising IPs. These names resolve <strong>only over the WireGuard tunnel</strong>; they are never exposed publicly.
          On Linux/macOS dnsmasq applies changes immediately; on Windows they ride the WireGuard <code className="px-1 bg-blue-100 rounded">DNS</code> directive.
        </p>
      </div>

      {isWindows ? (
        <div className="mb-6 bg-blue-50 border border-blue-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-blue-600 flex-shrink-0" />
          <p className="text-blue-800 text-sm">
            <strong>Windows server mode</strong> — dnsmasq is not available on Windows.
            Mappings are saved to the vault and pushed to clients through WireGuard's
            <code className="mx-1 px-1 bg-blue-100 rounded">DNS</code> directive. For a
            dedicated split-DNS resolver, run the server on Linux or macOS.
          </p>
        </div>
      ) : !dnsmasqAvailable && (
        <div className="mb-6 bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0" />
          <p className="text-amber-800 text-sm">
            <strong>dnsmasq not found</strong> — DNS mappings are saved to the vault but are not
            active. Install dnsmasq to enable internal hostname resolution.
          </p>
        </div>
      )}

      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-red-800 text-sm">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 bg-green-50 border border-green-200 rounded-lg px-4 py-3 text-green-800 text-sm">
          {success}
        </div>
      )}

      {/* Add form */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Add Mapping</h2>
        <div className="flex gap-3">
          <input
            value={newHostname}
            onChange={e => setNewHostname(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="plex.home"
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <input
            value={newIp}
            onChange={e => setNewIp(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="10.0.0.10"
            className="w-36 px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            onClick={handleAdd}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2 text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
      </div>

      {/* Mappings table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Hostname</th>
              <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">IP Address</th>
              <th className="text-right px-6 py-3 text-sm font-medium text-gray-700">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {Object.entries(mappings).map(([host, ip]) => (
              <tr key={host} className="hover:bg-gray-50">
                <td className="px-6 py-4 font-mono text-sm text-gray-900">{host}</td>
                <td className="px-6 py-4 font-mono text-sm text-gray-700">{ip}</td>
                <td className="px-6 py-4 text-right">
                  <button
                    onClick={() => handleRemove(host)}
                    className="text-red-600 hover:text-red-700 p-2 rounded-lg hover:bg-red-50 transition-colors"
                    title={`Remove ${host}`}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
            {Object.keys(mappings).length === 0 && (
              <tr>
                <td colSpan={3} className="px-6 py-12 text-center text-gray-500 text-sm">
                  No DNS mappings yet. Add one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
