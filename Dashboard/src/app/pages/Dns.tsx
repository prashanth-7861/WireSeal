import { useState, useEffect } from "react";
import { Globe, Plus, Trash2, AlertTriangle } from "lucide-react";
import { api } from "../api";

export function Dns() {
  const [mappings, setMappings] = useState<Record<string, string>>({});
  const [dnsmasqAvailable, setDnsmasqAvailable] = useState(false);
  const [newHostname, setNewHostname] = useState("");
  const [newIp, setNewIp] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const fetchDns = async () => {
    try {
      const res = await api.getDns();
      setMappings(res.mappings);
      setDnsmasqAvailable(res.dnsmasq_available);
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
      </div>
      <p className="text-gray-500 mb-6">
        Internal hostnames resolved for VPN clients only. Changes take effect immediately when dnsmasq is running.
      </p>

      {!dnsmasqAvailable && (
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
