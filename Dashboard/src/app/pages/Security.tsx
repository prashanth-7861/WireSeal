import { useState, useEffect, useCallback } from "react";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX,
  RefreshCw, Lock, Server, AlertTriangle,
  CheckCircle, XCircle, Hammer, Cpu, Download, Wifi,
} from "lucide-react";
import { api, type SecurityStatus } from "../api";

export function Security() {
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [hardening, setHardening] = useState(false);
  const [hardenResult, setHardenResult] = useState<string[] | null>(null);
  const [lastScanned, setLastScanned] = useState<Date | null>(null);

  const fetchStatus = useCallback(async () => {
    setLoading(true);
    try {
      const s = await api.securityStatus();
      setStatus(s);
      setLastScanned(new Date());
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load security status");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const handleHarden = async () => {
    if (!confirm("Apply server hardening?\n\nThis will:\n- Harden SSH configuration\n- Set kernel security parameters\n- Install and configure fail2ban\n- Enable automatic security updates\n\nContinue?")) return;
    setHardening(true);
    setHardenResult(null);
    try {
      const res = await api.hardenServer();
      setHardenResult(res.actions);
      await fetchStatus();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Hardening failed");
    } finally {
      setHardening(false);
    }
  };

  const passedChecks = status?.checks.filter((c) => c.ok).length ?? 0;
  const totalChecks = status?.checks.length ?? 0;
  const scorePercent = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;

  const scoreColor =
    scorePercent >= 80 ? "text-green-600" :
    scorePercent >= 50 ? "text-yellow-600" : "text-red-600";
  const scoreBg =
    scorePercent >= 80 ? "bg-green-100" :
    scorePercent >= 50 ? "bg-yellow-100" : "bg-red-100";
  const scoreBorder =
    scorePercent >= 80 ? "border-green-200" :
    scorePercent >= 50 ? "border-yellow-200" : "border-red-200";
  const ScoreIcon =
    scorePercent >= 80 ? ShieldCheck :
    scorePercent >= 50 ? ShieldAlert : ShieldX;

  const scoreLabel =
    scorePercent >= 80 ? "Well Protected" :
    scorePercent >= 50 ? "Needs Attention" : "At Risk";

  // No checks means running on Windows or API returned empty
  const noChecksAvailable = status && status.checks.length === 0;

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Security</h1>
          <p className="text-gray-500 mt-1">Server hardening and defense status</p>
        </div>
        <div className="flex items-center gap-3">
          {lastScanned && (
            <span className="text-xs text-gray-400">
              Scanned {lastScanned.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={fetchStatus}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-gray-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleHarden}
            disabled={hardening}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60"
          >
            <Hammer className={`w-4 h-4 ${hardening ? "animate-bounce" : ""}`} />
            {hardening ? "Hardening..." : "Harden Server"}
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {hardenResult && (
        <div className="mb-6 bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle className="w-5 h-5 text-green-600" />
            <p className="font-medium text-green-800">Server hardening applied</p>
          </div>
          {hardenResult.length > 0 ? (
            <ul className="text-green-700 text-sm space-y-1 list-disc list-inside ml-7">
              {hardenResult.map((a, i) => <li key={i}>{a}</li>)}
            </ul>
          ) : (
            <p className="text-green-700 text-sm ml-7">All hardening measures already in place.</p>
          )}
          <button
            onClick={() => setHardenResult(null)}
            className="text-green-500 hover:text-green-700 text-sm mt-2 ml-7"
          >
            Dismiss
          </button>
        </div>
      )}

      {loading && !status ? (
        <div className="text-center text-gray-500 py-12">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-3 text-gray-400" />
          Loading security status...
        </div>
      ) : noChecksAvailable ? (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12 text-center">
          <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-700 mb-2">Security Checks Unavailable</h2>
          <p className="text-gray-500 max-w-md mx-auto">
            Server hardening is available on Linux only. Deploy WireSeal on a Linux server
            to access firewall, fail2ban, SSH hardening, and kernel security features.
          </p>
        </div>
      ) : status && (
        <>
          {/* Score card */}
          <div className={`bg-white rounded-lg shadow-sm border ${scoreBorder} p-6 mb-6`}>
            <div className="flex items-center gap-6">
              <div className={`w-20 h-20 rounded-full flex items-center justify-center ${scoreBg}`}>
                <ScoreIcon className={`w-10 h-10 ${scoreColor}`} />
              </div>
              <div>
                <p className="text-sm text-gray-500 mb-1">Security Score</p>
                <p className={`text-4xl font-bold ${scoreColor}`}>{scorePercent}%</p>
                <p className="text-sm text-gray-500 mt-1">
                  {passedChecks}/{totalChecks} checks passed — <span className={`font-medium ${scoreColor}`}>{scoreLabel}</span>
                </p>
              </div>
              <div className="ml-auto flex flex-col gap-2">
                {status.fail2ban_active && status.fail2ban_bans > 0 && (
                  <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3">
                    <p className="text-sm text-red-600 font-medium">
                      {status.fail2ban_bans} IP{status.fail2ban_bans > 1 ? "s" : ""} currently banned
                    </p>
                    <p className="text-xs text-red-500">by fail2ban</p>
                  </div>
                )}
                {!status.ip_forwarding && (
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg px-4 py-2">
                    <p className="text-xs text-yellow-700 font-medium">IP forwarding is off</p>
                    <p className="text-xs text-yellow-600">VPN clients cannot reach the internet</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Defense status cards — 2x2 grid */}
          <div className="grid grid-cols-2 gap-4 mb-6">
            {/* Firewall */}
            <DefenseCard
              icon={Shield}
              title="Firewall"
              active={status.firewall_active}
              activeLabel="Active"
              inactiveLabel="Inactive"
              activeDesc="nftables deny-by-default + rate limiting"
              inactiveDesc="No firewall protection"
              inactiveColor="red"
            />

            {/* Fail2ban */}
            <DefenseCard
              icon={Lock}
              title="Fail2ban"
              active={status.fail2ban_active}
              activeLabel="Active"
              inactiveLabel="Not Installed"
              activeDesc={`Brute force protection — ${status.fail2ban_bans} banned`}
              inactiveDesc="Click Harden Server to install"
            />

            {/* SSH */}
            <DefenseCard
              icon={Server}
              title="SSH Hardened"
              active={status.ssh_hardened}
              activeLabel="Secured"
              inactiveLabel="Default Config"
              activeDesc="Root login disabled, auth limited"
              inactiveDesc="Click Harden Server to secure"
            />

            {/* Kernel */}
            <DefenseCard
              icon={Cpu}
              title="Kernel Hardened"
              active={status.kernel_hardened}
              activeLabel="Secured"
              inactiveLabel="Default"
              activeDesc="Anti-spoofing, SYN flood, ICMP protection"
              inactiveDesc="Click Harden Server to apply"
            />
          </div>

          {/* Additional indicators row */}
          <div className="grid grid-cols-2 gap-4 mb-6">
            <DefenseCard
              icon={Wifi}
              title="IP Forwarding"
              active={status.ip_forwarding}
              activeLabel="Enabled"
              inactiveLabel="Disabled"
              activeDesc="VPN traffic can reach the internet"
              inactiveDesc="VPN clients will have no internet"
              inactiveColor="red"
            />
            <DefenseCard
              icon={Download}
              title="Auto Updates"
              active={status.auto_updates}
              activeLabel="Enabled"
              inactiveLabel="Not Configured"
              activeDesc="Security patches applied automatically"
              inactiveDesc="Click Harden Server to enable"
            />
          </div>

          {/* Security checks grid */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden mb-6">
            <div className="p-4 border-b border-gray-200">
              <h2 className="font-semibold text-gray-900">Security Checks</h2>
              <p className="text-sm text-gray-500 mt-0.5">Individual hardening checks</p>
            </div>
            <div className="grid grid-cols-2 divide-x divide-gray-100">
              {status.checks.map((check, i) => (
                <div
                  key={i}
                  className={`flex items-center gap-3 px-5 py-3.5 ${
                    i < status.checks.length - (status.checks.length % 2 === 0 ? 2 : 1) ? "border-b border-gray-100" : ""
                  }`}
                >
                  {check.ok
                    ? <CheckCircle className="w-4.5 h-4.5 text-green-500 flex-shrink-0" />
                    : <XCircle className="w-4.5 h-4.5 text-red-500 flex-shrink-0" />}
                  <div className="min-w-0">
                    <p className={`text-sm font-medium ${check.ok ? "text-gray-900" : "text-red-700"}`}>
                      {check.name}
                    </p>
                    {!check.ok && check.fix && (
                      <p className="text-xs text-red-500 mt-0.5 truncate">{check.fix}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Open ports */}
          {status.open_ports.length > 0 && (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <div className="p-4 border-b border-gray-200">
                <h2 className="font-semibold text-gray-900">Listening Ports</h2>
                <p className="text-sm text-gray-500 mt-0.5">
                  {status.open_ports.length} service{status.open_ports.length > 1 ? "s" : ""} exposed on this server
                </p>
              </div>
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Port</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Protocol</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Service</th>
                    <th className="text-left px-6 py-3 text-sm font-medium text-gray-700">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {status.open_ports.map((p, i) => {
                    const known: Record<number, { name: string; expected: boolean }> = {
                      22: { name: "SSH", expected: true },
                      80: { name: "HTTP", expected: false },
                      443: { name: "HTTPS", expected: false },
                      51820: { name: "WireGuard", expected: true },
                      8080: { name: "WireSeal API", expected: true },
                      53: { name: "DNS", expected: false },
                      5353: { name: "mDNS", expected: false },
                    };
                    const info = known[p.port];
                    const serviceName = info?.name ?? p.process ?? "Unknown";
                    const isExpected = info?.expected ?? false;
                    return (
                      <tr key={i} className="hover:bg-gray-50">
                        <td className="px-6 py-3 font-mono text-sm text-gray-900">{p.port}</td>
                        <td className="px-6 py-3 text-sm text-gray-500 uppercase">{p.proto}</td>
                        <td className="px-6 py-3 text-sm text-gray-700">{serviceName}</td>
                        <td className="px-6 py-3">
                          {isExpected ? (
                            <span className="inline-flex items-center gap-1 text-xs text-green-700 bg-green-50 px-2 py-0.5 rounded-full">
                              <CheckCircle className="w-3 h-3" /> Expected
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-yellow-700 bg-yellow-50 px-2 py-0.5 rounded-full">
                              <AlertTriangle className="w-3 h-3" /> Review
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/** Reusable defense status card */
function DefenseCard({
  icon: Icon, title, active, activeLabel, inactiveLabel,
  activeDesc, inactiveDesc, inactiveColor = "yellow",
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  active: boolean;
  activeLabel: string;
  inactiveLabel: string;
  activeDesc: string;
  inactiveDesc: string;
  inactiveColor?: "yellow" | "red";
}) {
  const inactiveBorder = inactiveColor === "red" ? "border-red-200" : "border-yellow-200";
  const inactiveBg = inactiveColor === "red" ? "bg-red-100" : "bg-yellow-100";
  const inactiveIcon = inactiveColor === "red" ? "text-red-500" : "text-yellow-600";
  const inactiveText = inactiveColor === "red" ? "text-red-500" : "text-yellow-600";

  return (
    <div className={`bg-white rounded-lg shadow-sm border p-5 ${active ? "border-green-200" : inactiveBorder}`}>
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${active ? "bg-green-100" : inactiveBg}`}>
          <Icon className={`w-5 h-5 ${active ? "text-green-600" : inactiveIcon}`} />
        </div>
        <h3 className="font-medium text-gray-900">{title}</h3>
      </div>
      <p className={`text-lg font-semibold ${active ? "text-green-600" : inactiveText}`}>
        {active ? activeLabel : inactiveLabel}
      </p>
      <p className="text-xs text-gray-500 mt-1">
        {active ? activeDesc : inactiveDesc}
      </p>
    </div>
  );
}
