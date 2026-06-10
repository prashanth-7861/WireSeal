import { useState, useEffect, useCallback, useRef } from "react";
import {
  Wrench, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Wifi, Globe, Shield, Server,
  ChevronDown, ChevronRight, Loader2, Zap, ShieldCheck,
  Clock, Activity,
} from "lucide-react";
import { api, type Status, type SecurityStatus } from "../api";

// ── Types ──────────────────────────────────────────────────────────────────

type Severity = "pass" | "warn" | "fail" | "info";

interface CheckResult {
  id: string;
  label: string;
  severity: Severity;
  message: string;
  fix?: string;
  details?: string;
  /** If present, renders a "Fix" button. Must return a user-safe message. */
  action?: () => Promise<string>;
  actionLabel?: string;
  /** If true, show a confirmation dialog before running the action. */
  confirmRequired?: boolean;
  confirmMessage?: string;
}

interface CheckGroup {
  title: string;
  icon: typeof Server;
  checks: CheckResult[];
}

// ── Security: sanitize error messages ──────────────────────────────────────

/** Strip internal details from API errors before displaying to user. */
function sanitizeError(e: unknown): string {
  if (!(e instanceof Error)) return "Operation failed. Please try again.";
  const msg = e.message;
  // Strip file paths, stack traces, and internal details
  if (/traceback|\/home\/|\/root\/|C:\\|\/etc\/|line \d+/i.test(msg)) {
    return "Operation failed due to a server error.";
  }
  // Truncate long messages
  if (msg.length > 120) return msg.slice(0, 117) + "...";
  return msg;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function SeverityIcon({ severity }: { severity: Severity }) {
  switch (severity) {
    case "pass": return <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />;
    case "warn": return <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0" />;
    case "fail": return <XCircle className="w-4 h-4 text-red-500 flex-shrink-0" />;
    case "info": return <Activity className="w-4 h-4 text-blue-500 flex-shrink-0" />;
  }
}

function ConfirmDialog({ message, onConfirm, onCancel }: {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl border border-gray-200 p-6 max-w-sm w-full mx-4">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-semibold text-gray-900 mb-1">Confirm Action</h3>
            <p className="text-sm text-gray-600">{message}</p>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 text-sm text-white bg-orange-600 rounded-lg hover:bg-orange-700"
          >
            Proceed
          </button>
        </div>
      </div>
    </div>
  );
}

function FixButton({ action, label, confirmRequired, confirmMessage, onDone }: {
  action: () => Promise<string>;
  label: string;
  confirmRequired?: boolean;
  confirmMessage?: string;
  onDone: (msg: string, ok: boolean) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const cooldownRef = useRef(false);

  const execute = async () => {
    if (cooldownRef.current) return;
    cooldownRef.current = true;
    setBusy(true);
    try {
      const msg = await action();
      onDone(msg, true);
    } catch (e: unknown) {
      onDone(sanitizeError(e), false);
    } finally {
      setBusy(false);
      setTimeout(() => { cooldownRef.current = false; }, 2000);
    }
  };

  return (
    <>
      <button
        onClick={() => {
          if (busy || cooldownRef.current) return;
          if (confirmRequired) { setShowConfirm(true); return; }
          execute();
        }}
        disabled={busy}
        className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 text-xs font-medium transition-colors"
      >
        {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
        {busy ? "Applying..." : label}
      </button>
      {showConfirm && (
        <ConfirmDialog
          message={confirmMessage || `Are you sure you want to ${label.toLowerCase()}?`}
          onConfirm={() => { setShowConfirm(false); execute(); }}
          onCancel={() => setShowConfirm(false)}
        />
      )}
    </>
  );
}

// ── Check Runners ──────────────────────────────────────────────────────────

async function runApiCheck(): Promise<CheckResult> {
  try {
    await api.vaultInfo();
    return { id: "api", label: "API Server", severity: "pass", message: "API server is reachable and responding" };
  } catch {
    return {
      id: "api", label: "API Server", severity: "fail",
      message: "Cannot reach the WireSeal API server",
      fix: "The API server is not running or not reachable. Verify the server process is active.",
    };
  }
}

async function runVaultCheck(): Promise<CheckResult> {
  try {
    const info = await api.vaultInfo();
    if (!info.initialized) {
      return {
        id: "vault", label: "Vault", severity: "warn",
        message: "Vault not initialized",
        fix: "No server configuration exists yet. Go to the Setup page to initialize.",
      };
    }
    if (info.locked) {
      return {
        id: "vault", label: "Vault", severity: "info",
        message: "Vault is locked",
        fix: "Enter your passphrase on the lock screen to unlock and manage the VPN.",
      };
    }
    return { id: "vault", label: "Vault", severity: "pass", message: "Vault is unlocked and operational" };
  } catch {
    return { id: "vault", label: "Vault", severity: "fail", message: "Could not verify vault state" };
  }
}

async function runWireGuardCheck(): Promise<CheckResult> {
  try {
    const status: Status = await api.status();
    if (status.running) {
      const peerCount = status.peers?.length ?? 0;
      return {
        id: "wg", label: "WireGuard Tunnel", severity: "pass",
        message: `Tunnel active with ${peerCount} peer(s)`,
      };
    }
    return {
      id: "wg", label: "WireGuard Tunnel", severity: "warn",
      message: "WireGuard tunnel is not running",
      fix: "The VPN tunnel is down. Start it to accept incoming connections.",
      action: async () => {
        const res = await api.startServer();
        return res.note === "already running" ? "Tunnel was already running" : "Tunnel started successfully";
      },
      actionLabel: "Start Tunnel",
      confirmRequired: true,
      confirmMessage: "This will start the WireGuard VPN tunnel and begin accepting connections. Continue?",
    };
  } catch {
    return {
      id: "wg", label: "WireGuard Tunnel", severity: "fail",
      message: "Cannot determine tunnel status",
      fix: "Unlock the vault first, then verify WireGuard is installed on this system.",
    };
  }
}

async function runClientCheck(): Promise<CheckResult> {
  try {
    const clients = await api.listClients();
    if (!clients.clients || clients.clients.length === 0) {
      return {
        id: "clients", label: "VPN Clients", severity: "warn",
        message: "No VPN clients configured",
        fix: "Navigate to the Clients page to add your first device.",
      };
    }
    return {
      id: "clients", label: "VPN Clients", severity: "pass",
      message: `${clients.clients.length} client(s) configured`,
    };
  } catch {
    return { id: "clients", label: "VPN Clients", severity: "info", message: "Cannot retrieve client list" };
  }
}

async function runSecurityCheck(): Promise<CheckResult[]> {
  try {
    const sec: SecurityStatus = await api.securityStatus();
    const results: CheckResult[] = [];
    const passed = sec.checks.filter(c => c.ok).length;
    const total = sec.checks.length;

    if (total === 0) {
      results.push({
        id: "security-score", label: "Security Audit", severity: "info",
        message: "Security checks not available on this platform",
      });
    } else if (passed === total) {
      results.push({
        id: "security-score", label: "Security Audit", severity: "pass",
        message: `All ${total} security checks passed`,
      });
    } else {
      const failing = sec.checks.filter(c => !c.ok);
      results.push({
        id: "security-score", label: "Security Audit", severity: "warn",
        message: `${passed}/${total} security checks passed (${failing.length} issue${failing.length !== 1 ? "s" : ""})`,
        fix: "Server hardening will apply firewall rules, file permissions, and kernel parameters.",
        action: async () => {
          const res = await api.hardenServer();
          const count = res.actions?.length ?? 0;
          return `${count} hardening action${count !== 1 ? "s" : ""} applied successfully`;
        },
        actionLabel: "Harden Server",
        confirmRequired: true,
        confirmMessage: "This will modify firewall rules, file permissions, and system parameters to improve security. These changes are safe but may require a service restart. Continue?",
      });
      for (const c of failing.slice(0, 4)) {
        results.push({
          id: `security-${c.id}`, label: c.label, severity: "warn",
          message: c.detail || "Check did not pass",
          fix: c.fix || undefined,
        });
      }
    }
    return results;
  } catch {
    return [{
      id: "security", label: "Security Audit", severity: "info",
      message: "Cannot run security checks",
    }];
  }
}

async function runNetworkCheck(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  try {
    const net = await api.getNetworkDevices();
    results.push({
      id: "lan-subnet", label: "LAN Subnet", severity: "pass",
      message: `Detected: ${net.lan_subnet}`,
    });
    if (!net.scan_available) {
      results.push({
        id: "net-scan", label: "Network Scanner", severity: "info",
        message: "ARP scan unavailable — device discovery is limited to passive methods",
      });
    }
  } catch {
    results.push({
      id: "lan-subnet", label: "LAN Subnet", severity: "info",
      message: "Cannot detect LAN",
    });
  }

  try {
    const svc = await api.getNetworkServices();
    if (!svc.mdns_available) {
      results.push({
        id: "mdns", label: "Service Discovery (mDNS)", severity: "warn",
        message: "mDNS not available — LAN service browsing disabled",
        fix: "The zeroconf package is required for mDNS service discovery.",
      });
    } else {
      results.push({
        id: "mdns", label: "Service Discovery (mDNS)", severity: "pass",
        message: `${svc.services?.length ?? 0} service(s) discovered via mDNS`,
      });
    }
  } catch {
    // Silently skip — non-critical
  }

  return results;
}

async function runServiceCheck(): Promise<CheckResult> {
  try {
    const svc = await api.serviceStatus();
    if (svc.installed && svc.running) {
      return { id: "service", label: "Background Service", severity: "pass", message: "Installed and running" };
    }
    if (svc.installed) {
      return {
        id: "service", label: "Background Service", severity: "warn",
        message: "Service is installed but stopped",
        fix: "The background service ensures WireSeal starts automatically on boot.",
        action: async () => {
          await api.serviceStart();
          return "Service started successfully";
        },
        actionLabel: "Start Service",
        confirmRequired: true,
        confirmMessage: "Start the WireSeal background service? It will run on system boot.",
      };
    }
    return {
      id: "service", label: "Background Service", severity: "info",
      message: "Not installed (optional)",
      fix: "Installing the service enables auto-start on boot.",
      action: async () => {
        await api.serviceInstall({ autostart: true });
        return "Service installed with auto-start enabled";
      },
      actionLabel: "Install Service",
      confirmRequired: true,
      confirmMessage: "This will register WireSeal as a system service that starts automatically on boot. Continue?",
    };
  } catch {
    return { id: "service", label: "Background Service", severity: "info", message: "Cannot check service status" };
  }
}

async function runDnsCheck(): Promise<CheckResult> {
  try {
    const dns = await api.getDns();
    if (dns.dnsmasq_running) {
      const count = Object.keys(dns.mappings ?? {}).length;
      return { id: "dns", label: "DNS", severity: "pass", message: `dnsmasq running (${count} mapping${count !== 1 ? "s" : ""})` };
    }
    if (Object.keys(dns.mappings ?? {}).length > 0) {
      return { id: "dns", label: "DNS", severity: "warn", message: "Mappings configured but dnsmasq not running" };
    }
    return {
      id: "dns", label: "DNS", severity: "info",
      message: "Not configured (optional)",
      fix: "Configure DNS mappings if you want custom hostnames for VPN clients. Visit the DNS page.",
    };
  } catch {
    return { id: "dns", label: "Dynamic DNS", severity: "info", message: "Cannot check DNS configuration" };
  }
}

// ── Main Component ─────────────────────────────────────────────────────────

export function Troubleshoot() {
  const [groups, setGroups] = useState<CheckGroup[]>([]);
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState<Date | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [actionResults, setActionResults] = useState<Record<string, { msg: string; ok: boolean }>>({});
  const [confirmFixAll, setConfirmFixAll] = useState(false);

  const runAllChecks = useCallback(async () => {
    setRunning(true);
    setActionResults({});
    try {
      const [apiR, vaultR, wgR, clientR, secR, netR, svcR, dnsR] =
        await Promise.allSettled([
          runApiCheck(), runVaultCheck(), runWireGuardCheck(), runClientCheck(),
          runSecurityCheck(), runNetworkCheck(), runServiceCheck(), runDnsCheck(),
        ]);

      const v = <T,>(r: PromiseSettledResult<T>, fb: T): T =>
        r.status === "fulfilled" ? r.value : fb;

      setGroups([
        {
          title: "Core Services",
          icon: Server,
          checks: [
            v(apiR, { id: "api", label: "API Server", severity: "fail" as Severity, message: "Check failed" }),
            v(vaultR, { id: "vault", label: "Vault", severity: "fail" as Severity, message: "Check failed" }),
            v(wgR, { id: "wg", label: "WireGuard", severity: "fail" as Severity, message: "Check failed" }),
            v(svcR, { id: "service", label: "Service", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        {
          title: "VPN Configuration",
          icon: Wifi,
          checks: [
            v(clientR, { id: "clients", label: "Clients", severity: "fail" as Severity, message: "Check failed" }),
            v(dnsR, { id: "dns", label: "DNS", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        { title: "Network & Discovery", icon: Globe, checks: v(netR, []) },
        { title: "Security", icon: Shield, checks: v(secR, []) },
      ]);
      setLastRun(new Date());
    } finally {
      setRunning(false);
    }
  }, []);

  useEffect(() => { runAllChecks(); }, [runAllChecks]);

  const totalChecks = groups.reduce((s, g) => s + g.checks.length, 0);
  const passCount = groups.reduce((s, g) => s + g.checks.filter(c => c.severity === "pass").length, 0);
  const failCount = groups.reduce((s, g) => s + g.checks.filter(c => c.severity === "fail").length, 0);
  const warnCount = groups.reduce((s, g) => s + g.checks.filter(c => c.severity === "warn").length, 0);

  const overallColor = failCount > 0 ? "text-red-600" : warnCount > 0 ? "text-yellow-600" : "text-green-600";
  const overallBg = failCount > 0 ? "bg-red-50 border-red-200" : warnCount > 0 ? "bg-yellow-50 border-yellow-200" : "bg-green-50 border-green-200";
  const overallLabel = failCount > 0 ? "Issues Detected" : warnCount > 0 ? "Warnings" : "System Healthy";
  const OverallIcon = failCount > 0 ? XCircle : warnCount > 0 ? AlertTriangle : ShieldCheck;

  const fixableChecks = groups.flatMap(g => g.checks.filter(c => c.action && c.severity !== "pass"));

  const fixAll = async () => {
    setConfirmFixAll(false);
    for (const check of fixableChecks) {
      if (!check.action) continue;
      try {
        const msg = await check.action();
        setActionResults(prev => ({ ...prev, [check.id]: { msg, ok: true } }));
      } catch (e: unknown) {
        setActionResults(prev => ({ ...prev, [check.id]: { msg: sanitizeError(e), ok: false } }));
      }
    }
    setTimeout(runAllChecks, 2000);
  };

  return (
    <div className="max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-orange-100 rounded-xl flex items-center justify-center">
            <Wrench className="w-5 h-5 text-orange-600" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">System Diagnostics</h1>
            <p className="text-sm text-gray-500">Server health checks and remediation</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {fixableChecks.length > 0 && (
            <button
              onClick={() => setConfirmFixAll(true)}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm font-medium transition-colors"
            >
              <Zap className="w-4 h-4" />
              Fix All ({fixableChecks.length})
            </button>
          )}
          <button
            onClick={runAllChecks}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-900 disabled:opacity-50 text-sm font-medium transition-colors"
          >
            {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            {running ? "Scanning..." : "Re-scan"}
          </button>
        </div>
      </div>

      {/* Confirm Fix All dialog */}
      {confirmFixAll && (
        <ConfirmDialog
          message={`This will attempt to fix ${fixableChecks.length} issue(s): ${fixableChecks.map(c => c.actionLabel || c.label).join(", ")}. Each action will be applied sequentially. Continue?`}
          onConfirm={fixAll}
          onCancel={() => setConfirmFixAll(false)}
        />
      )}

      {/* Status banner */}
      {totalChecks > 0 && (
        <div className={`rounded-xl border p-5 mb-6 ${overallBg}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <OverallIcon className={`w-8 h-8 ${overallColor}`} />
              <div>
                <p className={`text-lg font-bold ${overallColor}`}>{overallLabel}</p>
                <p className="text-sm text-gray-600">
                  {passCount} passed, {warnCount} warning{warnCount !== 1 ? "s" : ""}, {failCount} failed
                </p>
              </div>
            </div>
            {lastRun && (
              <div className="flex items-center gap-1.5 text-xs text-gray-400">
                <Clock className="w-3.5 h-3.5" />
                {lastRun.toLocaleTimeString()}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Check groups */}
      {groups.map((group) => {
        const gFail = group.checks.filter(c => c.severity === "fail").length;
        const gWarn = group.checks.filter(c => c.severity === "warn").length;
        const gPass = group.checks.filter(c => c.severity === "pass").length;
        const GroupIcon = group.icon;

        return (
          <div key={group.title} className="bg-white rounded-xl border border-gray-200 mb-4 overflow-hidden shadow-sm">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <GroupIcon className="w-4 h-4 text-gray-400" />
                <h2 className="font-semibold text-gray-800 text-sm tracking-wide uppercase">{group.title}</h2>
              </div>
              <div className="flex items-center gap-1.5 text-xs">
                {gPass > 0 && <span className="px-2 py-0.5 bg-green-50 text-green-700 rounded-full">{gPass}</span>}
                {gWarn > 0 && <span className="px-2 py-0.5 bg-yellow-50 text-yellow-700 rounded-full">{gWarn}</span>}
                {gFail > 0 && <span className="px-2 py-0.5 bg-red-50 text-red-700 rounded-full">{gFail}</span>}
              </div>
            </div>

            <div className="divide-y divide-gray-50">
              {group.checks.map((check) => {
                const isExpanded = expanded[check.id] ?? (check.severity === "fail" || check.severity === "warn");
                const hasFix = check.fix || check.action || check.details;
                const result = actionResults[check.id];

                return (
                  <div key={check.id} className="px-5 py-3 hover:bg-gray-50/50 transition-colors">
                    <button
                      onClick={() => hasFix && setExpanded(prev => ({ ...prev, [check.id]: !isExpanded }))}
                      className={`flex items-center gap-3 w-full text-left ${hasFix ? "cursor-pointer" : "cursor-default"}`}
                    >
                      <SeverityIcon severity={check.severity} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900">{check.label}</p>
                        <p className="text-xs text-gray-500 truncate">{check.message}</p>
                      </div>
                      {check.action && check.severity !== "pass" && !result?.ok && (
                        <span className="px-2 py-0.5 bg-orange-50 text-orange-600 border border-orange-200 rounded text-xs font-medium">
                          Action Available
                        </span>
                      )}
                      {result?.ok && (
                        <span className="px-2 py-0.5 bg-green-50 text-green-600 border border-green-200 rounded text-xs font-medium">
                          Fixed
                        </span>
                      )}
                      {hasFix && (
                        isExpanded
                          ? <ChevronDown className="w-4 h-4 text-gray-300" />
                          : <ChevronRight className="w-4 h-4 text-gray-300" />
                      )}
                    </button>

                    {isExpanded && hasFix && (
                      <div className="mt-2 ml-7 p-4 bg-gray-50 rounded-lg text-sm space-y-3 border border-gray-100">
                        {check.fix && <p className="text-gray-700 leading-relaxed">{check.fix}</p>}
                        {check.details && <p className="text-gray-500 text-xs leading-relaxed">{check.details}</p>}

                        {check.action && check.severity !== "pass" && (
                          <div className="flex items-center gap-3 pt-1">
                            <FixButton
                              action={check.action}
                              label={check.actionLabel || "Apply Fix"}
                              confirmRequired={check.confirmRequired}
                              confirmMessage={check.confirmMessage}
                              onDone={(msg, ok) => {
                                setActionResults(prev => ({ ...prev, [check.id]: { msg, ok } }));
                                if (ok) setTimeout(runAllChecks, 2000);
                              }}
                            />
                            {result && (
                              <span className={`text-xs font-medium ${result.ok ? "text-green-600" : "text-red-600"}`}>
                                {result.msg}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
