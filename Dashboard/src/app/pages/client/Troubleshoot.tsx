import { useState, useEffect, useCallback, useRef } from "react";
import {
  Wrench, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Wifi, Globe, Terminal, ChevronDown,
  ChevronRight, Loader2, Key, Zap, ShieldCheck,
  Clock, Activity,
} from "lucide-react";
import { api } from "../../api";

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
  icon: typeof Wifi;
  checks: CheckResult[];
}

// ── Security: sanitize error messages ──────────────────────────────────────

/** Strip internal details from API errors before displaying to user. */
function sanitizeError(e: unknown): string {
  if (!(e instanceof Error)) return "Operation failed. Please try again.";
  const msg = e.message;
  if (/traceback|\/home\/|\/root\/|C:\\|\/etc\/|line \d+/i.test(msg)) {
    return "Operation failed due to a server error.";
  }
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

async function checkApiServer(): Promise<CheckResult> {
  try {
    await api.vaultInfo();
    return { id: "api", label: "API Server", severity: "pass", message: "Connected to WireSeal server" };
  } catch {
    return {
      id: "api", label: "API Server", severity: "fail",
      message: "Cannot reach the WireSeal API server",
      fix: "Make sure the server is running and you are on the correct network.",
    };
  }
}

async function checkVaultUnlocked(): Promise<CheckResult> {
  try {
    const info = await api.vaultInfo();
    if (info.initialized && !info.locked) {
      return { id: "vault", label: "Vault Access", severity: "pass", message: "Vault is unlocked — configs available" };
    }
    if (info.initialized && info.locked) {
      return {
        id: "vault", label: "Vault Access", severity: "warn",
        message: "Vault is locked — unlock to access VPN configs",
        fix: "Enter your passphrase on the lock screen to unlock.",
      };
    }
    return {
      id: "vault", label: "Vault Access", severity: "fail",
      message: "Vault not initialized — server needs setup first",
      fix: "Ask the server admin to run initial setup.",
    };
  } catch {
    return { id: "vault", label: "Vault Access", severity: "fail", message: "Cannot check vault" };
  }
}

async function checkTunnelStatus(): Promise<CheckResult> {
  try {
    const tunnel = await api.clientTunnelStatus();
    if (tunnel.connected) {
      return {
        id: "tunnel", label: "VPN Tunnel", severity: "pass",
        message: `Connected via profile: ${tunnel.profile || "unknown"}`,
        action: async () => {
          await api.clientTunnelDown();
          return "Tunnel disconnected";
        },
        actionLabel: "Disconnect",
        confirmRequired: true,
        confirmMessage: "This will disconnect the active VPN tunnel. You may lose access to remote resources. Continue?",
      };
    }
    let firstConfig: string | null = null;
    try {
      const configs = await api.clientListConfigs();
      firstConfig = configs.configs?.[0]?.name ?? null;
    } catch { /* ignore */ }

    return {
      id: "tunnel", label: "VPN Tunnel", severity: "warn",
      message: "VPN tunnel is not connected",
      fix: firstConfig
        ? `Connect using profile "${firstConfig}".`
        : "No configs available. Import one from the server first.",
      action: firstConfig
        ? async () => {
            await api.clientTunnelUp(firstConfig!);
            return `Connected via ${firstConfig}`;
          }
        : undefined,
      actionLabel: "Connect Now",
      confirmRequired: true,
      confirmMessage: firstConfig
        ? `This will establish a VPN connection using profile "${firstConfig}". Network traffic will be routed through the tunnel. Continue?`
        : undefined,
    };
  } catch {
    return {
      id: "tunnel", label: "VPN Tunnel", severity: "info",
      message: "Cannot check tunnel status",
      fix: "API server must be running to check tunnel.",
    };
  }
}

async function checkConfigs(): Promise<CheckResult> {
  try {
    const configs = await api.clientListConfigs();
    const count = configs.configs?.length ?? 0;
    if (count === 0) {
      return {
        id: "configs", label: "VPN Configs", severity: "warn",
        message: "No VPN configuration files found",
        fix: "Import a config from the server, or ask the admin to generate one for you.",
        details: "Go to the Connect page to import a .conf file.",
      };
    }
    return {
      id: "configs", label: "VPN Configs", severity: "pass",
      message: `${count} configuration file(s) available`,
    };
  } catch {
    return {
      id: "configs", label: "VPN Configs", severity: "info",
      message: "Cannot list configs — vault may be locked",
    };
  }
}

async function checkSSH(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  try {
    const sessions = await api.sshSessions();
    if (sessions.sessions && sessions.sessions.length > 0) {
      results.push({
        id: "ssh-sessions", label: "SSH Sessions", severity: "pass",
        message: `${sessions.sessions.length} active SSH session(s)`,
      });
    } else {
      results.push({
        id: "ssh-sessions", label: "SSH Sessions", severity: "info",
        message: "No active SSH sessions",
      });
    }
  } catch {
    results.push({
      id: "ssh-sessions", label: "SSH Sessions", severity: "info",
      message: "SSH session info not available",
    });
  }

  try {
    const keys = await api.sshKeysList();
    if (keys.keys && keys.keys.length > 0) {
      results.push({
        id: "ssh-keys", label: "SSH Keys", severity: "pass",
        message: `${keys.keys.length} SSH key(s) stored`,
      });
    } else {
      results.push({
        id: "ssh-keys", label: "SSH Keys", severity: "info",
        message: "No SSH keys stored — add one for passwordless login",
        fix: "Add your SSH key via the Terminal page.",
      });
    }
  } catch {
    results.push({
      id: "ssh-keys", label: "SSH Keys", severity: "info",
      message: "Cannot check SSH keys — vault may be locked",
    });
  }

  return results;
}

async function checkNetwork(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  try {
    const net = await api.getNetworkDevices();
    results.push({
      id: "lan", label: "LAN Detection", severity: "pass",
      message: `LAN subnet: ${net.lan_subnet} — ${net.devices?.length ?? 0} device(s) seen`,
    });
  } catch {
    results.push({
      id: "lan", label: "LAN Detection", severity: "info",
      message: "Cannot detect LAN devices",
    });
  }

  try {
    const svc = await api.getNetworkServices();
    if (svc.mdns_available) {
      results.push({
        id: "mdns", label: "mDNS / Bonjour", severity: "pass",
        message: `mDNS available — ${svc.services?.length ?? 0} service(s) found`,
        action: async () => {
          const res = await api.scanNetworkServices();
          return `Scan complete: ${res.services?.length ?? 0} service(s) found`;
        },
        actionLabel: "Re-scan mDNS",
        confirmRequired: true,
        confirmMessage: "This will perform a network scan to discover local services via mDNS. Continue?",
      });
    } else {
      results.push({
        id: "mdns", label: "mDNS / Bonjour", severity: "warn",
        message: "mDNS not available — cannot discover LAN services",
        fix: "Install zeroconf for service discovery.",
      });
    }
  } catch {
    // Silently skip — non-critical
  }

  return results;
}

async function checkPing(): Promise<CheckResult> {
  try {
    const status = await api.status();
    if (status.running) {
      return {
        id: "server-ping", label: "Server Reachable", severity: "pass",
        message: "Server VPN endpoint is responding",
      };
    }
    return {
      id: "server-ping", label: "Server Reachable", severity: "warn",
      message: "Server tunnel is not running",
      fix: "The server admin needs to start the WireGuard tunnel.",
    };
  } catch {
    return {
      id: "server-ping", label: "Server Reachable", severity: "info",
      message: "Cannot reach server to check status",
    };
  }
}

// ── Main Component ─────────────────────────────────────────────────────────

export function ClientTroubleshoot() {
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
      const [apiCheck, vaultCheck, tunnelCheck, configCheck, sshChecks, networkChecks, pingCheck] =
        await Promise.allSettled([
          checkApiServer(), checkVaultUnlocked(), checkTunnelStatus(),
          checkConfigs(), checkSSH(), checkNetwork(), checkPing(),
        ]);

      const v = <T,>(r: PromiseSettledResult<T>, fb: T): T =>
        r.status === "fulfilled" ? r.value : fb;

      setGroups([
        {
          title: "Connection",
          icon: Wifi,
          checks: [
            v(apiCheck, { id: "api", label: "API", severity: "fail" as Severity, message: "Check failed" }),
            v(vaultCheck, { id: "vault", label: "Vault", severity: "fail" as Severity, message: "Check failed" }),
            v(tunnelCheck, { id: "tunnel", label: "Tunnel", severity: "fail" as Severity, message: "Check failed" }),
            v(pingCheck, { id: "server-ping", label: "Server", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        {
          title: "VPN Configuration",
          icon: Key,
          checks: [
            v(configCheck, { id: "configs", label: "Configs", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        { title: "SSH & File Transfer", icon: Terminal, checks: v(sshChecks, []) },
        { title: "Network Discovery", icon: Globe, checks: v(networkChecks, []) },
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
  const overallLabel = failCount > 0 ? "Issues Detected" : warnCount > 0 ? "Warnings" : "All Systems Go";
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
            <h1 className="text-xl font-bold text-gray-900">Client Diagnostics</h1>
            <p className="text-sm text-gray-500">Connection health checks and remediation</p>
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
