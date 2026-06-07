import { useState, useEffect, useCallback } from "react";
import {
  Wrench, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Wifi, WifiOff, Globe, Terminal, Copy, ChevronDown,
  ChevronRight, Loader2, FolderOpen, Lock, Key, Server,
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
  command?: string;
  details?: string;
}

interface CheckGroup {
  title: string;
  icon: typeof Wifi;
  checks: CheckResult[];
}

// No module-level cache — diagnostic data must not leak across user sessions

// ── Helpers ────────────────────────────────────────────────────────────────

function SeverityIcon({ severity }: { severity: Severity }) {
  switch (severity) {
    case "pass": return <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />;
    case "warn": return <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0" />;
    case "fail": return <XCircle className="w-4 h-4 text-red-500 flex-shrink-0" />;
    case "info": return <Globe className="w-4 h-4 text-blue-500 flex-shrink-0" />;
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="ml-2 text-xs text-gray-400 hover:text-gray-600"
      title="Copy command"
    >
      {copied ? <CheckCircle className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
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
      command: "sudo wireseal serve",
    };
  }
}

async function checkVaultUnlocked(): Promise<CheckResult> {
  try {
    const info = await api.vaultInfo();
    if (info.state === "unlocked") {
      return { id: "vault", label: "Vault Access", severity: "pass", message: "Vault is unlocked — configs available" };
    }
    if (info.state === "locked") {
      return {
        id: "vault", label: "Vault Access", severity: "warn",
        message: "Vault is locked — unlock to access VPN configs",
        fix: "Enter your passphrase on the lock screen to unlock.",
      };
    }
    return {
      id: "vault", label: "Vault Access", severity: "fail",
      message: "Vault not initialized — server needs setup first",
      fix: "Ask the server admin to run 'wireseal init' first.",
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
      };
    }
    return {
      id: "tunnel", label: "VPN Tunnel", severity: "warn",
      message: "VPN tunnel is not connected",
      fix: "Go to the Connect page and select a profile to connect, or use the CLI.",
      command: "sudo wg-quick up <config-name>",
    };
  } catch {
    return {
      id: "tunnel", label: "VPN Tunnel", severity: "info",
      message: "Cannot check tunnel status",
      fix: "Tunnel status requires the API server to be running.",
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
        details: "Configs are usually .conf files exported from the server via 'wireseal export-config <client>'.",
        command: "sudo wireseal export-config my-device > ~/my-device.conf",
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
        fix: "Add your SSH key via the Terminal page or import from file.",
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
      });
    } else {
      results.push({
        id: "mdns", label: "mDNS / Bonjour", severity: "warn",
        message: "mDNS not available — cannot discover LAN services",
        fix: "Install the network extra for service discovery.",
        command: "pip install wireseal[network]",
      });
    }
  } catch {
    // ignore
  }

  return results;
}

async function checkClientSettings(): Promise<CheckResult> {
  try {
    await api.clientSettingsGet();
    return {
      id: "settings", label: "Client Settings", severity: "pass",
      message: "Client settings loaded successfully",
    };
  } catch {
    return {
      id: "settings", label: "Client Settings", severity: "info",
      message: "Cannot load client settings",
    };
  }
}

// ── Common fixes reference ─────────────────────────────────────────────────

const CLIENT_FIXES: { label: string; description: string; command?: string }[] = [
  {
    label: "Cannot connect to VPN",
    description: "Ensure WireGuard is installed, the config file is valid, and the server is reachable on the configured port.",
    command: "sudo wg-quick up <config-name>",
  },
  {
    label: "Connected but no internet",
    description: "Check that the server has IP forwarding and NAT enabled. For split-tunnel, only VPN traffic goes through the tunnel.",
    command: "ping 10.0.0.1  # Try pinging the server's VPN IP",
  },
  {
    label: "Cannot reach LAN devices",
    description: "You need split-lan tunnel mode. Ask the server admin to re-add your client with --tunnel-mode split-lan.",
    command: "sudo wireseal add-client my-device --tunnel-mode split-lan",
  },
  {
    label: "DNS not resolving",
    description: "Check the DNS setting in your WireGuard config. For split-lan, DNS should point to your router. For full tunnel, use 1.1.1.1 or 8.8.8.8.",
  },
  {
    label: "Handshake timeout",
    description: "The server may be behind a firewall or NAT. Ensure UDP port (usually 51820) is forwarded from your router to the server.",
  },
  {
    label: "Config file not found",
    description: "Export a config from the server and import it on the Connect page.",
    command: "sudo wireseal show-qr my-device  # Scan QR on phone\nsudo wireseal export-config my-device > ~/my-device.conf",
  },
  {
    label: "SSH connection refused",
    description: "Ensure SSH is running on the server, port 22 is open, and you have a valid key or password.",
    command: "ssh -v user@server-ip  # Verbose mode shows what's failing",
  },
  {
    label: "SFTP not working",
    description: "SFTP runs over SSH. If SSH works but SFTP doesn't, check that the SFTP subsystem is enabled in sshd_config.",
  },
];

// ── Main Component ─────────────────────────────────────────────────────────

export function ClientTroubleshoot() {
  const [groups, setGroups] = useState<CheckGroup[]>([]);
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showFixes, setShowFixes] = useState(false);

  const runAllChecks = useCallback(async () => {
    setRunning(true);
    try {
      const [apiCheck, vaultCheck, tunnelCheck, configCheck, sshChecks, networkChecks, settingsCheck] =
        await Promise.allSettled([
          checkApiServer(), checkVaultUnlocked(), checkTunnelStatus(),
          checkConfigs(), checkSSH(), checkNetwork(), checkClientSettings(),
        ]);

      const getValue = <T,>(r: PromiseSettledResult<T>, fallback: T): T =>
        r.status === "fulfilled" ? r.value : fallback;

      const result: CheckGroup[] = [
        {
          title: "Connection",
          icon: Wifi,
          checks: [
            getValue(apiCheck, { id: "api", label: "API", severity: "fail" as Severity, message: "Check failed" }),
            getValue(vaultCheck, { id: "vault", label: "Vault", severity: "fail" as Severity, message: "Check failed" }),
            getValue(tunnelCheck, { id: "tunnel", label: "Tunnel", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        {
          title: "VPN Configs",
          icon: Key,
          checks: [
            getValue(configCheck, { id: "configs", label: "Configs", severity: "fail" as Severity, message: "Check failed" }),
            getValue(settingsCheck, { id: "settings", label: "Settings", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        {
          title: "SSH & File Transfer",
          icon: Terminal,
          checks: getValue(sshChecks, []),
        },
        {
          title: "Network Discovery",
          icon: Globe,
          checks: getValue(networkChecks, []),
        },
      ];

      setGroups(result);
    } finally {
      setRunning(false);
    }
  }, []);

  useEffect(() => {
    runAllChecks();
  }, [runAllChecks]);

  const totalChecks = groups.reduce((sum, g) => sum + g.checks.length, 0);
  const passCount = groups.reduce((sum, g) => sum + g.checks.filter(c => c.severity === "pass").length, 0);
  const failCount = groups.reduce((sum, g) => sum + g.checks.filter(c => c.severity === "fail").length, 0);
  const warnCount = groups.reduce((sum, g) => sum + g.checks.filter(c => c.severity === "warn").length, 0);

  const overallColor = failCount > 0 ? "text-red-600" : warnCount > 0 ? "text-yellow-600" : "text-green-600";
  const overallBg = failCount > 0 ? "bg-red-50 border-red-200" : warnCount > 0 ? "bg-yellow-50 border-yellow-200" : "bg-green-50 border-green-200";
  const overallLabel = failCount > 0 ? "Issues Found" : warnCount > 0 ? "Warnings" : "All Good";
  const OverallIcon = failCount > 0 ? XCircle : warnCount > 0 ? AlertTriangle : CheckCircle;

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-orange-100 rounded-xl flex items-center justify-center">
            <Wrench className="w-5 h-5 text-orange-600" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">Client Troubleshoot</h1>
            <p className="text-sm text-gray-500">Diagnose connection and configuration issues</p>
          </div>
        </div>
        <button
          onClick={runAllChecks}
          disabled={running}
          className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 text-sm"
        >
          {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          {running ? "Running..." : "Re-run Checks"}
        </button>
      </div>

      {/* Score banner */}
      {totalChecks > 0 && (
        <div className={`rounded-xl border p-5 mb-6 ${overallBg}`}>
          <div className="flex items-center gap-4">
            <OverallIcon className={`w-8 h-8 ${overallColor}`} />
            <div>
              <p className={`text-lg font-bold ${overallColor}`}>{overallLabel}</p>
              <p className="text-sm text-gray-600">
                {passCount} passed, {warnCount} warning{warnCount !== 1 ? "s" : ""}, {failCount} failed — {totalChecks} total checks
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Check groups */}
      {groups.map((group) => {
        const groupFails = group.checks.filter(c => c.severity === "fail").length;
        const groupWarns = group.checks.filter(c => c.severity === "warn").length;
        const GroupIcon = group.icon;

        return (
          <div key={group.title} className="bg-white rounded-xl border border-gray-200 mb-4 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <GroupIcon className="w-4 h-4 text-gray-500" />
                <h2 className="font-semibold text-gray-900">{group.title}</h2>
              </div>
              <div className="flex items-center gap-2 text-xs">
                {groupFails > 0 && <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full">{groupFails} failed</span>}
                {groupWarns > 0 && <span className="px-2 py-0.5 bg-yellow-100 text-yellow-700 rounded-full">{groupWarns} warning{groupWarns !== 1 ? "s" : ""}</span>}
              </div>
            </div>

            <div className="divide-y divide-gray-50">
              {group.checks.map((check) => {
                const isExpanded = expanded[check.id] ?? (check.severity === "fail" || check.severity === "warn");
                const hasFix = check.fix || check.command || check.details;

                return (
                  <div key={check.id} className="px-5 py-3">
                    <button
                      onClick={() => hasFix && setExpanded(prev => ({ ...prev, [check.id]: !isExpanded }))}
                      className={`flex items-center gap-3 w-full text-left ${hasFix ? "cursor-pointer" : "cursor-default"}`}
                    >
                      <SeverityIcon severity={check.severity} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900">{check.label}</p>
                        <p className="text-xs text-gray-500 truncate">{check.message}</p>
                      </div>
                      {hasFix && (
                        isExpanded
                          ? <ChevronDown className="w-4 h-4 text-gray-400" />
                          : <ChevronRight className="w-4 h-4 text-gray-400" />
                      )}
                    </button>

                    {isExpanded && hasFix && (
                      <div className="mt-2 ml-7 p-3 bg-gray-50 rounded-lg text-sm space-y-2">
                        {check.fix && <p className="text-gray-700">{check.fix}</p>}
                        {check.details && <p className="text-gray-500 text-xs">{check.details}</p>}
                        {check.command && (
                          <div className="flex items-start gap-1">
                            <pre className="bg-gray-900 text-green-400 px-3 py-2 rounded text-xs font-mono whitespace-pre-wrap flex-1">
                              {check.command}
                            </pre>
                            <CopyButton text={check.command} />
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

      {/* Common fixes FAQ */}
      <div className="bg-white rounded-xl border border-gray-200 mt-6 overflow-hidden">
        <button
          onClick={() => setShowFixes(!showFixes)}
          className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-50"
        >
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 text-gray-500" />
            <h2 className="font-semibold text-gray-900">Common Issues & Fixes</h2>
          </div>
          {showFixes
            ? <ChevronDown className="w-4 h-4 text-gray-400" />
            : <ChevronRight className="w-4 h-4 text-gray-400" />}
        </button>

        {showFixes && (
          <div className="divide-y divide-gray-50">
            {CLIENT_FIXES.map(({ label, description, command }) => (
              <div key={label} className="px-5 py-3">
                <p className="text-sm font-medium text-gray-900 mb-1">{label}</p>
                <p className="text-xs text-gray-600 mb-2">{description}</p>
                {command && (
                  <div className="flex items-start gap-1">
                    <pre className="bg-gray-900 text-green-400 px-3 py-1.5 rounded text-xs font-mono whitespace-pre-wrap flex-1">
                      {command}
                    </pre>
                    <CopyButton text={command} />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
