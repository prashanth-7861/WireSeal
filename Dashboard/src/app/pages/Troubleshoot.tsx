import { useState, useEffect, useCallback } from "react";
import {
  Wrench, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Wifi, WifiOff, Shield, Server, Globe, HardDrive, Terminal,
  Copy, ChevronDown, ChevronRight, Loader2, Cpu, Lock,
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
  command?: string;
  details?: string;
}

interface CheckGroup {
  title: string;
  icon: typeof Server;
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

async function runApiCheck(): Promise<CheckResult> {
  try {
    await api.vaultInfo();
    return { id: "api", label: "API Server", severity: "pass", message: "API server is reachable and responding" };
  } catch {
    return {
      id: "api", label: "API Server", severity: "fail",
      message: "Cannot reach the WireSeal API server",
      fix: "Start the API server with the command below, or check if the service is running.",
      command: "sudo wireseal serve",
    };
  }
}

async function runVaultCheck(): Promise<CheckResult> {
  try {
    const info = await api.vaultInfo();
    if (info.state === "uninitialized") {
      return {
        id: "vault", label: "Vault", severity: "warn",
        message: "Vault not initialized — no server configuration exists yet",
        fix: "Initialize the vault to create your WireGuard server.",
        command: "sudo wireseal init --subnet 10.0.0.0/24 --port 51820",
      };
    }
    if (info.state === "locked") {
      return { id: "vault", label: "Vault", severity: "info", message: "Vault is locked — unlock it to manage clients" };
    }
    return { id: "vault", label: "Vault", severity: "pass", message: "Vault is unlocked and ready" };
  } catch {
    return { id: "vault", label: "Vault", severity: "fail", message: "Could not check vault state", fix: "API server may be down." };
  }
}

async function runWireGuardCheck(): Promise<CheckResult> {
  try {
    const status: Status = await api.status();
    if (status.running) {
      const peerCount = status.peers?.length ?? 0;
      return {
        id: "wg", label: "WireGuard Tunnel", severity: "pass",
        message: `WireGuard tunnel is running with ${peerCount} peer(s) configured`,
      };
    }
    return {
      id: "wg", label: "WireGuard Tunnel", severity: "warn",
      message: "WireGuard tunnel is not running",
      fix: "Start the tunnel or check if WireGuard is installed.",
      command: "sudo wg-quick up wg0",
      details: "If wg-quick is not found, WireGuard may not be installed. Install it with your package manager.",
    };
  } catch {
    return {
      id: "wg", label: "WireGuard Tunnel", severity: "fail",
      message: "Cannot check WireGuard status — vault may be locked or WireGuard not installed",
      fix: "Install WireGuard and ensure the vault is unlocked.",
      command: "sudo apt install wireguard-tools  # Debian/Ubuntu\nsudo pacman -S wireguard-tools    # Arch\nsudo dnf install wireguard-tools  # Fedora",
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
        fix: "Add a client to start using the VPN.",
        command: "sudo wireseal add-client my-phone",
      };
    }
    return {
      id: "clients", label: "VPN Clients", severity: "pass",
      message: `${clients.clients.length} client(s) configured`,
    };
  } catch {
    return { id: "clients", label: "VPN Clients", severity: "info", message: "Cannot list clients — vault may be locked" };
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
      results.push({
        id: "security-score", label: "Security Audit", severity: "warn",
        message: `${passed}/${total} security checks passed`,
        fix: "Go to the Security page to review and apply server hardening.",
      });
      // Add top 3 failing checks as detail
      const failing = sec.checks.filter(c => !c.ok).slice(0, 3);
      for (const c of failing) {
        results.push({
          id: `security-${c.id}`, label: c.label, severity: "warn",
          message: c.detail || "Check failed",
          fix: c.fix || undefined,
        });
      }
    }
    return results;
  } catch {
    return [{
      id: "security", label: "Security Audit", severity: "info",
      message: "Cannot run security checks — vault may be locked",
    }];
  }
}

async function runNetworkCheck(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  try {
    const net = await api.getNetworkDevices();
    results.push({
      id: "lan-subnet", label: "LAN Subnet", severity: "pass",
      message: `Detected LAN subnet: ${net.lan_subnet}`,
    });
    if (!net.scan_available) {
      results.push({
        id: "net-scan", label: "Network Scanner", severity: "info",
        message: "ARP scan not available — install arp-scan for device discovery",
        command: "sudo apt install arp-scan  # Debian/Ubuntu",
      });
    }
  } catch {
    results.push({
      id: "lan-subnet", label: "LAN Subnet", severity: "info",
      message: "Cannot detect LAN — vault may be locked",
    });
  }

  try {
    const svc = await api.getNetworkServices();
    if (!svc.mdns_available) {
      results.push({
        id: "mdns", label: "mDNS / Bonjour", severity: "warn",
        message: "mDNS service discovery not available — zeroconf package missing",
        fix: "Install the network extra for LAN device discovery.",
        command: "pip install wireseal[network]",
      });
    } else {
      results.push({
        id: "mdns", label: "mDNS / Bonjour", severity: "pass",
        message: `mDNS available — ${svc.services?.length ?? 0} service(s) discovered`,
      });
    }
  } catch {
    // ignore
  }

  return results;
}

async function runServiceCheck(): Promise<CheckResult> {
  try {
    const svc = await api.serviceStatus();
    if (svc.installed && svc.running) {
      return { id: "service", label: "Background Service", severity: "pass", message: "WireSeal service is installed and running" };
    }
    if (svc.installed) {
      return {
        id: "service", label: "Background Service", severity: "warn",
        message: "Service is installed but not running",
        fix: "Start the background service.",
        command: "sudo wireseal service start",
      };
    }
    return {
      id: "service", label: "Background Service", severity: "info",
      message: "Background service not installed (optional)",
      fix: "Install for auto-start on boot.",
      command: "sudo wireseal service install",
    };
  } catch {
    return { id: "service", label: "Background Service", severity: "info", message: "Cannot check service status" };
  }
}

async function runDnsCheck(): Promise<CheckResult> {
  try {
    const dns = await api.getDns();
    if (dns.provider && dns.provider !== "none") {
      return { id: "dns", label: "Dynamic DNS", severity: "pass", message: `DNS provider: ${dns.provider} — ${dns.hostname || "configured"}` };
    }
    return {
      id: "dns", label: "Dynamic DNS", severity: "info",
      message: "No dynamic DNS configured (optional — needed for changing IP addresses)",
      fix: "Set up DNS if your server IP changes. Go to the DNS page to configure.",
    };
  } catch {
    return { id: "dns", label: "Dynamic DNS", severity: "info", message: "Cannot check DNS — vault may be locked" };
  }
}

// ── Install Commands Map ───────────────────────────────────────────────────

const INSTALL_COMMANDS: { label: string; command: string }[] = [
  { label: "Install WireGuard (Debian/Ubuntu)", command: "sudo apt install wireguard wireguard-tools" },
  { label: "Install WireGuard (Arch)", command: "sudo pacman -S wireguard-tools" },
  { label: "Install WireGuard (Fedora)", command: "sudo dnf install wireguard-tools" },
  { label: "Install WireGuard (macOS)", command: "brew install wireguard-tools wireguard-go" },
  { label: "Install WireGuard (Windows)", command: "winget install WireGuard.WireGuard" },
  { label: "Install zeroconf/mDNS (pip)", command: "pip install wireseal[network]" },
  { label: "Install Avahi mDNS (Debian)", command: "sudo apt install avahi-daemon avahi-utils libnss-mdns" },
  { label: "Install Avahi mDNS (Arch)", command: "sudo pacman -S avahi nss-mdns" },
  { label: "Install GUI deps (Debian)", command: "sudo apt install python3-gi gir1.2-webkit2-4.1 python3-gi-cairo" },
  { label: "Install GUI deps (Arch)", command: "sudo pacman -S webkit2gtk python-gobject python-cairo" },
  { label: "Enable IP Forwarding (Linux)", command: "sudo sysctl -w net.ipv4.ip_forward=1" },
  { label: "Start WireGuard tunnel", command: "sudo wg-quick up wg0" },
  { label: "Check WireGuard status", command: "sudo wg show" },
  { label: "Start WireSeal API", command: "sudo wireseal serve" },
  { label: "Install WireSeal service", command: "sudo wireseal service install" },
];

// ── Main Component ─────────────────────────────────────────────────────────

export function Troubleshoot() {
  const [groups, setGroups] = useState<CheckGroup[]>([]);
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showInstall, setShowInstall] = useState(false);

  const runAllChecks = useCallback(async () => {
    setRunning(true);
    try {
      const [apiCheck, vaultCheck, wgCheck, clientCheck, securityChecks, networkChecks, serviceCheck, dnsCheck] =
        await Promise.allSettled([
          runApiCheck(), runVaultCheck(), runWireGuardCheck(), runClientCheck(),
          runSecurityCheck(), runNetworkCheck(), runServiceCheck(), runDnsCheck(),
        ]);

      const getValue = <T,>(r: PromiseSettledResult<T>, fallback: T): T =>
        r.status === "fulfilled" ? r.value : fallback;

      const result: CheckGroup[] = [
        {
          title: "Core Services",
          icon: Server,
          checks: [
            getValue(apiCheck, { id: "api", label: "API Server", severity: "fail" as Severity, message: "Check failed" }),
            getValue(vaultCheck, { id: "vault", label: "Vault", severity: "fail" as Severity, message: "Check failed" }),
            getValue(wgCheck, { id: "wg", label: "WireGuard", severity: "fail" as Severity, message: "Check failed" }),
            getValue(serviceCheck, { id: "service", label: "Service", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        {
          title: "VPN Configuration",
          icon: Wifi,
          checks: [
            getValue(clientCheck, { id: "clients", label: "Clients", severity: "fail" as Severity, message: "Check failed" }),
            getValue(dnsCheck, { id: "dns", label: "DNS", severity: "fail" as Severity, message: "Check failed" }),
          ],
        },
        {
          title: "Network & Discovery",
          icon: Globe,
          checks: getValue(networkChecks, []),
        },
        {
          title: "Security",
          icon: Shield,
          checks: getValue(securityChecks, []),
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
            <h1 className="text-xl font-bold text-gray-900">Server Troubleshoot</h1>
            <p className="text-sm text-gray-500">Diagnose and fix common server issues</p>
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

      {/* Install commands reference */}
      <div className="bg-white rounded-xl border border-gray-200 mt-6 overflow-hidden">
        <button
          onClick={() => setShowInstall(!showInstall)}
          className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-50"
        >
          <div className="flex items-center gap-3">
            <Terminal className="w-4 h-4 text-gray-500" />
            <h2 className="font-semibold text-gray-900">Install Commands Reference</h2>
          </div>
          {showInstall
            ? <ChevronDown className="w-4 h-4 text-gray-400" />
            : <ChevronRight className="w-4 h-4 text-gray-400" />}
        </button>

        {showInstall && (
          <div className="px-5 pb-4 space-y-2">
            {INSTALL_COMMANDS.map(({ label, command }) => (
              <div key={label} className="flex items-center gap-2">
                <span className="text-xs text-gray-500 w-48 flex-shrink-0">{label}</span>
                <pre className="bg-gray-900 text-green-400 px-3 py-1.5 rounded text-xs font-mono flex-1 truncate">
                  {command}
                </pre>
                <CopyButton text={command} />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
