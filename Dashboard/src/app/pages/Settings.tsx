import { useState, useEffect } from "react";
import {
  Lock,
  RotateCcw,
  AlertTriangle,
  Key,
  Eye,
  EyeOff,
  CheckCircle,
  Globe,
  PowerOff,
  Trash2,
  Copy,
  X,
  Cpu,
} from "lucide-react";
import { api } from "../api";

// ── Platform detection (best-effort) ────────────────────────────────────────
type OsKey = "windows" | "macos" | "linux" | "unknown";

function detectOs(): OsKey {
  if (typeof navigator === "undefined") return "unknown";
  const ua = navigator.userAgent || "";
  const platform = navigator.platform || "";
  if (/Win/i.test(platform) || /Windows/i.test(ua)) return "windows";
  if (/Mac/i.test(platform) || /Macintosh/i.test(ua)) return "macos";
  if (/Linux/i.test(platform) || /X11/i.test(ua)) return "linux";
  return "unknown";
}

// Per-OS uninstall instructions — copy-paste commands.
const UNINSTALL_COMMANDS: Record<OsKey, { label: string; cmd: string }[]> = {
  windows: [
    {
      label: "Installed via WireSeal-x64-Setup.exe (NSIS):",
      cmd: "Use Settings → Apps → WireSeal → Uninstall, or run %ProgramFiles%\\WireSeal\\uninstall.exe",
    },
    {
      label: "Installed via PowerShell venv script:",
      cmd: "Set-ExecutionPolicy Bypass -Scope Process -Force; .\\scripts\\uninstall-windows.ps1",
    },
    {
      label: "Also remove vault data (irreversible):",
      cmd: ".\\scripts\\uninstall-windows.ps1 -Purge -Yes",
    },
  ],
  macos: [
    { label: "Standard uninstall (keeps vault):", cmd: "sudo bash scripts/uninstall-macos.sh" },
    { label: "Also remove vault data (irreversible):", cmd: "sudo bash scripts/uninstall-macos.sh --purge --yes" },
  ],
  linux: [
    { label: "Standard uninstall (keeps vault):", cmd: "sudo bash scripts/uninstall-linux.sh" },
    { label: "Also remove vault data (irreversible):", cmd: "sudo bash scripts/uninstall-linux.sh --purge --yes" },
  ],
  unknown: [
    {
      label: "Manual removal:",
      cmd: "Run `wireseal uninstall` (CLI) or see README.md for per-OS uninstall steps.",
    },
  ],
};

export function Settings() {
  // Passphrase change
  const [showPassphraseDialog, setShowPassphraseDialog] = useState(false);
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [showPassphrases, setShowPassphrases] = useState(false);
  const [passphraseLoading, setPassphraseLoading] = useState(false);

  // Endpoint update
  const [showEndpointDialog, setShowEndpointDialog] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [endpointLoading, setEndpointLoading] = useState(false);

  // Background service
  const [svcStatus, setSvcStatus] = useState<{
    installed: boolean; running: boolean; enabled: boolean;
  } | null>(null);
  const [svcLoading, setSvcLoading] = useState(false);

  // Port change
  const [showPortDialog, setShowPortDialog] = useState(false);
  const [newPort, setNewPort] = useState("");
  const [portLoading, setPortLoading] = useState(false);
  // Pending warning from backend — when set, dialog flips to "confirm
  // anyway" mode and the next submit forwards confirm_warning=true.
  const [portWarning, setPortWarning] = useState<string | null>(null);
  // Cached port-policy from /api/port-policy. Loaded lazily when the dialog
  // opens so the Settings page doesn't pay the round-trip on every mount.
  const [portPolicy, setPortPolicy] = useState<{
    blocked: { port: number; reason: string }[];
    warnings: { port: number; reason: string }[];
    recommended: { port: number; label: string }[];
  } | null>(null);

  // Terminate
  const [terminateLoading, setTerminateLoading] = useState(false);

  // Fresh start
  const [showResetDialog, setShowResetDialog] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);

  // Uninstall
  const [showUninstallDialog, setShowUninstallDialog] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [uninstallPurge, setUninstallPurge] = useState(false);
  const [uninstallRunning, setUninstallRunning] = useState(false);
  const [uninstallDone, setUninstallDone] = useState(false);
  const detectedOs = detectOs();

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const copyCmd = async (cmd: string, idx: number) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1500);
    } catch {
      setError("Clipboard write failed — copy manually");
      setSuccess("");
    }
  };

  // Server-side uninstall: requests POST /api/uninstall with confirm
  // sentinel. Backend spawns the platform uninstall script detached and
  // exits the API process ~2s later. UI flips to "uninstall running" state
  // because every subsequent fetch will fail (the server is gone).
  const runUninstall = async () => {
    if (uninstallRunning || uninstallDone) return;
    const confirmMsg = uninstallPurge
      ? "Uninstall WireSeal AND delete vault data? This is irreversible — all vault keys, client configs, and audit history will be lost."
      : "Uninstall WireSeal? Vault data will be preserved at the OS-default path.";
    if (!window.confirm(confirmMsg)) return;
    setUninstallRunning(true);
    try {
      const res = await api.uninstall(uninstallPurge);
      // Backend will exit ~2s after responding. Mark done and surface the
      // expected disconnection so the user knows what to expect next.
      setUninstallDone(true);
      flash(res.note);
    } catch (e: unknown) {
      // Two failure modes: (1) backend rejected (auth, validation) — show
      // the message; (2) the connection dropped because the server already
      // exited — treat as success because the uninstall is in flight.
      const msg = e instanceof Error ? e.message : String(e);
      if (/Failed to fetch|NetworkError|connection/i.test(msg)) {
        setUninstallDone(true);
        flash("Uninstall in progress — API server has stopped.");
      } else {
        flashError(msg);
      }
    } finally {
      setUninstallRunning(false);
    }
  };

  const flash = (msg: string) => {
    setSuccess(msg);
    setError("");
    setTimeout(() => setSuccess(""), 4000);
  };

  const flashError = (msg: string) => {
    setError(msg);
    setSuccess("");
  };

  const handleChangePassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (newPassphrase.length < 12) {
      setError("New passphrase must be at least 12 characters");
      return;
    }
    if (newPassphrase !== confirmPassphrase) {
      setError("New passphrases do not match");
      return;
    }

    setPassphraseLoading(true);
    try {
      await api.changePassphrase(currentPassphrase, newPassphrase);
      setShowPassphraseDialog(false);
      setCurrentPassphrase("");
      setNewPassphrase("");
      setConfirmPassphrase("");
      flash("Passphrase updated successfully");
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Failed to change passphrase");
    } finally {
      setPassphraseLoading(false);
    }
  };

  const handleUpdateEndpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    setEndpointLoading(true);
    try {
      const res = await api.updateEndpoint(endpoint.trim() || undefined);
      setShowEndpointDialog(false);
      setEndpoint("");
      flash(`Endpoint updated to ${res.endpoint}`);
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Failed to update endpoint");
    } finally {
      setEndpointLoading(false);
    }
  };

  const openPortDialog = async () => {
    setShowPortDialog(true);
    setPortWarning(null);
    setNewPort("");
    if (!portPolicy) {
      try {
        const p = await api.portPolicy();
        setPortPolicy({
          blocked: p.blocked,
          warnings: p.warnings,
          recommended: p.recommended,
        });
      } catch {
        // Non-fatal — dialog still works without quick-picks.
      }
    }
  };

  const handleChangePort = async (e: React.FormEvent) => {
    e.preventDefault();
    const portNum = parseInt(newPort, 10);
    if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
      flashError("Port must be 1-65535");
      return;
    }
    // If we already surfaced a warning to the user and they re-submit,
    // forward confirm_warning=true so the backend accepts the port.
    const confirmingWarning = portWarning !== null;
    setPortLoading(true);
    try {
      const res = await api.changePort(portNum, confirmingWarning);
      setShowPortDialog(false);
      setNewPort("");
      setPortWarning(null);
      const warns = res.warnings && res.warnings.length > 0
        ? ` (background warnings: ${res.warnings.join("; ")})`
        : "";
      flash(`Port changed: ${res.old_port} -> ${res.new_port}. Re-scan client QR codes.${warns}`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to change port";
      // Backend signals an "are you sure?" warning by including this exact
      // phrase in the 400 error message. Detect it and surface a confirm UI
      // instead of dismissing the dialog.
      if (/Resubmit with `confirm_warning: true`/i.test(msg)) {
        setPortWarning(msg.replace(/\s*Resubmit with .*$/i, "").trim());
      } else {
        flashError(msg);
      }
    } finally {
      setPortLoading(false);
    }
  };

  // ── Background-service handlers ─────────────────────────────────────────
  // Each call refreshes svcStatus from the backend so the UI reflects the
  // OS service-manager's truth (systemd / launchd / Task Scheduler).
  const refreshSvcStatus = async () => {
    try {
      const s = await api.serviceStatus();
      setSvcStatus({ installed: s.installed, running: s.running, enabled: s.enabled });
    } catch {
      setSvcStatus(null);
    }
  };

  useEffect(() => {
    refreshSvcStatus();
    // Re-poll once a minute so external state changes (sysadmin runs
    // `systemctl stop wireseal-api` directly) eventually surface in the UI.
    const t = setInterval(refreshSvcStatus, 60_000);
    return () => clearInterval(t);
  }, []);

  const handleSvcInstall = async () => {
    setSvcLoading(true);
    try {
      const s = await api.serviceInstall({ autostart: true });
      setSvcStatus({ installed: s.installed, running: s.running, enabled: s.enabled });
      flash("Service installed. Click Start to launch it now.");
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Service install failed");
    } finally {
      setSvcLoading(false);
    }
  };

  const handleSvcUninstall = async () => {
    if (!confirm("Uninstall the WireSeal background service? Dashboard will only run when launched manually.")) return;
    setSvcLoading(true);
    try {
      await api.serviceUninstall();
      await refreshSvcStatus();
      flash("Service uninstalled.");
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Service uninstall failed");
    } finally {
      setSvcLoading(false);
    }
  };

  const handleSvcStart = async () => {
    setSvcLoading(true);
    try {
      const s = await api.serviceStart();
      setSvcStatus({ installed: s.installed, running: s.running, enabled: s.enabled });
      flash("Service started.");
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Service start failed");
    } finally {
      setSvcLoading(false);
    }
  };

  const handleSvcStop = async () => {
    if (!confirm("Stop the background service? The dashboard will keep running until you close it.")) return;
    setSvcLoading(true);
    try {
      const s = await api.serviceStop();
      setSvcStatus({ installed: s.installed, running: s.running, enabled: s.enabled });
      flash("Service stopped.");
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Service stop failed");
    } finally {
      setSvcLoading(false);
    }
  };

  const handleTerminate = async () => {
    if (!confirm("Stop the WireGuard interface (wg-quick down)? Clients will disconnect.")) return;
    setTerminateLoading(true);
    try {
      await api.terminate();
      flash("WireGuard interface stopped");
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Failed to stop interface");
    } finally {
      setTerminateLoading(false);
    }
  };

  const handleFreshStart = async () => {
    setResetLoading(true);
    try {
      await api.freshStart();
      flash("Fresh start complete — vault and configs wiped");
      setTimeout(() => window.location.reload(), 2000);
    } catch (e: unknown) {
      flashError(e instanceof Error ? e.message : "Failed to perform fresh start");
      setShowResetDialog(false);
    } finally {
      setResetLoading(false);
    }
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Settings</h1>
        <p className="text-gray-500 mt-1">Manage vault security and server settings</p>
      </div>

      {success && (
        <div className="mb-6 bg-green-50 border border-green-200 rounded-lg p-4 flex items-center gap-3">
          <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
          <p className="text-green-800">{success}</p>
        </div>
      )}

      {error && !showPassphraseDialog && !showEndpointDialog && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Security Settings */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <Lock className="w-6 h-6 text-gray-700" />
            <h2 className="text-xl font-semibold text-gray-900">Security Settings</h2>
          </div>
        </div>
        <div className="divide-y divide-gray-100">
          <div className="p-6 flex items-center justify-between">
            <div>
              <h3 className="font-medium text-gray-900 mb-1">Change Vault Passphrase</h3>
              <p className="text-sm text-gray-500">Re-encrypt the vault with a new passphrase</p>
            </div>
            <button
              onClick={() => setShowPassphraseDialog(true)}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
            >
              <Key className="w-4 h-4" />
              Change Passphrase
            </button>
          </div>
          <div className="p-6 flex items-center justify-between">
            <div>
              <h3 className="font-medium text-gray-900 mb-1">Update Public Endpoint</h3>
              <p className="text-sm text-gray-500">
                Set or auto-detect the server's public IP/hostname for client configs
              </p>
            </div>
            <button
              onClick={() => setShowEndpointDialog(true)}
              className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors flex items-center gap-2"
            >
              <Globe className="w-4 h-4" />
              Update Endpoint
            </button>
          </div>
          <div className="p-6 flex items-center justify-between">
            <div>
              <h3 className="font-medium text-gray-900 mb-1">Change WireGuard Port</h3>
              <p className="text-sm text-gray-500">
                Reconciles the firewall rule (drops the old port, opens the new), re-renders
                <code className="mx-1 px-1 bg-gray-100 rounded">wg0.conf</code>, and restarts
                the tunnel. Existing clients must re-scan the QR code to pick up the new endpoint.
              </p>
            </div>
            <button
              onClick={openPortDialog}
              className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors flex items-center gap-2"
            >
              <Globe className="w-4 h-4" />
              Change Port
            </button>
          </div>
        </div>
      </div>

      {/* Background Service */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <Cpu className="w-6 h-6 text-gray-700" />
            <h2 className="text-xl font-semibold text-gray-900">Background Service</h2>
          </div>
          <p className="text-xs text-gray-500 mt-1.5">
            Run WireSeal as an OS-managed service that survives terminal close and starts at boot.
            Linux <code>systemd</code> · macOS <code>launchd</code> · Windows Task Scheduler.
          </p>
        </div>

        <div className="p-6 space-y-4">
          {/* Status row — three indicators. */}
          <div className="grid grid-cols-3 gap-3">
            {([
              ["installed", "Registered", "Service is registered with the OS service manager"],
              ["enabled",   "Auto-start", "Will start at boot / system login"],
              ["running",   "Running",    "Service is currently running in the background"],
            ] as const).map(([k, label, hint]) => (
              <div
                key={k}
                className="border border-gray-200 rounded-lg p-3"
                title={hint}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      svcStatus && svcStatus[k] ? "bg-green-500" : "bg-gray-300"
                    }`}
                  />
                  <span className="text-xs font-medium text-gray-700">{label}</span>
                </div>
                <p className="text-sm font-semibold text-gray-900 mt-1">
                  {svcStatus
                    ? svcStatus[k]
                      ? "Yes"
                      : "No"
                    : "—"}
                </p>
              </div>
            ))}
          </div>

          {/* Action buttons — install/uninstall + start/stop. */}
          <div className="flex flex-wrap gap-2">
            {!svcStatus?.installed ? (
              <button
                onClick={handleSvcInstall}
                disabled={svcLoading}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2 disabled:opacity-60"
              >
                <Cpu className="w-4 h-4" />
                {svcLoading ? "Installing..." : "Install Service"}
              </button>
            ) : (
              <>
                {svcStatus.running ? (
                  <button
                    onClick={handleSvcStop}
                    disabled={svcLoading}
                    className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors flex items-center gap-2 disabled:opacity-60"
                  >
                    <PowerOff className="w-4 h-4" />
                    {svcLoading ? "Stopping..." : "Stop"}
                  </button>
                ) : (
                  <button
                    onClick={handleSvcStart}
                    disabled={svcLoading}
                    className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2 disabled:opacity-60"
                  >
                    <CheckCircle className="w-4 h-4" />
                    {svcLoading ? "Starting..." : "Start"}
                  </button>
                )}
                <button
                  onClick={handleSvcUninstall}
                  disabled={svcLoading}
                  className="px-4 py-2 border border-red-300 text-red-700 rounded-lg hover:bg-red-50 transition-colors flex items-center gap-2 disabled:opacity-60"
                >
                  <Trash2 className="w-4 h-4" />
                  Uninstall
                </button>
              </>
            )}
            <button
              onClick={refreshSvcStatus}
              disabled={svcLoading}
              className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-gray-700 disabled:opacity-60"
            >
              Refresh
            </button>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-900">
            <p className="font-medium mb-1">Where this lives on disk:</p>
            <ul className="list-disc list-inside space-y-0.5 font-mono">
              <li>Linux: <code>/etc/systemd/system/wireseal.service</code></li>
              <li>macOS: <code>/Library/LaunchDaemons/com.wireseal.api.plist</code></li>
              <li>Windows: Task Scheduler task <code>WireSeal-API</code> (run as SYSTEM)</li>
            </ul>
            <p className="font-medium mt-2 mb-1">Manual control (Linux):</p>
            <pre className="text-[11px]">{`sudo systemctl start  wireseal
sudo systemctl stop   wireseal
sudo systemctl status wireseal`}</pre>
          </div>
        </div>
      </div>

      {/* Server Control */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <PowerOff className="w-6 h-6 text-gray-700" />
            <h2 className="text-xl font-semibold text-gray-900">Server Control</h2>
          </div>
        </div>
        <div className="p-6 flex items-center justify-between">
          <div>
            <h3 className="font-medium text-gray-900 mb-1">Stop WireGuard Interface</h3>
            <p className="text-sm text-gray-500">
              Runs <code className="text-xs bg-gray-100 px-1 py-0.5 rounded">wg-quick down wg0</code> — all clients will disconnect
            </p>
          </div>
          <button
            onClick={handleTerminate}
            disabled={terminateLoading}
            className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition-colors flex items-center gap-2 disabled:opacity-60"
          >
            <PowerOff className="w-4 h-4" />
            {terminateLoading ? "Stopping…" : "Stop Server"}
          </button>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="bg-white rounded-lg shadow-sm border border-red-200">
        <div className="p-6 border-b border-red-200 bg-red-50">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-red-700" />
            <h2 className="text-xl font-semibold text-red-900">Danger Zone</h2>
          </div>
        </div>
        <div className="divide-y divide-red-100">
          <div className="p-6 flex items-center justify-between">
            <div>
              <h3 className="font-medium text-gray-900 mb-1">Fresh Start (Wipe Everything)</h3>
              <p className="text-sm text-gray-500">
                Destroys the vault, all client configs, and brings down the WireGuard interface. This
                cannot be undone.
              </p>
            </div>
            <button
              onClick={() => setShowResetDialog(true)}
              className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
            >
              <RotateCcw className="w-4 h-4" />
              Fresh Start
            </button>
          </div>
          <div className="p-6 flex items-center justify-between">
            <div>
              <h3 className="font-medium text-gray-900 mb-1">Uninstall WireSeal</h3>
              <p className="text-sm text-gray-500">
                Removes the WireSeal binary, virtualenv, and system wrapper. Vault data is
                preserved unless you opt in to <code>--purge</code>. Requires admin/sudo.
              </p>
            </div>
            <button
              onClick={() => setShowUninstallDialog(true)}
              className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Uninstall
            </button>
          </div>
        </div>
      </div>

      {/* Change Passphrase Dialog */}
      {showPassphraseDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                <Key className="w-6 h-6 text-blue-700" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-gray-900">Change Passphrase</h2>
                <p className="text-sm text-gray-500">Enter current and new passphrase</p>
              </div>
            </div>

            <form onSubmit={handleChangePassphrase} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Current Passphrase</label>
                <div className="relative">
                  <input
                    type={showPassphrases ? "text" : "password"}
                    value={currentPassphrase}
                    onChange={(e) => setCurrentPassphrase(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="Enter current passphrase"
                    required
                    disabled={passphraseLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassphrases(!showPassphrases)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  >
                    {showPassphrases ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">New Passphrase</label>
                <input
                  type={showPassphrases ? "text" : "password"}
                  value={newPassphrase}
                  onChange={(e) => setNewPassphrase(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Min. 12 characters"
                  required
                  disabled={passphraseLoading}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Confirm New Passphrase</label>
                <input
                  type={showPassphrases ? "text" : "password"}
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Confirm new passphrase"
                  required
                  disabled={passphraseLoading}
                />
              </div>

              {error && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowPassphraseDialog(false); setError(""); setCurrentPassphrase(""); setNewPassphrase(""); setConfirmPassphrase(""); }}
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={passphraseLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60"
                  disabled={passphraseLoading}
                >
                  {passphraseLoading ? "Updating…" : "Update Passphrase"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Change Port Dialog */}
      {showPortDialog && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
          onClick={(e) => {
            // Click outside dialog dismisses it (ignore clicks on the dialog itself).
            if (e.target === e.currentTarget && !portLoading) {
              setShowPortDialog(false);
              setError("");
              setNewPort("");
              setPortWarning(null);
            }
          }}
        >
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md max-h-[90vh] flex flex-col">
            {/* Sticky header with X close — solves "cannot close popup" bug. */}
            <div className="flex items-start justify-between gap-3 p-6 border-b border-gray-100 flex-shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center">
                  <Globe className="w-6 h-6 text-gray-700" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">Change WireGuard Port</h2>
                  <p className="text-sm text-gray-500">UDP, 1-65535. Tunnel restarts.</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowPortDialog(false);
                  setError("");
                  setNewPort("");
                  setPortWarning(null);
                }}
                className="p-1 rounded hover:bg-gray-100 transition-colors flex-shrink-0"
                disabled={portLoading}
                aria-label="Close"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>

            <form
              onSubmit={handleChangePort}
              className="flex flex-col flex-1 min-h-0"
            >
              {/* Scrollable body — keeps Apply button visible when content is tall. */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">New Port</label>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={newPort}
                  onChange={(e) => { setNewPort(e.target.value); setPortWarning(null); }}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg font-mono focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., 51821"
                  disabled={portLoading}
                  autoFocus
                />
                <p className="text-xs text-gray-400 mt-1.5">
                  UDP, 1-65535. Background: drops old firewall rule, opens new,
                  re-renders <code>wg0.conf</code>, restarts tunnel.
                </p>
              </div>

              {/* Recommended quick-pick chips. Loaded from /api/port-policy. */}
              {portPolicy && portPolicy.recommended.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-gray-500 mb-1.5">Recommended</p>
                  <div className="flex flex-wrap gap-1.5">
                    {portPolicy.recommended.map((r) => (
                      <button
                        type="button"
                        key={r.port}
                        onClick={() => { setNewPort(String(r.port)); setPortWarning(null); }}
                        className="px-2.5 py-1 text-xs font-mono border border-gray-300 rounded hover:bg-gray-50 transition-colors"
                        title={r.label}
                        disabled={portLoading}
                      >
                        {r.port}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Conditions block — what's blocked vs warned. */}
              {portPolicy && (
                <details className="bg-gray-50 border border-gray-200 rounded-lg text-xs">
                  <summary className="px-3 py-2 cursor-pointer text-gray-700 font-medium">
                    Port restrictions ({portPolicy.blocked.length} blocked, {portPolicy.warnings.length} flagged)
                  </summary>
                  <div className="px-3 pb-3 space-y-2 text-gray-600">
                    <div>
                      <p className="font-medium text-red-700 mt-2">Blocked (will be rejected):</p>
                      <ul className="list-disc list-inside space-y-0.5">
                        {portPolicy.blocked.map((b) => (
                          <li key={b.port}><span className="font-mono">{b.port}</span> — {b.reason}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <p className="font-medium text-yellow-700">Flagged (require confirmation):</p>
                      <ul className="list-disc list-inside space-y-0.5">
                        {portPolicy.warnings.map((w) => (
                          <li key={w.port}><span className="font-mono">{w.port}</span> — {w.reason}</li>
                        ))}
                        <li>Privileged range <span className="font-mono">1-1023</span> — well-known, may be filtered upstream</li>
                      </ul>
                    </div>
                  </div>
                </details>
              )}

              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 flex gap-2 text-sm text-yellow-900">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Existing peers cache the old endpoint. After saving, re-scan each client's QR code.</span>
              </div>

              {/* Backend-flagged port — shown after a 400 with a port warning. */}
              {portWarning && (
                <div className="bg-orange-50 border border-orange-300 rounded-lg p-3 text-sm text-orange-900">
                  <div className="flex gap-2">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-orange-700" />
                    <div>
                      <p className="font-medium mb-1">Port flagged by policy</p>
                      <p className="text-xs">{portWarning}</p>
                      <p className="text-xs mt-1.5">
                        Click <strong>Apply anyway</strong> to override and use this port.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {error && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              </div>

              {/* Sticky footer — Cancel + Apply always visible regardless of body scroll. */}
              <div className="flex gap-3 p-6 border-t border-gray-100 flex-shrink-0 bg-white rounded-b-lg">
                <button
                  type="button"
                  onClick={() => { setShowPortDialog(false); setError(""); setNewPort(""); setPortWarning(null); }}
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={portLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className={`flex-1 ${portWarning ? "bg-orange-600 hover:bg-orange-700" : "bg-gray-700 hover:bg-gray-800"} text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-60`}
                  disabled={portLoading}
                >
                  {portLoading
                    ? "Applying..."
                    : portWarning
                      ? "Apply anyway"
                      : "Apply"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Update Endpoint Dialog */}
      {showEndpointDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center">
                <Globe className="w-6 h-6 text-gray-700" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-gray-900">Update Endpoint</h2>
                <p className="text-sm text-gray-500">Leave blank to auto-detect your public IP</p>
              </div>
            </div>

            <form onSubmit={handleUpdateEndpoint} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Public IP or Hostname (optional)
                </label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="e.g., 203.0.113.1 or vpn.example.com"
                  disabled={endpointLoading}
                />
              </div>

              {error && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowEndpointDialog(false); setError(""); setEndpoint(""); }}
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={endpointLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 bg-gray-700 text-white px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors disabled:opacity-60"
                  disabled={endpointLoading}
                >
                  {endpointLoading ? "Updating…" : "Update"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Fresh Start Confirmation Dialog */}
      {showResetDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-red-700" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900">Confirm Fresh Start</h2>
            </div>
            <p className="text-gray-700 mb-4">This will permanently destroy:</p>
            <ul className="space-y-2 mb-6 text-sm text-gray-600">
              {[
                "The encrypted vault (all keys and secrets)",
                "All client WireGuard configs",
                "The audit log",
                "The WireGuard server config",
              ].map((item) => (
                <li key={item} className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-red-600 rounded-full flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
            <div className="flex gap-3">
              <button
                onClick={() => setShowResetDialog(false)}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                disabled={resetLoading}
              >
                Cancel
              </button>
              <button
                onClick={handleFreshStart}
                className="flex-1 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-60"
                disabled={resetLoading}
              >
                {resetLoading ? "Wiping…" : "Confirm Fresh Start"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Uninstall Instructions Dialog */}
      {showUninstallDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200 flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                  <Trash2 className="w-6 h-6 text-red-700" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">Uninstall WireSeal</h2>
                  <p className="text-sm text-gray-500">
                    Detected OS: <span className="font-mono">{detectedOs}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowUninstallDialog(false)}
                className="p-1 rounded hover:bg-gray-100"
                aria-label="Close"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 flex gap-3">
                <AlertTriangle className="w-5 h-5 text-yellow-700 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-yellow-900">
                  <p className="font-medium mb-1">Two ways to uninstall:</p>
                  <p>
                    <strong>(1) Run from this dashboard</strong> using the red button below — backend
                    spawns the platform uninstall script and shuts down the API server. Requires the
                    server to already be running with the privileges it was installed with (root /
                    Administrator).
                  </p>
                  <p className="mt-1.5">
                    <strong>(2) Run manually</strong> — copy a command below and execute it in an
                    elevated terminal. Use this if the run-now path errors out.
                  </p>
                </div>
              </div>

              {/* Run-from-dashboard control */}
              {!uninstallDone && (
                <div className="border border-red-200 bg-red-50 rounded-lg p-4 space-y-3">
                  <div className="flex items-start gap-3">
                    <Trash2 className="w-5 h-5 text-red-700 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="font-medium text-red-900">Run uninstall now</p>
                      <p className="text-xs text-red-800 mt-1">
                        Spawns <code>scripts/uninstall-{detectedOs === "windows" ? "windows.ps1" : detectedOs === "macos" ? "macos.sh" : "linux.sh"}</code> with <code>--yes</code>, then exits the API server.
                        The dashboard will go offline.
                      </p>
                    </div>
                  </div>
                  <label className="flex items-center gap-2 text-sm text-red-900 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={uninstallPurge}
                      onChange={(e) => setUninstallPurge(e.target.checked)}
                      disabled={uninstallRunning}
                      className="rounded border-red-300"
                    />
                    Also delete vault data ({detectedOs === "windows"
                      ? "%APPDATA%\\WireSeal"
                      : detectedOs === "macos"
                        ? "~/Library/Application Support/WireSeal"
                        : "~/.config/wireseal"}) — irreversible
                  </label>
                  <button
                    onClick={runUninstall}
                    disabled={uninstallRunning}
                    className="w-full px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center justify-center gap-2 disabled:opacity-60"
                  >
                    <Trash2 className="w-4 h-4" />
                    {uninstallRunning
                      ? "Running..."
                      : uninstallPurge
                        ? "Uninstall + Purge Vault"
                        : "Uninstall (keep vault)"}
                  </button>
                </div>
              )}

              {uninstallDone && (
                <div className="border border-green-200 bg-green-50 rounded-lg p-4 flex gap-3">
                  <CheckCircle className="w-5 h-5 text-green-700 flex-shrink-0 mt-0.5" />
                  <div className="text-sm text-green-900">
                    <p className="font-medium">Uninstall in progress.</p>
                    <p className="mt-1">
                      The API server is shutting down. Close this window — the dashboard will not
                      reconnect because the service is being removed.
                    </p>
                  </div>
                </div>
              )}

              {UNINSTALL_COMMANDS[detectedOs].map((entry, idx) => (
                <div key={idx} className="space-y-1.5">
                  <p className="text-sm font-medium text-gray-700">{entry.label}</p>
                  <div className="flex items-stretch gap-2">
                    <code className="flex-1 bg-gray-900 text-green-300 font-mono text-xs px-3 py-2 rounded-lg overflow-x-auto whitespace-pre">
                      {entry.cmd}
                    </code>
                    <button
                      onClick={() => copyCmd(entry.cmd, idx)}
                      className="px-3 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg flex items-center gap-1.5 text-sm text-gray-700 transition-colors"
                      title="Copy to clipboard"
                    >
                      {copiedIdx === idx ? (
                        <>
                          <CheckCircle className="w-4 h-4 text-green-600" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-4 h-4" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ))}

              <div className="bg-gray-50 border border-gray-200 rounded-lg p-3 text-xs text-gray-600">
                <p className="font-medium text-gray-700 mb-1">What gets removed:</p>
                <ul className="list-disc list-inside space-y-0.5">
                  <li>System wrapper (<code>wireseal</code> command)</li>
                  <li>Virtualenv at <code>.venv</code></li>
                  <li>Tunnel service / systemd unit / launchd plist (per-OS)</li>
                  <li>Firewall rule (UDP 51820)</li>
                  <li><strong>Vault data preserved</strong> unless <code>--purge</code> / <code>-Purge</code> is passed</li>
                </ul>
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 flex justify-end">
              <button
                onClick={() => setShowUninstallDialog(false)}
                className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
