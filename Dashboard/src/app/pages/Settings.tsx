import { useState } from "react";
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
} from "lucide-react";
import { api } from "../api";

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

  // Terminate
  const [terminateLoading, setTerminateLoading] = useState(false);

  // Fresh start
  const [showResetDialog, setShowResetDialog] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

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
    </div>
  );
}
