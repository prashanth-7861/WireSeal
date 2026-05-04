import { useState, useEffect } from "react";
import { NavLink, Outlet } from "react-router";
import {
  Wifi, TerminalSquare, Settings, Info, LogOut,
  Circle, WifiOff, KeyRound, Trash2, AlertCircle,
} from "lucide-react";
import { api } from "../api";

interface ClientLayoutProps {
  onLock: () => void;
}

const navItems = [
  { to: "/client", label: "Connect", icon: Wifi, end: true },
  { to: "/client/terminal", label: "Terminal", icon: TerminalSquare },
  { to: "/client/settings", label: "Settings", icon: Settings },
  { to: "/about", label: "About", icon: Info },
];

export function ClientLayout({ onLock }: ClientLayoutProps) {
  const [pinSet, setPinSet] = useState(false);
  const [showPinSetup, setShowPinSetup] = useState(false);
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [pinSetupError, setPinSetupError] = useState("");
  const [pinSetupLoading, setPinSetupLoading] = useState(false);

  useEffect(() => {
    api.pinInfo().then((info) => setPinSet(info.pin_set ?? false)).catch(() => {});
  }, []);

  const handlePinSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setPinSetupError("");

    if (!newPin || !newPin.match(/^\d{4,8}$/)) {
      setPinSetupError("PIN must be 4–8 digits"); return;
    }
    if (newPin !== confirmPin) {
      setPinSetupError("PINs do not match"); return;
    }

    setPinSetupLoading(true);
    try {
      await api.setPin(newPin);
      setPinSet(true);
      setShowPinSetup(false);
      setNewPin("");
      setConfirmPin("");
    } catch (err: unknown) {
      setPinSetupError(err instanceof Error ? err.message : "Failed to set PIN");
    } finally {
      setPinSetupLoading(false);
    }
  };

  const handleRemovePin = async () => {
    try {
      await api.removePin();
      setPinSet(false);
    } catch {
      // ignore
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <aside className="fixed left-0 top-0 h-full w-60 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-5 border-b border-gray-100">
          <h1 className="font-bold text-lg text-gray-900 tracking-tight">WireSeal</h1>
          <p className="text-xs text-emerald-600 mt-0.5 font-medium">Client Mode</p>
        </div>

        <nav className="px-2 py-3 flex-1">
          {navItems.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg mb-0.5 transition-colors text-sm ${
                  isActive
                    ? "bg-emerald-50 text-emerald-700 font-medium"
                    : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Status indicators */}
        <div className="px-4 py-3 border-t border-gray-100 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <WifiOff className="w-3 h-3 text-gray-400" />
              <span className="text-xs text-gray-500">VPN Tunnel</span>
            </div>
            <span className="text-xs font-medium text-gray-400">
              Not connected
            </span>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Circle className="w-2.5 h-2.5 fill-current text-green-500" />
              <span className="text-xs text-gray-500">API Server</span>
            </div>
            <span className="text-xs font-medium text-green-600">Online</span>
          </div>
          {/* PIN indicator */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRound className={`w-3 h-3 ${pinSet ? "text-green-500" : "text-gray-400"}`} />
              <span className="text-xs text-gray-500">Quick PIN</span>
            </div>
            {pinSet ? (
              <button
                onClick={handleRemovePin}
                className="text-xs text-red-500 hover:text-red-600 flex items-center gap-1 transition-colors"
                title="Remove PIN"
              >
                <Trash2 className="w-3 h-3" />
                Remove
              </button>
            ) : (
              <button
                onClick={() => setShowPinSetup(true)}
                className="text-xs text-blue-500 hover:text-blue-600 transition-colors"
              >
                Set PIN
              </button>
            )}
          </div>
        </div>

        <div className="p-2 border-t border-gray-100 space-y-0.5">
          {/* Removed "Switch to Server" — server vs client roles are locked
              to the vault at init. clearMode() would just re-sync to
              vault.mode and flip back, leaving the user stuck. To switch
              roles, run Fresh-Start (Settings) which destroys the vault
              and lets the user re-init in the other mode. */}
          <button
            onClick={onLock}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg w-full text-gray-500 hover:bg-gray-100 hover:text-gray-700 transition-colors text-sm"
          >
            <LogOut className="w-4 h-4" />
            <span>Lock Vault</span>
          </button>
        </div>
      </aside>

      <main className="ml-60 p-8">
        <Outlet />
      </main>

      {/* PIN setup dialog */}
      {showPinSetup && (
        <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md mx-4">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                <KeyRound className="w-6 h-6 text-green-700" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-gray-900">Set a Quick Unlock PIN</h2>
                <p className="text-sm text-gray-500">Skip the passphrase next time</p>
              </div>
            </div>

            <form onSubmit={handlePinSetup} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">PIN (4-8 digits)</label>
                <input
                  type="password"
                  inputMode="numeric"
                  value={newPin}
                  onChange={(e) => { if (/^\d*$/.test(e.target.value) && e.target.value.length <= 8) setNewPin(e.target.value); }}
                  className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-xl tracking-[0.5em]"
                  placeholder="Enter PIN"
                  autoFocus
                  disabled={pinSetupLoading}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Confirm PIN</label>
                <input
                  type="password"
                  inputMode="numeric"
                  value={confirmPin}
                  onChange={(e) => { if (/^\d*$/.test(e.target.value) && e.target.value.length <= 8) setConfirmPin(e.target.value); }}
                  className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-xl tracking-[0.5em]"
                  placeholder="Confirm PIN"
                  disabled={pinSetupLoading}
                />
              </div>

              {pinSetupError && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{pinSetupError}</span>
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => { setShowPinSetup(false); setNewPin(""); setConfirmPin(""); setPinSetupError(""); }}
                  className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={pinSetupLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={pinSetupLoading || newPin.length < 4}
                  className="flex-1 bg-green-600 text-white px-4 py-2.5 rounded-lg hover:bg-green-700 transition-colors disabled:opacity-60 flex items-center justify-center gap-2"
                >
                  <KeyRound className="w-4 h-4" />
                  {pinSetupLoading ? "Setting..." : "Set PIN"}
                </button>
              </div>

              <p className="text-xs text-gray-400 text-center">
                Your PIN encrypts the passphrase locally for quick access. After 5 wrong attempts, the PIN is removed.
              </p>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
