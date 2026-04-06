import { useState, useEffect, useCallback, useRef } from "react";
import { NavLink, Outlet, useNavigate } from "react-router";
import {
  Server, ScrollText, Monitor, Settings, LogOut, Info,
  Lock, Play, Eye, EyeOff, AlertCircle, CheckCircle,
  Shield, Sparkles, Wifi, WifiOff, Circle, RotateCcw,
  KeyRound, Hash, ArrowLeft, Trash2, ShieldAlert, Timer,
  Users, Globe,
} from "lucide-react";
import { api, VAULT_LOCKED_EVENT, type Status } from "../api";

type VaultState = "loading" | "uninitialized" | "locked" | "unlocked";

export function Layout() {
  const navigate = useNavigate();
  const [vaultState, setVaultState] = useState<VaultState>("loading");

  // Passphrase dialog state
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [passphraseMode, setPassphraseMode] = useState<"setup" | "unlock">("unlock");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  // Multi-admin state
  const [multiAdmin, setMultiAdmin] = useState(false);
  const [adminId, setAdminId] = useState("owner");

  // PIN state
  const [pinSet, setPinSet] = useState(false);
  const [unlockMode, setUnlockMode] = useState<"pin" | "passphrase">("pin");
  const [pin, setPin] = useState(["", "", "", "", "", ""]);
  const [pinLength, setPinLength] = useState(6);
  const pinRefs = useRef<(HTMLInputElement | null)[]>([]);

  // PIN setup dialog (shown after successful unlock)
  const [showPinSetup, setShowPinSetup] = useState(false);
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [pinSetupError, setPinSetupError] = useState("");
  const [pinSetupLoading, setPinSetupLoading] = useState(false);

  // Post-init success
  const [initResult, setInitResult] = useState<{
    server_ip: string; subnet: string; public_key: string; endpoint: string | null;
    warnings?: string[] | null;
  } | null>(null);

  // Server status for sidebar indicator
  const [serverStatus, setServerStatus] = useState<Status | null>(null);
  const [apiOnline, setApiOnline] = useState(false);

  // ── Vault info probe ─────────────────────────────────────────────────────
  const probeVault = useCallback(async () => {
    try {
      const info = await api.vaultInfo();
      if (!info.initialized) {
        setVaultState("uninitialized");
      } else if (info.locked) {
        setVaultState("locked");
      } else {
        setVaultState("unlocked");
      }
      setPinSet(info.pin_set ?? false);
      setUnlockMode(info.pin_set ? "pin" : "passphrase");
      setMultiAdmin(info.multi_admin ?? false);
    } catch {
      setVaultState("locked");
    }
  }, []);

  useEffect(() => { probeVault(); }, [probeVault]);

  // ── Server status polling (for sidebar indicator) ──────────────────────────
  useEffect(() => {
    if (vaultState !== "unlocked") { setApiOnline(false); setServerStatus(null); return; }
    setApiOnline(true);
    const poll = async () => {
      try {
        const s = await api.status();
        setServerStatus(s);
        setApiOnline(true);
      } catch {
        setServerStatus(null);
      }
    };
    poll();
    const id = window.setInterval(poll, 5000);
    return () => clearInterval(id);
  }, [vaultState]);

  // ── Admin status polling ──────────────────────────────────────────────────
  useEffect(() => {
    if (vaultState !== "unlocked") { setAdminActive(false); setAdminExpiresIn(0); return; }
    const poll = async () => {
      try {
        const s = await api.adminStatus();
        setAdminActive(s.active);
        setAdminExpiresIn(s.expires_in);
        if (!s.active) navigate("/");   // redirect away from /admin if expired
      } catch { /* ignore */ }
    };
    poll();
    const id = window.setInterval(poll, 30_000);
    return () => clearInterval(id);
  }, [vaultState, navigate]);

  // ── Listen for 401 events from any page's API calls ───────────────────────
  useEffect(() => {
    const handler = () => {
      try { localStorage.removeItem("vault_users"); } catch { /* ignore */ }
      setVaultState("locked");
      setInitResult(null);
      setAdminActive(false);
    };
    window.addEventListener(VAULT_LOCKED_EVENT, handler);
    return () => window.removeEventListener(VAULT_LOCKED_EVENT, handler);
  }, []);

  // ── PIN input handlers ───────────────────────────────────────────────────
  const handlePinChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    const newPinArr = [...pin];
    newPinArr[index] = value.slice(-1);
    setPin(newPinArr);
    setAuthError("");

    if (value && index < pinLength - 1) {
      pinRefs.current[index + 1]?.focus();
    }

    // Auto-submit when all digits are filled
    const fullPin = newPinArr.join("");
    if (fullPin.length === pinLength && newPinArr.every(d => d !== "")) {
      handlePinUnlock(fullPin);
    }
  };

  const handlePinKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !pin[index] && index > 0) {
      pinRefs.current[index - 1]?.focus();
    }
  };

  const handlePinPaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, pinLength);
    if (pasted.length > 0) {
      const newPinArr = [...pin];
      for (let i = 0; i < pinLength; i++) {
        newPinArr[i] = pasted[i] || "";
      }
      setPin(newPinArr);
      if (pasted.length === pinLength) {
        handlePinUnlock(pasted);
      } else {
        pinRefs.current[pasted.length]?.focus();
      }
    }
  };

  const handlePinUnlock = async (pinValue: string) => {
    setAuthLoading(true);
    setAuthError("");
    try {
      await api.unlockPin(pinValue);
      setVaultState("unlocked");
      setPin(["", "", "", "", "", ""]);
      navigate("/");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Wrong PIN";
      setAuthError(msg);
      setPin(["", "", "", "", "", ""]);
      pinRefs.current[0]?.focus();
      // If PIN was removed (too many attempts), switch to passphrase mode
      if (msg.includes("removed") || msg.includes("passphrase")) {
        setPinSet(false);
        setUnlockMode("passphrase");
      }
    } finally {
      setAuthLoading(false);
    }
  };

  // ── Auth handlers ─────────────────────────────────────────────────────────
  const openStartDialog = () => {
    if (vaultState === "locked" && pinSet) {
      setUnlockMode("pin");
      setPin(["", "", "", "", "", ""]);
      setAuthError("");
      setShowPassphrase(true);
      setTimeout(() => pinRefs.current[0]?.focus(), 100);
    } else {
      setUnlockMode("passphrase");
      setPassphraseMode(vaultState === "uninitialized" ? "setup" : "unlock");
      setPassphrase("");
      setConfirmPassphrase("");
      setAuthError("");
      setShowPassphrase(true);
    }
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");

    if (passphraseMode === "setup") {
      if (passphrase.length < 12) { setAuthError("Passphrase must be at least 12 characters"); return; }
      if (passphrase !== confirmPassphrase) { setAuthError("Passphrases do not match"); return; }
    }

    setAuthLoading(true);
    try {
      if (passphraseMode === "setup") {
        const result = await api.init(passphrase);
        setInitResult({
          server_ip: result.server_ip,
          subnet: result.subnet,
          public_key: result.public_key,
          endpoint: result.endpoint,
          warnings: result.warnings,
        });
      } else {
        await api.unlock(passphrase, multiAdmin ? adminId : undefined);
      }
      setShowPassphrase(false);
      setVaultState("unlocked");
      navigate("/");

      // Offer PIN setup if no PIN is set yet
      if (!pinSet) {
        setTimeout(() => setShowPinSetup(true), 500);
      }
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setPassphrase("");
      setConfirmPassphrase("");
      setAuthLoading(false);
    }
  };

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

  const handleAdminAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdminAuthError("");
    setAdminAuthLoading(true);
    try {
      const res = await api.adminAuthenticate(adminPassword);
      setAdminActive(true);
      setAdminExpiresIn(res.expires_in);
      setShowAdminAuth(false);
      setAdminPassword("");
      navigate("/admin");
    } catch (err) {
      setAdminAuthError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setAdminPassword("");
      setAdminAuthLoading(false);
    }
  };

  const handleAdminDeactivate = async () => {
    try { await api.adminDeactivate(); } catch { /* ignore */ }
    setAdminActive(false);
    setAdminExpiresIn(0);
    navigate("/");
  };

  const handleLock = async () => {
    try { await api.lock(); } catch { /* ignore */ }
    try { localStorage.removeItem("vault_users"); } catch { /* ignore */ }
    setAdminActive(false);
    setVaultState("locked");
    setInitResult(null);
    navigate("/");
  };

  // Admin mode state
  const [adminActive, setAdminActive]           = useState(false);
  const [adminExpiresIn, setAdminExpiresIn]     = useState(0);
  const [showAdminAuth, setShowAdminAuth]       = useState(false);
  const [adminPassword, setAdminPassword]       = useState("");
  const [showAdminPw, setShowAdminPw]           = useState(false);
  const [adminAuthError, setAdminAuthError]     = useState("");
  const [adminAuthLoading, setAdminAuthLoading] = useState(false);

  // Fresh start
  const [showFreshStart, setShowFreshStart] = useState(false);
  const [freshStartLoading, setFreshStartLoading] = useState(false);

  const handleFreshStart = async () => {
    setFreshStartLoading(true);
    try {
      await api.freshStart();
      setShowFreshStart(false);
      setVaultState("uninitialized");
      setPinSet(false);
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Fresh start failed");
    } finally {
      setFreshStartLoading(false);
    }
  };

  const navItems = [
    { to: "/", label: "Dashboard", icon: Server, end: true },
    { to: "/clients", label: "Clients", icon: Monitor },
    { to: "/audit-log", label: "Audit Log", icon: ScrollText },
    { to: "/security", label: "Security", icon: Shield },
    { to: "/admins", label: "Admins", icon: Users },
    { to: "/dns", label: "DNS", icon: Globe },
    { to: "/settings", label: "Settings", icon: Settings },
    ...(adminActive ? [{ to: "/admin", label: "Admin Panel", icon: ShieldAlert, end: false }] : []),
    { to: "/about", label: "About", icon: Info },
  ];

  // ── Loading state ─────────────────────────────────────────────────────────
  if (vaultState === "loading") {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-950 to-slate-900 flex items-center justify-center">
        <div className="flex flex-col items-center gap-6 animate-fade-in">
          <div className="w-24 h-24 bg-blue-600/20 rounded-3xl flex items-center justify-center border border-blue-500/30 shadow-lg shadow-blue-500/10">
            <Shield className="w-14 h-14 text-blue-400" />
          </div>
          <div className="text-center">
            <h1 className="text-3xl font-bold text-white tracking-tight">WireSeal</h1>
            <p className="text-blue-300/70 text-sm mt-1">Secure WireGuard Management</p>
          </div>
          <div className="flex items-center gap-2 text-blue-300/60 text-sm">
            <div className="w-4 h-4 border-2 border-blue-400/40 border-t-blue-400 rounded-full animate-spin" />
            <span>Connecting to server...</span>
          </div>
        </div>
      </div>
    );
  }

  // ── Locked / Uninitialized — full-screen welcome screen ──────────────────
  if (vaultState === "locked" || vaultState === "uninitialized") {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-950 to-slate-900 flex items-center justify-center">
        <div className="flex flex-col items-center text-center gap-8 max-w-lg w-full mx-4 animate-fade-in">
          {/* Logo */}
          <div className="w-24 h-24 bg-blue-600/20 rounded-3xl flex items-center justify-center border border-blue-500/30 shadow-lg shadow-blue-500/10">
            <Shield className="w-14 h-14 text-blue-400" />
          </div>

          {/* Welcome text */}
          <div>
            <div className="flex items-center justify-center gap-2 mb-2">
              <Sparkles className="w-5 h-5 text-amber-400" />
              <span className="text-amber-400/80 text-sm font-medium tracking-wide uppercase">
                {vaultState === "uninitialized" ? "Welcome" : "Welcome back"}
              </span>
              <Sparkles className="w-5 h-5 text-amber-400" />
            </div>
            <h1 className="text-4xl font-bold text-white tracking-tight mb-2">WireSeal</h1>
            <p className="text-blue-300/60 text-sm mb-4">Secure WireGuard Management</p>
            <h2 className="text-lg font-semibold text-blue-200 mb-2">
              {vaultState === "uninitialized" ? "Let's get you set up" : "Your server is ready"}
            </h2>
            <p className="text-blue-300/50 max-w-sm mx-auto text-sm leading-relaxed">
              {vaultState === "uninitialized"
                ? "Create a vault passphrase to encrypt your keys and configs. Everything is secured with dual-layer AEAD encryption."
                : pinSet
                  ? "Enter your PIN to quickly unlock and start."
                  : "Unlock the vault with your passphrase to start managing your WireGuard network."}
            </p>
          </div>

          {/* CTA button */}
          <button
            onClick={openStartDialog}
            className="flex items-center gap-3 px-8 py-3.5 bg-blue-600 text-white text-lg font-medium rounded-xl hover:bg-blue-500 transition-all shadow-lg shadow-blue-600/30 hover:shadow-blue-500/40 hover:scale-[1.02] active:scale-[0.98]"
          >
            {vaultState === "uninitialized" ? <Play className="w-6 h-6" /> : pinSet ? <KeyRound className="w-6 h-6" /> : <Play className="w-6 h-6" />}
            {vaultState === "uninitialized" ? "Get Started" : pinSet ? "Enter PIN" : "Unlock & Start"}
          </button>

          {/* Fresh Start option */}
          {vaultState === "locked" && (
            <button
              onClick={() => setShowFreshStart(true)}
              className="flex items-center gap-2 text-blue-400/50 hover:text-blue-300 text-sm transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Fresh Start
            </button>
          )}

          {/* Security badge */}
          <div className="flex items-center gap-2 text-blue-400/40 text-xs mt-2">
            <Lock className="w-3.5 h-3.5" />
            <span>ChaCha20-Poly1305 + AES-256-GCM-SIV + Argon2id</span>
          </div>
        </div>

        {/* Fresh Start confirmation dialog */}
        {showFreshStart && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md mx-4">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                  <RotateCcw className="w-6 h-6 text-red-600" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">Fresh Start</h2>
                  <p className="text-sm text-gray-500">This action cannot be undone</p>
                </div>
              </div>
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
                <p className="text-red-800 text-sm font-medium mb-2">This will permanently destroy:</p>
                <ul className="text-red-700 text-sm space-y-1 list-disc list-inside">
                  <li>All encryption keys and vault data</li>
                  <li>All client configurations</li>
                  <li>Server WireGuard config</li>
                  <li>Audit log history</li>
                </ul>
              </div>
              {authError && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 border border-red-200 p-3 rounded-lg mb-4">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{authError}</span>
                </div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={() => { setShowFreshStart(false); setAuthError(""); }}
                  className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={freshStartLoading}
                >
                  Cancel
                </button>
                <button
                  onClick={handleFreshStart}
                  disabled={freshStartLoading}
                  className="flex-1 bg-red-600 text-white px-4 py-2.5 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-60"
                >
                  {freshStartLoading ? "Resetting..." : "Confirm Fresh Start"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Unlock dialog — PIN or Passphrase */}
        {showPassphrase && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md mx-4">
              {/* PIN unlock mode */}
              {unlockMode === "pin" && vaultState === "locked" && (
                <>
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                      <KeyRound className="w-6 h-6 text-blue-700" />
                    </div>
                    <div>
                      <h2 className="text-xl font-semibold text-gray-900">Quick Unlock</h2>
                      <p className="text-sm text-gray-500">Enter your PIN to unlock</p>
                    </div>
                  </div>

                  {/* PIN input boxes */}
                  <div className="flex justify-center gap-3 mb-6" onPaste={handlePinPaste}>
                    {pin.slice(0, pinLength).map((digit, i) => (
                      <input
                        key={i}
                        ref={(el) => { pinRefs.current[i] = el; }}
                        type="password"
                        inputMode="numeric"
                        maxLength={1}
                        value={digit}
                        onChange={(e) => handlePinChange(i, e.target.value)}
                        onKeyDown={(e) => handlePinKeyDown(i, e)}
                        disabled={authLoading}
                        className="w-12 h-14 text-center text-2xl font-bold border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                        autoFocus={i === 0}
                      />
                    ))}
                  </div>

                  {authLoading && (
                    <div className="flex items-center justify-center gap-2 text-blue-600 text-sm mb-4">
                      <div className="w-4 h-4 border-2 border-blue-400/40 border-t-blue-400 rounded-full animate-spin" />
                      <span>Unlocking...</span>
                    </div>
                  )}

                  {authError && (
                    <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg mb-4">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />
                      <span>{authError}</span>
                    </div>
                  )}

                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => { setShowPassphrase(false); setAuthError(""); setPin(["", "", "", "", "", ""]); }}
                      className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={() => { setUnlockMode("passphrase"); setPassphraseMode("unlock"); setAuthError(""); }}
                      className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-sm flex items-center justify-center gap-2"
                    >
                      <Lock className="w-4 h-4" />
                      Use Passphrase
                    </button>
                  </div>
                </>
              )}

              {/* Passphrase unlock/setup mode */}
              {(unlockMode === "passphrase" || vaultState === "uninitialized") && (
                <>
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                      <Lock className="w-6 h-6 text-blue-700" />
                    </div>
                    <div>
                      <h2 className="text-xl font-semibold text-gray-900">
                        {passphraseMode === "setup" ? "Initialize Vault" : "Unlock Vault"}
                      </h2>
                      <p className="text-sm text-gray-500">
                        {passphraseMode === "setup"
                          ? "Create a passphrase to encrypt your vault"
                          : "Enter your passphrase to unlock and start"}
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleAuth} className="space-y-4">
                    {multiAdmin && passphraseMode === "unlock" && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">Admin ID</label>
                        <input
                          type="text"
                          value={adminId}
                          onChange={e => setAdminId(e.target.value)}
                          className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          placeholder="owner"
                          disabled={authLoading}
                        />
                      </div>
                    )}
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Passphrase</label>
                      <div className="relative">
                        <input
                          type={showPw ? "text" : "password"}
                          value={passphrase}
                          onChange={(e) => setPassphrase(e.target.value)}
                          className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          placeholder={passphraseMode === "setup" ? "Min. 12 characters" : "Enter your passphrase"}
                          autoFocus
                          disabled={authLoading}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPw(!showPw)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                        >
                          {showPw ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                        </button>
                      </div>
                    </div>

                    {passphraseMode === "setup" && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">Confirm Passphrase</label>
                        <input
                          type={showPw ? "text" : "password"}
                          value={confirmPassphrase}
                          onChange={(e) => setConfirmPassphrase(e.target.value)}
                          className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          placeholder="Confirm passphrase"
                          disabled={authLoading}
                        />
                      </div>
                    )}

                    {authError && (
                      <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                        <AlertCircle className="w-4 h-4 flex-shrink-0" />
                        <span>{authError}</span>
                      </div>
                    )}

                    <div className="flex gap-3 pt-1">
                      <button
                        type="button"
                        onClick={() => {
                          if (pinSet && vaultState === "locked") {
                            setUnlockMode("pin");
                            setAuthError("");
                            setPin(["", "", "", "", "", ""]);
                            setTimeout(() => pinRefs.current[0]?.focus(), 100);
                          } else {
                            setShowPassphrase(false); setAuthError(""); setPassphrase(""); setConfirmPassphrase("");
                          }
                        }}
                        className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors flex items-center justify-center gap-2"
                        disabled={authLoading}
                      >
                        {pinSet && vaultState === "locked" ? (
                          <><ArrowLeft className="w-4 h-4" /> Back to PIN</>
                        ) : "Cancel"}
                      </button>
                      <button
                        type="submit"
                        disabled={authLoading}
                        className="flex-1 bg-blue-600 text-white px-4 py-2.5 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60 flex items-center justify-center gap-2"
                      >
                        <Play className="w-4 h-4" />
                        {authLoading
                          ? (passphraseMode === "setup" ? "Initializing..." : "Starting...")
                          : (passphraseMode === "setup" ? "Initialize & Start" : "Start Server")}
                      </button>
                    </div>

                    {passphraseMode === "setup" && (
                      <p className="text-xs text-gray-400 text-center">
                        Your passphrase encrypts all vault data using dual-layer AEAD encryption. It cannot be recovered.
                      </p>
                    )}
                  </form>
                </>
              )}
            </div>
          </div>
        )}

        {/* PIN setup dialog (after successful passphrase unlock, if no PIN set) */}
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
                    Skip
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

  // ── Unlocked — show sidebar + page content ──────────────────────────────
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-60 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-5 border-b border-gray-100">
          <h1 className="font-bold text-lg text-gray-900 tracking-tight">WireSeal</h1>
          <p className="text-xs text-gray-400 mt-0.5">WireGuard Dashboard</p>
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
                    ? "bg-blue-50 text-blue-700 font-medium"
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
              <Circle className={`w-2.5 h-2.5 fill-current ${apiOnline ? "text-green-500" : "text-red-500"}`} />
              <span className="text-xs text-gray-500">API Server</span>
            </div>
            <span className={`text-xs font-medium ${apiOnline ? "text-green-600" : "text-red-500"}`}>
              {apiOnline ? "Online" : "Offline"}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {serverStatus?.running
                ? <Wifi className="w-3 h-3 text-green-500" />
                : <WifiOff className="w-3 h-3 text-gray-400" />}
              <span className="text-xs text-gray-500">WireGuard</span>
            </div>
            <span className={`text-xs font-medium ${serverStatus?.running ? "text-green-600" : "text-gray-400"}`}>
              {serverStatus?.running ? "Running" : "Stopped"}
            </span>
          </div>
          {/* PIN indicator */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRound className={`w-3 h-3 ${pinSet ? "text-green-500" : "text-gray-400"}`} />
              <span className="text-xs text-gray-500">Quick PIN</span>
            </div>
            {pinSet ? (
              <button
                onClick={async () => { await api.removePin(); setPinSet(false); }}
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

          {/* Admin mode indicator */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className={`w-3 h-3 ${adminActive ? "text-red-500" : "text-gray-400"}`} />
              <span className="text-xs text-gray-500">Admin Mode</span>
            </div>
            {adminActive ? (
              <div className="flex items-center gap-1">
                <span className="text-xs text-red-500 flex items-center gap-0.5">
                  <Timer className="w-3 h-3" />
                  {Math.ceil(adminExpiresIn / 60)}m
                </span>
                <button
                  onClick={handleAdminDeactivate}
                  className="text-xs text-gray-400 hover:text-gray-600 ml-1 transition-colors"
                  title="Deactivate admin mode"
                >
                  ×
                </button>
              </div>
            ) : (
              <button
                onClick={() => { setAdminAuthError(""); setAdminPassword(""); setShowAdminAuth(true); }}
                className="text-xs text-red-500 hover:text-red-600 transition-colors"
              >
                Activate
              </button>
            )}
          </div>
        </div>

        <div className="p-2 border-t border-gray-100">
          <button
            onClick={handleLock}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg w-full text-gray-500 hover:bg-gray-100 hover:text-gray-700 transition-colors text-sm"
          >
            <LogOut className="w-4 h-4" />
            <span>Lock Vault</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="ml-60 p-8">
        {/* Post-init success banner (shown on any page after first init) */}
        {initResult && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-6">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center flex-shrink-0">
                <CheckCircle className="w-7 h-7 text-green-600" />
              </div>
              <div className="flex-1">
                <h2 className="text-xl font-semibold text-green-900 mb-1">Server Initialized Successfully</h2>
                <p className="text-green-700 text-sm mb-4">Your WireSeal vault has been created and the WireGuard tunnel is configured.</p>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="text-green-600">Server IP:</span>{" "}
                    <span className="font-mono text-green-900">{initResult.server_ip}</span>
                  </div>
                  <div>
                    <span className="text-green-600">Subnet:</span>{" "}
                    <span className="font-mono text-green-900">{initResult.subnet}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-green-600">Public Key:</span>{" "}
                    <span className="font-mono text-green-900 text-xs break-all">{initResult.public_key}</span>
                  </div>
                  {initResult.endpoint && (
                    <div className="col-span-2">
                      <span className="text-green-600">Endpoint:</span>{" "}
                      <span className="font-mono text-green-900">{initResult.endpoint}</span>
                    </div>
                  )}
                </div>
                {initResult.warnings && initResult.warnings.length > 0 && (
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 mt-3">
                    <p className="text-yellow-800 text-sm font-medium mb-1">Setup warnings:</p>
                    <ul className="text-yellow-700 text-xs space-y-1 list-disc list-inside">
                      {initResult.warnings.map((w, i) => <li key={i}>{w}</li>)}
                    </ul>
                    <p className="text-yellow-600 text-xs mt-2">
                      The vault was created successfully. Run WireSeal as Administrator to complete WireGuard setup.
                    </p>
                  </div>
                )}
                <p className="text-green-600 text-sm mt-4">Head to the <strong>Clients</strong> page to add your first VPN client.</p>
              </div>
              <button
                onClick={() => setInitResult(null)}
                className="text-green-400 hover:text-green-600 text-lg leading-none"
                title="Dismiss"
              >&times;</button>
            </div>
          </div>
        )}
        <Outlet />
      </main>

      {/* Admin mode authentication dialog */}
      {showAdminAuth && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md mx-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <ShieldAlert className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-gray-900">Activate Admin Mode</h2>
                <p className="text-sm text-gray-500">Enter your root / sudo password</p>
              </div>
            </div>

            <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 mb-5 text-sm text-amber-800">
              Admin mode grants full, unrestricted system access for 30 minutes.
              All actions are audit-logged.
            </div>

            <form onSubmit={handleAdminAuth} className="space-y-4">
              <div className="relative">
                <input
                  type={showAdminPw ? "text" : "password"}
                  value={adminPassword}
                  onChange={e => setAdminPassword(e.target.value)}
                  placeholder="Root / sudo password"
                  className="w-full px-4 py-2.5 pr-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
                  autoFocus
                  disabled={adminAuthLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowAdminPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showAdminPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {adminAuthError && (
                <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{adminAuthError}</span>
                </div>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => { setShowAdminAuth(false); setAdminPassword(""); setAdminAuthError(""); }}
                  className="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                  disabled={adminAuthLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={adminAuthLoading || !adminPassword}
                  className="flex-1 bg-red-600 text-white px-4 py-2.5 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-60 flex items-center justify-center gap-2"
                >
                  <ShieldAlert className="w-4 h-4" />
                  {adminAuthLoading ? "Verifying..." : "Activate"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* PIN setup dialog (available while unlocked) */}
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
                  {pinSet ? "Cancel" : "Skip"}
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
