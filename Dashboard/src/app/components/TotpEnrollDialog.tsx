/**
 * TotpEnrollDialog — 3-step TOTP enrollment wizard.
 *
 * Step 1 (QR): Display otpauth:// URI + base32 secret for manual entry.
 *              A QR image is rendered via the browser's built-in fetch to
 *              api.qrserver.com (works on LAN too) with a plain-text
 *              fallback that shows the URI and secret.
 * Step 2 (Verify): User enters the 6-digit code from their authenticator.
 * Step 3 (Backup codes): Display the 8 single-use recovery codes.
 */

import { useState, useEffect } from "react";
import { AlertTriangle, CheckCircle, Copy, X, ShieldCheck } from "lucide-react";
import { api } from "../api";

interface Props {
  onClose: () => void;
  onEnrolled: () => void;
}

type Step = "qr" | "verify" | "backup";

export function TotpEnrollDialog({ onClose, onEnrolled }: Props) {
  const [step, setStep] = useState<Step>("qr");
  const [otpauthUri, setOtpauthUri] = useState("");
  const [secretB32, setSecretB32] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [qrImageError, setQrImageError] = useState(false);

  // Step 1: Begin enrollment on mount
  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        const res = await api.totpEnrollBegin();
        setOtpauthUri(res.otpauth_uri);
        setSecretB32(res.secret_b32);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to begin enrollment");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // Step 2: Confirm with TOTP code
  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await api.totpEnrollConfirm(totpCode);
      setBackupCodes(res.backup_codes);
      setStep("backup");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Verification failed";
      setError(msg === "invalid_code" ? "Invalid code — check your authenticator and try again." : msg);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyAll = async () => {
    try {
      await navigator.clipboard.writeText(backupCodes.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Clipboard API not available in some embedded contexts
    }
  };

  const handleCopySecret = async () => {
    try {
      await navigator.clipboard.writeText(secretB32);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  // Build QR image URL via api.qrserver.com (free, no API key, works on LAN)
  // Fallback: show URI text if image fails to load.
  const qrImageUrl = otpauthUri
    ? `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthUri)}`
    : "";

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-indigo-700" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Enable Two-Factor Auth</h2>
              <p className="text-xs text-gray-500">
                {step === "qr" && "Step 1 of 3 — Scan QR code"}
                {step === "verify" && "Step 2 of 3 — Verify code"}
                {step === "backup" && "Step 3 of 3 — Save backup codes"}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Step 1: QR Code */}
        {step === "qr" && (
          <div className="space-y-4">
            <p className="text-sm text-gray-600">
              Scan this QR code with your authenticator app (Google Authenticator, Aegis, Bitwarden, etc.)
            </p>
            {loading ? (
              <div className="flex justify-center py-8">
                <div className="w-8 h-8 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : (
              <>
                {/* QR image — with fallback to text */}
                <div className="flex justify-center">
                  {!qrImageError && qrImageUrl ? (
                    <img
                      src={qrImageUrl}
                      alt="TOTP QR Code"
                      width={200}
                      height={200}
                      className="rounded-lg border border-gray-200"
                      onError={() => setQrImageError(true)}
                    />
                  ) : (
                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-center">
                      <p className="text-xs text-gray-500 mb-2">QR image unavailable (no internet).</p>
                      <p className="text-xs text-gray-500">Use manual entry below.</p>
                    </div>
                  )}
                </div>

                {/* Manual entry secret */}
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-xs font-medium text-gray-500 mb-1">Manual entry secret</p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-xs font-mono text-gray-800 break-all">
                      {secretB32}
                    </code>
                    <button
                      type="button"
                      onClick={handleCopySecret}
                      className="text-gray-400 hover:text-gray-600 flex-shrink-0"
                      title="Copy secret"
                    >
                      {copied ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </>
            )}

            {error && (
              <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-sm"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => { setStep("verify"); setError(""); }}
                disabled={!otpauthUri || loading}
                className="flex-1 bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors text-sm disabled:opacity-60"
              >
                Next
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Verify code */}
        {step === "verify" && (
          <form onSubmit={handleConfirm} className="space-y-4">
            <p className="text-sm text-gray-600">
              Enter the 6-digit code from your authenticator app to confirm enrollment.
            </p>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Verification code
              </label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                pattern="[0-9]{6}"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                className="w-full px-4 py-3 text-center text-2xl font-mono tracking-widest border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="000000"
                autoFocus
                required
                disabled={loading}
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
                onClick={() => { setStep("qr"); setError(""); setTotpCode(""); }}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-sm"
                disabled={loading}
              >
                Back
              </button>
              <button
                type="submit"
                disabled={totpCode.length !== 6 || loading}
                className="flex-1 bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors text-sm disabled:opacity-60"
              >
                {loading ? "Verifying…" : "Confirm"}
              </button>
            </div>
          </form>
        )}

        {/* Step 3: Backup codes */}
        {step === "backup" && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-green-700 bg-green-50 rounded-lg p-3">
              <CheckCircle className="w-5 h-5 flex-shrink-0" />
              <p className="text-sm font-medium">Two-factor authentication enabled!</p>
            </div>

            <div>
              <p className="text-sm text-gray-600 mb-3">
                Save these 8 backup codes in a secure location. Each code can only be used once
                to unlock without your authenticator device.
              </p>
              <div className="grid grid-cols-2 gap-2 bg-gray-50 rounded-lg p-4 border border-gray-200">
                {backupCodes.map((code) => (
                  <code
                    key={code}
                    className="text-xs font-mono text-gray-800 bg-white border border-gray-200 rounded px-2 py-1 text-center tracking-wider"
                  >
                    {code}
                  </code>
                ))}
              </div>
            </div>

            <div className="flex gap-3">
              <button
                type="button"
                onClick={handleCopyAll}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-sm flex items-center justify-center gap-2"
              >
                {copied ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="w-4 h-4" />
                    Copy All
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => { onEnrolled(); onClose(); }}
                className="flex-1 bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors text-sm"
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
