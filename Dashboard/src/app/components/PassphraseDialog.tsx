import { useState } from "react";
import { Lock, Eye, EyeOff, AlertCircle } from "lucide-react";

interface PassphraseDialogProps {
  mode: "setup" | "unlock";
  error?: string;
  onSuccess: (passphrase: string) => void;
}

export function PassphraseDialog({ mode, error: externalError, onSuccess }: PassphraseDialogProps) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [localError, setLocalError] = useState("");
  const [loading, setLoading] = useState(false);

  const error = localError || externalError || "";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError("");

    if (mode === "setup") {
      if (passphrase.length < 12) {
        setLocalError("Passphrase must be at least 12 characters");
        return;
      }
      if (passphrase !== confirmPassphrase) {
        setLocalError("Passphrases do not match");
        return;
      }
    }

    setLoading(true);
    try {
      await onSuccess(passphrase);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-8 w-full max-w-md">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
            <Lock className="w-6 h-6 text-blue-700" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900">
              {mode === "setup" ? "Initialize WireSeal Vault" : "Unlock Vault"}
            </h2>
            <p className="text-sm text-gray-500">
              {mode === "setup"
                ? "Create a strong passphrase to protect your vault"
                : "Enter your passphrase to continue"}
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Passphrase
            </label>
            <div className="relative">
              <input
                type={showPassphrase ? "text" : "password"}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter passphrase"
                autoFocus
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassphrase(!showPassphrase)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
              >
                {showPassphrase ? (
                  <EyeOff className="w-5 h-5" />
                ) : (
                  <Eye className="w-5 h-5" />
                )}
              </button>
            </div>
          </div>

          {mode === "setup" && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Confirm Passphrase
              </label>
              <input
                type={showPassphrase ? "text" : "password"}
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Confirm passphrase"
                disabled={loading}
              />
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 p-3 rounded-lg">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-60"
          >
            {loading
              ? mode === "setup" ? "Initializing…" : "Unlocking…"
              : mode === "setup" ? "Initialize Vault" : "Unlock"}
          </button>
        </form>

        {mode === "setup" && (
          <p className="text-xs text-gray-500 mt-4">
            Your passphrase encrypts all vault data with dual-layer AEAD encryption. Make sure to
            remember it — it cannot be recovered.
          </p>
        )}
      </div>
    </div>
  );
}
