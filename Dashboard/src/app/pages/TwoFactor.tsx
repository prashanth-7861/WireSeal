import { useEffect, useState } from "react";
import {
  ShieldCheck, ShieldOff, KeyRound, Copy, CheckCircle,
  AlertTriangle, Smartphone, ChevronDown, ChevronRight,
} from "lucide-react";
import { api } from "../api";
import type { AdminInfo } from "../api";
import { AdminRoleBadge } from "../components/AdminRoleBadge";
import { TotpEnrollDialog } from "../components/TotpEnrollDialog";

let _cache: AdminInfo[] | null = null;

export function TwoFactor() {
  const [admins, setAdmins] = useState<AdminInfo[]>(_cache ?? []);
  const [loading, setLoading] = useState(_cache === null);
  const [enrolling, setEnrolling] = useState(false);
  const [enrollingId, setEnrollingId] = useState<string | null>(null);
  const [confirmingDisable, setConfirmingDisable] = useState(false);
  const [disablePass, setDisablePass] = useState("");
  const [disableError, setDisableError] = useState("");
  const [disabling, setDisabling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const currentId = api.getCurrentAdminId();
  const me = admins.find(a => a.id === currentId);
  const enrolled = me?.totp_enrolled ?? false;

  const load = () => {
    setLoading(true); setError(null);
    api.listAdmins()
      .then(d => { _cache = d.admins; setAdmins(d.admins); })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  };

  const handleDisable = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!confirmingDisable) { setConfirmingDisable(true); return; }
    setDisabling(true); setDisableError("");
    try {
      await api.totpDisable(undefined, disablePass);
      setConfirmingDisable(false); setDisablePass("");
      load();
    } catch (err: unknown) {
      setDisableError(err instanceof Error ? err.message : "Failed");
    } finally { setDisabling(false); }
  };

  useEffect(() => { load(); }, []);

  if (loading) return (
    <div className="p-6 flex items-center gap-3 text-gray-500">
      <div className="w-5 h-5 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
      <span>Loading...</span>
    </div>
  );

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center">
          <Smartphone className="w-6 h-6 text-indigo-700" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Two-Factor Authentication</h1>
          <p className="text-sm text-gray-500">Add an extra layer of security to your account</p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-red-600 text-sm bg-red-50 border border-red-200 rounded-lg p-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!error && (
        <>
          {/* Status card */}
          <div className={`rounded-xl border-2 p-6 ${enrolled ? "border-green-300 bg-green-50/50" : "border-amber-200 bg-amber-50/50"}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-4">
                <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${enrolled ? "bg-green-100" : "bg-amber-100"}`}>
                  {enrolled ? <ShieldCheck className="w-8 h-8 text-green-700" /> : <ShieldOff className="w-8 h-8 text-amber-600" />}
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-gray-900">
                    {enrolled ? "Protected" : "Not Protected"}
                  </h2>
                  <p className="text-sm text-gray-600 mt-0.5">
                    {enrolled
                      ? "Your account is secured with two-factor authentication."
                      : "Your account is protected by passphrase only."}
                  </p>
                  {!enrolled && (
                    <ul className="text-sm text-gray-500 mt-3 space-y-1">
                      <li className="flex items-center gap-2">· Authenticator code required at vault unlock</li>
                      <li className="flex items-center gap-2">· Authenticator code required to reveal client configs</li>
                      <li className="flex items-center gap-2">· Authenticator code required for destructive actions</li>
                    </ul>
                  )}
                </div>
              </div>
              <div className="flex-shrink-0">
                {enrolled ? (
                  <button onClick={handleDisable} className="px-4 py-2 text-sm border border-red-300 text-red-700 rounded-lg hover:bg-red-50 transition-colors">
                    Disable
                  </button>
                ) : (
                  <button onClick={() => { setEnrolling(true); setEnrollingId(currentId); }} className="px-4 py-2 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors">
                    Enable
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Backup codes */}
          <div className="border rounded-xl p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <KeyRound className="w-5 h-5 text-gray-500 mt-0.5" />
                <div>
                  <h2 className="text-sm font-semibold text-gray-800">Recovery Codes</h2>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Use a backup code to unlock if you lose access to your authenticator app.
                    Each code can be used once.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowBackupCodes(!showBackupCodes)}
                disabled={!enrolled}
                className="px-3 py-1.5 text-xs border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-40 flex-shrink-0"
              >
                {showBackupCodes ? "Hide" : "View"}
              </button>
            </div>
            {showBackupCodes && (
              <div className="mt-3 bg-gray-50 border rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-700">Remaining codes</span>
                  <span className={`text-sm font-semibold ${(me?.backup_codes_remaining ?? 0) <= 2 ? "text-red-600" : "text-gray-900"}`}>
                    {me?.backup_codes_remaining ?? 0} of 8
                  </span>
                </div>
                {(me?.backup_codes_remaining ?? 0) <= 2 && (
                  <p className="text-xs text-red-600 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Low on recovery codes. Consider re-enrolling to generate new ones.
                  </p>
                )}
                <p className="text-xs text-gray-500">
                  Recovery codes are shown only once during enrollment. Store them securely.
                  Each code can be used once to unlock your vault if you lose your authenticator.
                </p>
              </div>
            )}
          </div>

          {/* Multi-admin section (collapsed) */}
          {admins.length > 1 && (
            <div className="border rounded-xl overflow-hidden">
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="w-full flex items-center justify-between px-5 py-3 text-sm text-gray-600 hover:bg-gray-50 transition-colors"
              >
                <span className="font-medium">{admins.length} admins</span>
                {showAdvanced ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              </button>
              {showAdvanced && (
                <table className="w-full text-sm border-t">
                  <thead>
                    <tr className="bg-gray-50 text-left text-gray-600 uppercase text-xs">
                      <th className="px-4 py-2.5 border-b">Admin</th>
                      <th className="px-4 py-2.5 border-b">Role</th>
                      <th className="px-4 py-2.5 border-b">TOTP</th>
                      <th className="px-4 py-2.5 border-b text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {admins.filter(a => a.id !== currentId).map(admin => (
                      <tr key={admin.id} className="hover:bg-gray-50">
                        <td className="px-4 py-2.5 border-b font-mono text-xs">{admin.id}</td>
                        <td className="px-4 py-2.5 border-b"><AdminRoleBadge role={admin.role} /></td>
                        <td className="px-4 py-2.5 border-b">
                          <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${admin.totp_enrolled ? "text-green-700" : "text-gray-500"}`}>
                            <span className={`w-2 h-2 rounded-full ${admin.totp_enrolled ? "bg-green-500" : "bg-gray-300"}`} />
                            {admin.totp_enrolled ? "Enrolled" : "Not enrolled"}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 border-b text-right">
                          {admin.totp_enrolled ? (
                            <button onClick={() => { api.totpDisable(admin.id); load(); }} className="text-xs text-red-600 hover:text-red-800 font-medium px-2 py-1 rounded hover:bg-red-50">
                              Disable
                            </button>
                          ) : (
                            <button onClick={() => { setEnrolling(true); setEnrollingId(admin.id); }} className="text-xs text-indigo-600 hover:text-indigo-800 font-medium px-2 py-1 rounded hover:bg-indigo-50">
                              Enroll
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </>
      )}

      {enrolling && (
        <TotpEnrollDialog
          adminId={enrollingId ?? currentId}
          onClose={() => { setEnrolling(false); setEnrollingId(null); }}
          onEnrolled={() => { setEnrolling(false); setEnrollingId(null); load(); }}
        />
      )}

      {/* Disable confirmation modal */}
      {confirmingDisable && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-sm">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Disable Two-Factor Auth</h3>
            <p className="text-sm text-gray-600 mb-4">Enter your vault passphrase to confirm.</p>
            <form onSubmit={handleDisable}>
              <input type="password" value={disablePass}
                onChange={e => setDisablePass(e.target.value)}
                className="w-full border rounded px-3 py-2 text-sm mb-3 focus:ring-2 focus:ring-red-500 focus:border-transparent"
                placeholder="Vault passphrase" autoFocus required disabled={disabling}
              />
              {disableError && <p className="text-red-600 text-sm mb-2">{disableError}</p>}
              <div className="flex gap-2 justify-end">
                <button type="button" onClick={() => { setConfirmingDisable(false); setDisablePass(""); setDisableError(""); }}
                  className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800" disabled={disabling}>Cancel</button>
                <button type="submit" disabled={!disablePass || disabling}
                  className="px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50">
                  {disabling ? "Disabling..." : "Disable"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
