import React, { useEffect, useState } from "react";
import { api, BackupConfig, BackupEntry } from "../api";

const DEST_LABELS: Record<string, string> = {
  local: "Local Filesystem",
  ssh: "SSH / rsync",
  webdav: "WebDAV (self-hosted)",
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

// Module-level cache — survives navigation, avoids blank loading flash
let _backupCache: { config: BackupConfig; backups: BackupEntry[] } | null = null;

export function Backup() {
  const [config, setConfig] = useState<BackupConfig | null>(_backupCache?.config ?? null);
  const [backups, setBackups] = useState<BackupEntry[]>(_backupCache?.backups ?? []);
  const [loading, setLoading] = useState(_backupCache === null);
  const [error, setError] = useState<string | null>(null);

  // Config form state
  const [dest, setDest] = useState<"local" | "ssh" | "webdav">("local");
  const [localPath, setLocalPath] = useState("");
  const [sshHost, setSshHost] = useState("");
  const [sshUser, setSshUser] = useState("");
  const [sshPath, setSshPath] = useState("");
  const [webdavUrl, setWebdavUrl] = useState("");
  const [webdavUser, setWebdavUser] = useState("");
  const [webdavPass, setWebdavPass] = useState("");
  const [keepN, setKeepN] = useState(10);
  const [enabled, setEnabled] = useState(false);
  const [savingConfig, setSavingConfig] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Trigger state
  const [triggering, setTriggering] = useState(false);
  const [triggerResult, setTriggerResult] = useState<string | null>(null);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  // Restore modal state
  const [restorePath, setRestorePath] = useState<string | null>(null);
  const [restorePass, setRestorePass] = useState("");
  const [restoring, setRestoring] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([api.getBackupConfig(), api.listBackups()])
      .then(([cfgRes, listRes]) => {
        const c = cfgRes.backup_config;
        _backupCache = { config: c, backups: listRes.backups };
        setConfig(c);
        setDest((c.destination as "local" | "ssh" | "webdav") ?? "local");
        setLocalPath(c.local_path ?? "");
        setSshHost(c.ssh_host ?? "");
        setSshUser(c.ssh_user ?? "");
        setSshPath(c.ssh_path ?? "");
        setWebdavUrl(c.webdav_url ?? "");
        setWebdavUser(c.webdav_user ?? "");
        setWebdavPass("");
        setKeepN(c.keep_n ?? 10);
        setEnabled(c.enabled ?? false);
        setBackups(listRes.backups);
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingConfig(true);
    setSaveSuccess(false);
    try {
      await api.setBackupConfig({
        enabled,
        destination: dest,
        local_path: localPath || null,
        ssh_host: sshHost || null,
        ssh_user: sshUser || null,
        ssh_path: sshPath || null,
        webdav_url: webdavUrl || null,
        webdav_user: webdavUser || null,
        webdav_pass: webdavPass || null,
        keep_n: keepN,
      });
      setSaveSuccess(true);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save config");
    } finally {
      setSavingConfig(false);
    }
  };

  const handleTrigger = async () => {
    setTriggering(true);
    setTriggerResult(null);
    setTriggerError(null);
    try {
      const res = await api.triggerBackup();
      setTriggerResult(`Created: ${res.path} (${formatBytes(res.size_bytes)})`);
      load();
    } catch (err: unknown) {
      setTriggerError(err instanceof Error ? err.message : "Backup failed");
    } finally {
      setTriggering(false);
    }
  };

  const handleRestore = async () => {
    if (!restorePath || !restorePass) return;
    setRestoring(true);
    setRestoreError(null);
    try {
      await api.restoreBackup(restorePath, restorePass);
      alert("Vault restored. The page will reload for re-unlock.");
      window.location.reload();
    } catch (err: unknown) {
      setRestoreError(err instanceof Error ? err.message : "Restore failed");
    } finally {
      setRestoring(false);
      setRestorePass("");
    }
  };

  return (
    <div className="p-6 space-y-8 max-w-3xl">
      <h1 className="text-2xl font-bold text-gray-900">Backup</h1>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {loading && <p className="text-gray-500 text-sm">Loading backup configuration…</p>}

      {/* Config form */}
      {!loading && (
        <section className="bg-white border border-gray-200 rounded-xl p-6 space-y-5">
          <h2 className="text-lg font-semibold text-gray-800">Configuration</h2>

          <form onSubmit={handleSaveConfig} className="space-y-4">
            <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
              <input
                type="checkbox"
                checked={enabled}
                onChange={e => setEnabled(e.target.checked)}
                className="rounded"
              />
              Enable automatic backup
            </label>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Destination type
              </label>
              <select
                value={dest}
                onChange={e => setDest(e.target.value as "local" | "ssh" | "webdav")}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                {Object.entries(DEST_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>

            {dest === "local" && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Local path</label>
                <input
                  value={localPath}
                  onChange={e => setLocalPath(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder={
                    typeof navigator !== "undefined" && /Win/i.test(navigator.platform)
                      ? "C:\\ProgramData\\WireSeal\\backups"
                      : "/var/backups/wireseal"
                  }
                />
              </div>
            )}

            {dest === "ssh" && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">SSH host</label>
                  <input
                    value={sshHost}
                    onChange={e => setSshHost(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="backup.example.com"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">SSH user</label>
                  <input
                    value={sshUser}
                    onChange={e => setSshUser(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="backup"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Remote path</label>
                  <input
                    value={sshPath}
                    onChange={e => setSshPath(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="/home/backup/wireseal"
                  />
                </div>
                <p className="text-xs text-gray-500">
                  SSH backup uses key-based authentication. Ensure the server's SSH key is authorized on the remote host.
                </p>
              </>
            )}

            {dest === "webdav" && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">WebDAV URL</label>
                  <input
                    value={webdavUrl}
                    onChange={e => setWebdavUrl(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="https://dav.example.com/wireseal"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                  <input
                    value={webdavUser}
                    onChange={e => setWebdavUser(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                  <input
                    type="password"
                    value={webdavPass}
                    onChange={e => setWebdavPass(e.target.value)}
                    autoComplete="new-password"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="WebDAV password"
                  />
                </div>
              </>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Keep last N backups
              </label>
              <input
                type="number"
                value={keepN}
                min={1}
                max={100}
                onChange={e => setKeepN(Number(e.target.value))}
                className="w-32 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            <div className="flex items-center gap-3">
              <button
                type="submit"
                disabled={savingConfig}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {savingConfig ? "Saving…" : "Save Config"}
              </button>
              {saveSuccess && (
                <span className="text-sm text-green-600">Configuration saved.</span>
              )}
            </div>
          </form>
        </section>
      )}

      {/* Manual trigger */}
      {!loading && (
        <section className="bg-white border border-gray-200 rounded-xl p-6 space-y-3">
          <h2 className="text-lg font-semibold text-gray-800">Manual Backup</h2>
          {config?.last_backup_at && (
            <p className="text-sm text-gray-500">
              Last backup: {formatDate(config.last_backup_at)}
            </p>
          )}
          <button
            onClick={handleTrigger}
            disabled={triggering || !config?.enabled}
            title={!config?.enabled ? "Enable backup in configuration first" : undefined}
            className="bg-green-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {triggering ? "Running…" : "Trigger Backup Now"}
          </button>
          {!config?.enabled && (
            <p className="text-xs text-gray-500">Backup is disabled. Enable it in the configuration above to run manual backups.</p>
          )}
          {triggerResult && (
            <p className="text-sm text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
              {triggerResult}
            </p>
          )}
          {triggerError && (
            <p className="text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
              {triggerError}
            </p>
          )}
        </section>
      )}

      {/* Backup list */}
      {!loading && backups.length > 0 && (
        <section className="bg-white border border-gray-200 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4">Existing Backups</h2>
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="bg-gray-50 text-left text-gray-600 uppercase text-xs tracking-wide">
                <th className="px-4 py-2.5 border-b border-gray-200">File</th>
                <th className="px-4 py-2.5 border-b border-gray-200">Created</th>
                <th className="px-4 py-2.5 border-b border-gray-200">Size</th>
                <th className="px-4 py-2.5 border-b border-gray-200"></th>
              </tr>
            </thead>
            <tbody>
              {backups.map(b => (
                <tr key={b.path} className="hover:bg-gray-50 transition-colors">
                  <td className="px-4 py-2.5 border-b border-gray-100 font-mono text-xs text-gray-700 max-w-xs truncate">
                    {b.path}
                  </td>
                  <td className="px-4 py-2.5 border-b border-gray-100 text-gray-500">
                    {formatDate(b.created_at)}
                  </td>
                  <td className="px-4 py-2.5 border-b border-gray-100 text-gray-500">
                    {formatBytes(b.size_bytes)}
                  </td>
                  <td className="px-4 py-2.5 border-b border-gray-100">
                    <button
                      onClick={() => { setRestorePath(b.path); setRestoreError(null); setRestorePass(""); }}
                      className="text-amber-600 hover:text-amber-800 text-xs font-medium transition-colors"
                    >
                      Restore
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {!loading && backups.length === 0 && !error && (
        <p className="text-sm text-gray-400">No backups found. Trigger a backup above to create one.</p>
      )}

      {/* Restore modal */}
      {restorePath && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4 space-y-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-gray-900">Restore Vault</h3>
            <p className="text-sm text-gray-600">
              Restoring{" "}
              <span className="font-mono text-xs break-all bg-gray-100 px-1 py-0.5 rounded">
                {restorePath}
              </span>
              . The live vault will be replaced. You will need to re-unlock afterward.
            </p>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Backup passphrase
              </label>
              <input
                type="password"
                value={restorePass}
                onChange={e => setRestorePass(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-amber-500 focus:border-transparent"
                placeholder="Passphrase used for the backup vault"
                autoFocus
              />
            </div>
            {restoreError && (
              <p className="text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                {restoreError}
              </p>
            )}
            <div className="flex gap-3">
              <button
                onClick={handleRestore}
                disabled={restoring || !restorePass}
                className="bg-amber-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-amber-700 disabled:opacity-50 transition-colors"
              >
                {restoring ? "Restoring…" : "Confirm Restore"}
              </button>
              <button
                onClick={() => { setRestorePath(null); setRestoreError(null); setRestorePass(""); }}
                className="px-4 py-2 rounded-lg text-sm border border-gray-300 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
