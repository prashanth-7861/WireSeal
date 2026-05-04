import { useState, useEffect, useCallback } from "react";
import {
  Settings, Shield, Globe, Clock, Wifi, Save, RefreshCw,
  AlertTriangle, CheckCircle,
} from "lucide-react";
import { api, ClientSettings as ClientSettingsType, ClientConfig } from "../../api";

export function ClientSettings() {
  const [settings, setSettings] = useState<ClientSettingsType | null>(null);
  const [profiles, setProfiles] = useState<ClientConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Form state
  const [autoConnect, setAutoConnect] = useState<string>("");
  const [autoLock, setAutoLock] = useState<number>(15);
  const [killSwitch, setKillSwitch] = useState(false);
  const [dnsOverride, setDnsOverride] = useState("");

  const load = useCallback(async () => {
    try {
      const [s, cfgs] = await Promise.all([
        api.clientSettingsGet(),
        api.clientListConfigs(),
      ]);
      setSettings(s);
      setProfiles(cfgs.configs ?? []);
      setAutoConnect(s.auto_connect_profile ?? "");
      setAutoLock(s.auto_lock_minutes);
      setKillSwitch(s.kill_switch);
      setDnsOverride(s.dns_override);
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load settings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = async () => {
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const updated = await api.clientSettingsPut({
        auto_connect_profile: autoConnect || null,
        auto_lock_minutes: autoLock,
        kill_switch: killSwitch,
        dns_override: dnsOverride.trim(),
      });
      setSettings(updated);
      setSuccess("Settings saved");
      setTimeout(() => setSuccess(""), 3000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const hasChanges = settings && (
    (autoConnect || null) !== settings.auto_connect_profile ||
    autoLock !== settings.auto_lock_minutes ||
    killSwitch !== settings.kill_switch ||
    dnsOverride.trim() !== settings.dns_override
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <RefreshCw className="w-5 h-5 animate-spin text-gray-400" />
      </div>
    );
  }

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Client Settings</h1>
          <p className="text-gray-500 mt-1">VPN connection, security, and network preferences</p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving || !hasChanges}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 text-white font-medium text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <Save className="w-4 h-4" />
          {saving ? "Saving..." : "Save Changes"}
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-center gap-2 text-red-700 text-sm">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg flex items-center gap-2 text-green-700 text-sm">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          {success}
        </div>
      )}

      <div className="space-y-6">
        {/* Connection Section */}
        <section className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 bg-blue-50 rounded-lg flex items-center justify-center">
              <Wifi className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Connection</h2>
              <p className="text-gray-500 text-xs">Auto-connect and tunnel behavior</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Auto-connect profile
              </label>
              <select
                value={autoConnect}
                onChange={(e) => setAutoConnect(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="">Disabled — manual connect only</option>
                {profiles.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                  </option>
                ))}
              </select>
              <p className="text-xs text-gray-400 mt-1">
                Automatically connect to this profile after vault unlock.
              </p>
            </div>
          </div>
        </section>

        {/* Security Section */}
        <section className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 bg-amber-50 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-amber-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Security</h2>
              <p className="text-gray-500 text-xs">Kill switch and session timeout</p>
            </div>
          </div>

          <div className="space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Kill Switch</p>
                <p className="text-xs text-gray-400 mt-0.5">
                  Block all internet traffic if VPN tunnel drops unexpectedly.
                  Traffic stays blocked until you reconnect or manually disconnect.
                </p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={killSwitch}
                onClick={() => setKillSwitch(!killSwitch)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  killSwitch ? "bg-blue-600" : "bg-gray-200"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    killSwitch ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
            </div>

            <div className="border-t border-gray-100 pt-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Auto-lock timeout
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={1440}
                  value={autoLock}
                  onChange={(e) => setAutoLock(Math.max(1, Math.min(1440, Number(e.target.value) || 15)))}
                  className="w-24 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <span className="text-sm text-gray-500">minutes</span>
                <Clock className="w-4 h-4 text-gray-400 ml-1" />
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Lock the vault after this period of inactivity (1–1440 min).
              </p>
            </div>
          </div>
        </section>

        {/* Network Section */}
        <section className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 bg-green-50 rounded-lg flex items-center justify-center">
              <Globe className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Network</h2>
              <p className="text-gray-500 text-xs">DNS and routing preferences</p>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              DNS Override
            </label>
            <input
              type="text"
              value={dnsOverride}
              onChange={(e) => setDnsOverride(e.target.value)}
              placeholder="e.g. 1.1.1.1, 9.9.9.9"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">
              Comma-separated DNS servers. Overrides the profile's DNS setting
              when tunnel connects. Leave empty to use profile default.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}
