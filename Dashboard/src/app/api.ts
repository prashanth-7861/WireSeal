/** Typed fetch helpers for the WireSeal REST API. */

const BASE = "/api";

/**
 * Fired whenever the backend returns 401 (vault locked).
 * App.tsx listens for this to reset to the locked/start-server screen
 * without requiring a full page reload.
 */
export const VAULT_LOCKED_EVENT = "wireseal:vault-locked";

async function _fetch<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : {},
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error("Cannot reach WireSeal server — is `wireseal serve` running?");
  }

  let data: unknown;
  try {
    data = await res.json();
  } catch {
    throw new Error(`Server returned an invalid response (HTTP ${res.status})`);
  }

  if (!res.ok) {
    const err = (data as Record<string, string>).error ?? `HTTP ${res.status}`;
    // Vault got locked on the server (e.g. process restart) — broadcast so
    // the Dashboard can detect it and return to the Start Server screen.
    // Exempt /unlock and /init themselves to avoid a redirect loop on wrong passphrase.
    if (res.status === 401 && path !== "/unlock" && path !== "/init" && path !== "/fresh-start") {
      window.dispatchEvent(new CustomEvent(VAULT_LOCKED_EVENT));
    }
    throw new Error(err);
  }
  return data as T;
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface VaultInfo {
  initialized: boolean;
  locked: boolean;
  interface: string;
  pin_set: boolean;
  multi_admin: boolean;
  totp_required_for: string[];
  /** "server" or "client" — null when vault is locked (not yet decrypted). */
  mode: "server" | "client" | null;
}

export interface AdminInfo {
  id: string;
  role: "owner" | "admin" | "readonly";
  totp_enrolled: boolean;
  last_unlock: string | null;
}

export interface Peer {
  public_key_short: string;
  allowed_ips: string;
  last_handshake: string;
  last_handshake_seconds: number;   // -1 = never; seconds since last handshake otherwise
  transfer_rx: string;               // pre-formatted: "1.29 MB", "466.94 KB", "0 B"
  transfer_tx: string;               // pre-formatted: same
  connected: boolean;                // true when last_handshake_seconds in [0, 179]
  name: string;
}

export interface Status {
  running: boolean;
  interface: string;
  server_ip: string;
  endpoint: string;
  port: number;
  peers: Peer[];
  total_clients: number;
}

export interface Client {
  name: string;
  ip: string;
  permanent: boolean;
  ttl_seconds: number | null;
  ttl_expires_at: number | null;
  expires_in_seconds: number | null;
}

export interface AuditEntry {
  timestamp: string;
  action: string;
  metadata: Record<string, unknown>;
  success: boolean;
  error: string | null;
}

export interface FileActivityEvent {
  timestamp: string;
  type: string;
  operation: string;
  details: Record<string, string>;
}

export interface SecurityCheck {
  name: string;
  ok: boolean;
  fix?: string | null;
}

export interface OpenPort {
  port: number;
  proto: string;
  process: string;
}

export interface SecurityStatus {
  ssh_hardened: boolean;
  kernel_hardened: boolean;
  fail2ban_active: boolean;
  fail2ban_bans: number;
  firewall_active: boolean;
  ip_forwarding: boolean;
  auto_updates: boolean;
  open_ports: OpenPort[];
  checks: SecurityCheck[];
}

export interface AdminStatus {
  active: boolean;
  expires_in: number;
}

export interface ServiceInfo {
  unit: string;
  load: string;
  active: string;
  sub: string;
  description: string;
}

export interface ExecResult {
  returncode: number;
  stdout: string;
  stderr: string;
}

export interface DnsStatus {
  mappings: Record<string, string>;
  dnsmasq_available: boolean;
  dnsmasq_running: boolean;
  platform?: string; // "win32" | "linux" | "darwin"
}

export interface BackupConfig {
  enabled: boolean;
  destination: "local" | "ssh" | "webdav";
  local_path: string | null;
  ssh_host: string | null;
  ssh_user: string | null;
  ssh_path: string | null;
  webdav_url: string | null;
  webdav_user: string | null;
  keep_n: number;
  last_backup_at: number | null;
}

export interface BackupEntry {
  path: string;
  created_at: number;
  size_bytes: number;
}

export interface SessionSummary {
  sessions: {
    start: string;
    end: string | null;
    event_count: number;
    event_types: Record<string, number>;
  }[];
  summary: {
    total_sessions: number;
    total_events: number;
    action_counts: Record<string, number>;
    clients_added: number;
    clients_removed: number;
    configs_exported: number;
    qr_codes_generated: number;
  };
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

export interface ClientConfig {
  name: string;
  imported_at: string;
  server_endpoint: string;
  interface_ip: string;
}

export interface ClientConfigFull extends ClientConfig {
  config_text: string;
}

export interface ClientTunnelStatus {
  connected: boolean;
  profile: string | null;
  interface: string;
  wg_output?: string;
}

export interface SshSessionInfo {
  session_id: string;
  profile: string;
  host: string;
  port: number;
  username: string;
  actor_id: string;
  started_at: number;
}

export const api = {
  vaultInfo: () =>
    _fetch<VaultInfo>("GET", "/vault-info"),

  init: (
    passphrase: string,
    opts?: { mode?: "server" | "client"; subnet?: string; port?: number; endpoint?: string },
  ) =>
    _fetch<{
      ok: boolean;
      mode?: "server" | "client";
      // Server-mode-only fields
      server_ip?: string;
      subnet?: string;
      public_key?: string;
      endpoint?: string;
      warnings?: string[] | null;
    }>("POST", "/init", { passphrase, ...opts }),

  unlock: (passphrase: string, admin_id?: string) =>
    _fetch<{ ok: boolean; role?: string }>("POST", "/unlock", {
      passphrase,
      ...(admin_id !== undefined ? { admin_id } : {}),
    }),

  lock: () =>
    _fetch<{ ok: boolean }>("POST", "/lock"),

  status: () =>
    _fetch<Status>("GET", "/status"),

  listClients: () =>
    _fetch<Client[]>("GET", "/clients"),

  addClient: (name: string, ttl_seconds?: number) =>
    _fetch<Client>("POST", "/clients", ttl_seconds != null ? { name, ttl_seconds } : { name }),

  removeClient: (name: string) =>
    _fetch<{ ok: boolean }>("DELETE", `/clients/${encodeURIComponent(name)}`),

  setClientTtl: (name: string, opts: { ttl_seconds?: number; permanent?: boolean }) =>
    _fetch<{ ok: boolean; expires_at?: number; permanent?: boolean }>("POST", `/clients/${encodeURIComponent(name)}/ttl`, opts),

  heartbeat: (name: string) =>
    _fetch<{ ok: boolean; expires_at?: number; permanent?: boolean }>("POST", `/heartbeat/${encodeURIComponent(name)}`),

  clientQr: (name: string) =>
    _fetch<{ name: string; qr_png_b64: string; format?: string }>("GET", `/clients/${encodeURIComponent(name)}/qr`),

  clientConfig: (name: string) =>
    _fetch<{ name: string; config: string }>("GET", `/clients/${encodeURIComponent(name)}/config`),

  rotateClientKeys: (name: string) =>
    _fetch<{ ok: boolean; name: string; config: string; qr_png_b64?: string; warning?: string }>(
      "POST", `/clients/${encodeURIComponent(name)}/rotate`
    ),

  rotateServerKeys: () =>
    _fetch<{ ok: boolean; client_count: number; warning?: string }>("POST", "/rotate-server-keys"),

  auditLog: () =>
    _fetch<{ entries: AuditEntry[] }>("GET", "/audit-log"),

  sessionSummary: () =>
    _fetch<SessionSummary>("GET", "/session-summary"),

  fileActivity: () =>
    _fetch<{ events: FileActivityEvent[] }>("GET", "/file-activity"),

  securityStatus: () =>
    _fetch<SecurityStatus>("GET", "/security-status"),

  hardenServer: () =>
    _fetch<{ ok: boolean; actions: string[] }>("POST", "/harden-server"),

  changePassphrase: (current: string, newPass: string) =>
    _fetch<{ ok: boolean }>("POST", "/change-passphrase", { current, new: newPass }),

  startServer: () =>
    _fetch<{ ok: boolean; note?: string }>("POST", "/start"),

  terminate: () =>
    _fetch<{ ok: boolean }>("POST", "/terminate"),

  freshStart: () =>
    _fetch<{ ok: boolean }>("POST", "/fresh-start", { confirm: "CONFIRM" }),

  updateEndpoint: (endpoint?: string) =>
    _fetch<{ ok: boolean; endpoint: string }>("POST", "/update-endpoint", { endpoint }),

  setPin: (pin: string) =>
    _fetch<{ ok: boolean }>("POST", "/set-pin", { pin }),

  removePin: () =>
    _fetch<{ ok: boolean }>("POST", "/remove-pin"),

  unlockPin: (pin: string) =>
    _fetch<{ ok: boolean }>("POST", "/unlock-pin", { pin }),

  pinInfo: () =>
    _fetch<{ pin_set: boolean }>("GET", "/pin-info"),

  // ── Admin mode ────────────────────────────────────────────────────────────
  adminAuthenticate: (password: string) =>
    _fetch<{ ok: boolean; expires_in: number }>("POST", "/admin/authenticate", { password }),

  adminDeactivate: () =>
    _fetch<{ ok: boolean }>("POST", "/admin/deactivate"),

  adminStatus: () =>
    _fetch<AdminStatus>("GET", "/admin/status"),

  adminExec: (cmd: string[], stdin = "", timeout = 30) =>
    _fetch<ExecResult>("POST", "/admin/exec", { cmd, stdin, timeout }),

  adminServices: () =>
    _fetch<{ services: ServiceInfo[]; note?: string }>("GET", "/admin/services"),

  adminServiceAction: (name: string, action: string) =>
    _fetch<ExecResult & { ok: boolean }>(
      "POST", `/admin/services/${encodeURIComponent(name)}/${encodeURIComponent(action)}`
    ),

  adminReadFile: (path: string) =>
    _fetch<{ path: string; content: string }>("POST", "/admin/file/read", { path }),

  adminWriteFile: (path: string, content: string) =>
    _fetch<{ ok: boolean; path: string }>("POST", "/admin/file/write", { path, content }),

  // ── Multi-admin management ────────────────────────────────────────────────
  listAdmins: (): Promise<{ admins: AdminInfo[] }> =>
    _fetch<{ admins: AdminInfo[] }>("GET", "/admins"),

  addAdmin: (admin_id: string, passphrase: string, role: string): Promise<void> =>
    _fetch<void>("POST", "/admins", { admin_id, passphrase, role }),

  removeAdmin: (admin_id: string): Promise<void> =>
    _fetch<void>("DELETE", `/admins/${encodeURIComponent(admin_id)}`),

  changeAdminPassphrase: (admin_id: string, new_passphrase: string): Promise<void> =>
    _fetch<void>("POST", `/admins/${encodeURIComponent(admin_id)}/change-passphrase`, { new_passphrase }),

  // ── Split-DNS (7.4) ───────────────────────────────────────────────────────
  getDns: () =>
    _fetch<DnsStatus>("GET", "/dns"),

  setDns: (mappings: Record<string, string>) =>
    _fetch<{ ok: boolean; reloaded: boolean }>("POST", "/dns", { mappings }),

  addDnsMapping: (hostname: string, ip: string) =>
    _fetch<{ ok: boolean }>("POST", `/dns/${encodeURIComponent(hostname)}`, { ip }),

  removeDnsMapping: (hostname: string) =>
    _fetch<{ ok: boolean }>("DELETE", `/dns/${encodeURIComponent(hostname)}`),

  // ── Backup (7.5 encrypted local backup) ──────────────────────────────────
  getBackupConfig: (): Promise<{ backup_config: BackupConfig }> =>
    _fetch<{ backup_config: BackupConfig }>("GET", "/backup/config"),

  setBackupConfig: (cfg: Partial<BackupConfig>): Promise<{ ok: boolean }> =>
    _fetch<{ ok: boolean }>("POST", "/backup/config", cfg),

  triggerBackup: (): Promise<{ ok: boolean; path: string; size_bytes: number; created_at: number }> =>
    _fetch<{ ok: boolean; path: string; size_bytes: number; created_at: number }>("POST", "/backup/trigger"),

  listBackups: (): Promise<{ backups: BackupEntry[] }> =>
    _fetch<{ backups: BackupEntry[] }>("GET", "/backup/list"),

  restoreBackup: (backup_path: string, passphrase: string): Promise<{ ok: boolean; message: string }> =>
    _fetch<{ ok: boolean; message: string }>("POST", "/backup/restore", { backup_path, passphrase }),

  health: (): Promise<{ status: string; vault_initialized: boolean; vault_locked: boolean; uptime_seconds: number }> =>
    _fetch<{ status: string; vault_initialized: boolean; vault_locked: boolean; uptime_seconds: number }>("GET", "/health"),

  // ── Client mode — config management + tunnel ──────────────────────────────
  clientListConfigs: () =>
    _fetch<{ configs: ClientConfig[] }>("GET", "/client/configs"),

  clientImportConfig: (name: string, config_text: string) =>
    _fetch<{ ok: boolean; name: string; server_endpoint?: string; interface_ip?: string; imported_at: string }>(
      "POST", "/client/configs", { name, config_text }
    ),

  clientGetConfig: (name: string) =>
    _fetch<ClientConfigFull>("GET", `/client/configs/${encodeURIComponent(name)}`),

  clientDeleteConfig: (name: string) =>
    _fetch<{ ok: boolean }>("DELETE", `/client/configs/${encodeURIComponent(name)}`),

  clientTunnelUp: (name: string) =>
    _fetch<{ interface: string; profile: string; status: string }>(
      "POST", `/client/tunnel/up/${encodeURIComponent(name)}`
    ),

  clientTunnelDown: () =>
    _fetch<{ interface: string; profile: string; status: string }>("POST", "/client/tunnel/down"),

  clientTunnelStatus: () =>
    _fetch<ClientTunnelStatus>("GET", "/client/tunnel/status"),

  // ── SSH bridge — one-time token issuance for WebSocket connections ───────
  sshToken: (params: {
    host: string;
    port: number;
    username: string;
    password?: string;
    profile_name: string;
    term?: string;
  }) =>
    _fetch<{ token: string; ws_url: string; expires_in: number }>(
      "POST", "/ssh/token", params
    ),

  sshSessions: () =>
    _fetch<{ sessions: SshSessionInfo[] }>("GET", "/ssh/sessions"),
};
