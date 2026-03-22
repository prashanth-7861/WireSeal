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
    if (res.status === 401 && path !== "/unlock" && path !== "/init") {
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
}

export interface Peer {
  public_key_short: string;
  allowed_ips: string;
  last_handshake: string;
  transfer_rx: string;
  transfer_tx: string;
  connected: boolean;
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
}

export interface AuditEntry {
  timestamp: string;
  action: string;
  metadata: Record<string, unknown>;
  success: boolean;
  error: string | null;
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

export const api = {
  vaultInfo: () =>
    _fetch<VaultInfo>("GET", "/vault-info"),

  init: (passphrase: string, opts?: { subnet?: string; port?: number; endpoint?: string }) =>
    _fetch<{ ok: boolean; server_ip: string; subnet: string; public_key: string; endpoint: string }>(
      "POST", "/init", { passphrase, ...opts }
    ),

  unlock: (passphrase: string) =>
    _fetch<{ ok: boolean }>("POST", "/unlock", { passphrase }),

  lock: () =>
    _fetch<{ ok: boolean }>("POST", "/lock"),

  status: () =>
    _fetch<Status>("GET", "/status"),

  listClients: () =>
    _fetch<Client[]>("GET", "/clients"),

  addClient: (name: string) =>
    _fetch<Client>("POST", "/clients", { name }),

  removeClient: (name: string) =>
    _fetch<{ ok: boolean }>("DELETE", `/clients/${encodeURIComponent(name)}`),

  clientQr: (name: string) =>
    _fetch<{ name: string; qr_png_b64: string }>("GET", `/clients/${encodeURIComponent(name)}/qr`),

  auditLog: () =>
    _fetch<{ entries: AuditEntry[] }>("GET", "/audit-log"),

  changePassphrase: (current: string, newPass: string) =>
    _fetch<{ ok: boolean }>("POST", "/change-passphrase", { current, new: newPass }),

  terminate: () =>
    _fetch<{ ok: boolean }>("POST", "/terminate"),

  freshStart: () =>
    _fetch<{ ok: boolean }>("POST", "/fresh-start", { confirm: "CONFIRM" }),

  updateEndpoint: (endpoint?: string) =>
    _fetch<{ ok: boolean; endpoint: string }>("POST", "/update-endpoint", { endpoint }),
};
