---
phase: "08"
title: Real-Time Dashboard & File Manager
status: planning
---

# Phase 8: Real-Time Dashboard & File Manager

## Goal
Replace all polling with SSE push-streaming so the dashboard reflects live
state without hammering the server. Add a cloud-style file manager so VPN
clients can browse, upload, and download files through the dashboard without
any external cloud service.

## Constraints (NON-NEGOTIABLE)
- No external web framework (pure stdlib `http.server` / `ThreadingHTTPServer`)
- No new Python dependencies for SSE — stdlib only (`queue`, `threading`)
- File manager path traversal: every path operation validated against configured
  share root; any traversal attempt → 403 + audit log entry
- Auth: all file endpoints require unlocked vault (same `_require_unlocked()`)
- SSE clients auto-removed from registry on disconnect; no memory leak
- Backward compatible: if browser does not support EventSource, dashboard falls
  back to polling at original intervals

## Features

### 8.1 Server-Sent Events (SSE) Stream
Replace 3–60 s `setInterval` polling with a persistent `/api/events` endpoint.

**Server side:**
- `_SSEBroker` singleton: thread-safe registry of connected client queues
- Broadcast from existing mutation points: peer up/down, client add/remove,
  tunnel state change, audit event, vault lock/unlock
- Heartbeat ping every 25 s to keep proxies from closing idle connections
- `GET /api/events` streams `text/event-stream`; Connection: keep-alive;
  no `Content-Length` (chunked)
- Each event: `event: <type>\ndata: <json>\n\n`

**Event types:**
| Event | Trigger | Payload |
|-------|---------|---------|
| `status` | every 5 s server-side tick + peer state change | full status object |
| `clients` | client add/remove/rotate/TTL update | client list |
| `tunnel` | client mode tunnel up/down | tunnel status |
| `audit` | any audit log write | last audit entry |
| `vault` | lock/unlock | `{locked: bool}` |
| `ping` | 25 s heartbeat | `{}` |

**Dashboard side:**
- `useServerEvents(url, handlers)` React hook wrapping `EventSource`
- Reconnect with exponential backoff (1 s → 30 s cap) on `onerror`
- Replace Dashboard.tsx 3 s `setInterval` with `status` event handler
- Replace Clients.tsx 5 s `setInterval` with `clients` event handler
- Replace Connect.tsx 5/15 s `setInterval` with `tunnel` event handler
- Settings.tsx 60 s service poll stays as-is (low churn, not worth SSE)
- Vault lock events broadcast to all tabs via `BroadcastChannel` (replaces
  current `VAULT_LOCKED_EVENT` custom event which only works same-tab)

### 8.2 File Manager API
Configurable server-side share directory exposed via REST.

**Config stored in vault** (`data["filemanager"]`):
```json
{
  "share_root": "/home/user/shared",
  "max_upload_mb": 100,
  "enabled": true
}
```

**Endpoints:**
| Method | Path | Action |
|--------|------|--------|
| `GET` | `/api/files/config` | Get share root config |
| `PUT` | `/api/files/config` | Set share root + limits |
| `GET` | `/api/files?path=` | List directory (name, size, mtime, is_dir) |
| `GET` | `/api/files/download?path=` | Stream file download |
| `POST` | `/api/files/upload?path=` | Multipart upload (chunked-friendly) |
| `POST` | `/api/files/mkdir` | Create directory |
| `DELETE` | `/api/files?path=` | Delete file or empty dir |
| `POST` | `/api/files/rename` | Move/rename within share root |

**Security:**
- `_resolve_safe_path(share_root, user_path)` → `Path.resolve()` then assert
  result starts with `share_root`; raises `_ApiError(403)` on any traversal
- Symlinks: `follow_symlinks=False` on `os.stat`; symlinks outside root → 403
- Upload size enforced via `Content-Length` header check before writing
- Upload written to `.tmp` + `os.replace()` (atomic); partial uploads never
  left behind
- Every write/delete/rename logged to audit log
- Requires unlocked vault; owner or admin role only for config changes

### 8.3 Dashboard Files Page
Cloud-style file browser replacing the planned stub.

**UI:**
- Left sidebar: breadcrumb path navigator
- Main area: list/grid toggle, sortable columns (name, size, modified)
- Toolbar: Upload button, New Folder, sort controls
- Drag-drop upload onto main area
- File row actions: Download, Rename, Delete (with confirmation)
- Upload progress bar (XHR with `progress` event; SSE not used here)
- Empty state with "Set share folder in Settings" CTA if not configured
- Settings → File Manager section: share root path input, max upload size

**Error states:**
- Share root not configured → banner with link to settings
- Path outside root → toast "Access denied"
- Upload too large → toast with size limit
- Directory not empty on delete → toast "Directory not empty"

## Implementation Order
8.1 → 8.2 → 8.3
(SSE first so file upload events can stream through the broker)

## Success Criteria
1. Dashboard peers update within 1 s of `wg show` state change — no polling
2. Clients page reflects add/remove instantly without manual refresh
3. Client mode tunnel status updates in real-time on connect/disconnect
4. Vault lock broadcasts to all open dashboard tabs simultaneously
5. File listing, upload, download, mkdir, rename, delete all work end-to-end
6. Path traversal attempt (`../../etc/passwd`) returns 403 and audit entry
7. 100 MB file uploads with progress bar; no server memory buffering entire file
8. Share root not set → Files page shows config CTA, no crash
