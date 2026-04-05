---
phase: 07-ztna-foundation
plan: "02"
subsystem: api/cli/dashboard
tags: [multi-admin, api, cli, dashboard, react, keyslot]
dependency_graph:
  requires:
    - "07-01: KeyslotStore, vault.add_keyslot/remove_keyslot/change_keyslot_passphrase"
  provides:
    - "GET /api/admins — list admins with id/role/totp_enrolled/last_unlock"
    - "POST /api/admins — create keyslot + admins entry (owner only)"
    - "DELETE /api/admins/<id> — remove keyslot + admins entry (owner only)"
    - "POST /api/admins/<id>/change-passphrase — change admin passphrase"
    - "_session[admin_id] and _session[admin_role] set on unlock"
    - "multi_admin + totp_required_for in vault-info response"
    - "add-admin, remove-admin, list-admins, change-admin-passphrase CLI commands"
    - "Admins.tsx page, AdminRoleBadge.tsx component"
  affects:
    - "07-03 (TOTP): depends on _session[admin_id] established here"
    - "07-04 (ephemeral keys): admin session model used for key operations"
tech_stack:
  added:
    - "import datetime in api.py (_utcnow_iso helper)"
    - "lucide-react Users icon in Layout.tsx"
  patterns:
    - "Role-check pattern: _require_owner() raises _ApiError(403) inline"
    - "Owner bypasses old_passphrase verification for change-passphrase via direct keyslot re-wrap"
    - "Cache includes admins snapshot from _refresh_cache(state)"
    - "multiAdmin flag from vault-info drives admin_id input in unlock dialog"
key_files:
  created:
    - path: "Dashboard/src/app/components/AdminRoleBadge.tsx"
      description: "Colored role pill: owner=purple, admin=blue, readonly=gray"
    - path: "Dashboard/src/app/pages/Admins.tsx"
      description: "Admin list table with remove button; add admin form with role select"
  modified:
    - path: "src/wireseal/api.py"
      description: "4 new handlers, _require_owner, updated _h_unlock/_h_vault_info/_h_lock, admin routes"
    - path: "src/wireseal/main.py"
      description: "add-admin, remove-admin, list-admins, change-admin-passphrase commands"
    - path: "Dashboard/src/app/api.ts"
      description: "AdminInfo type, 4 admin methods, VaultInfo extended, unlock() admin_id param"
    - path: "Dashboard/src/app/routes.tsx"
      description: "Added /admins route"
    - path: "Dashboard/src/app/components/Layout.tsx"
      description: "Admins nav link, multiAdmin state, admin_id unlock input"
decisions:
  - "Owner changing another admin's passphrase uses direct keyslot re-wrap (create_keyslot with session master_key) rather than requiring old passphrase — API handler accesses vault._session_store directly within open() context"
  - "_require_owner() raises _ApiError(403) directly (not callback pattern) consistent with existing _require_unlocked() style"
  - "Admins cache snapshot added to _refresh_cache() output so handlers can read admin data without re-opening vault"
  - "change_keyslot_passphrase for self-change requires old_passphrase; owner-changing-other bypasses this"
metrics:
  duration: "~35 minutes"
  completed_date: "2026-04-05"
  tasks_completed: 3
  files_modified: 5
  files_created: 2
---

# Phase 7 Plan 02: Multi-Admin API + CLI + Dashboard Admins Page Summary

Multi-admin management layer exposed via four REST API endpoints, four CLI commands, and a full Admins dashboard page with role badge component and multi-admin-aware unlock screen.

## What Was Built

### Task 1: api.py — 4 handlers + updated unlock/vault-info

**New handler: `_require_owner()`**
- Raises `_ApiError("owner role required", 403)` if `_session["admin_role"] != "owner"`
- Consistent with existing `_require_unlocked()` raise-pattern (not callback)

**Updated `_h_unlock`:**
- Extracts `admin_id = body.get("admin_id", "owner")` from request body
- Opens vault with `vault.open(passphrase, admin_id=admin_id)` for v3 keyslot lookup
- Updates `state.data["admins"][admin_id]["last_unlock"]` to UTC ISO timestamp
- Stores `_session["admin_id"]` and `_session["admin_role"]` (from admins dict)
- Response now includes `"role": admin_role`

**Updated `_h_vault_info`:**
- Adds `multi_admin: bool` (True when `len(admins) > 1` in cache)
- Adds `totp_required_for: list[str]` (admin_ids with non-None totp_secret_b32)
- Both fields default to False/[] when vault is locked

**Updated `_h_lock`:**
- Clears `admin_id` and `admin_role` from session on lock

**Updated `_refresh_cache`:**
- Adds `"admins"` key to cache snapshot for fast reads by admin handlers

**New `_h_list_admins` (GET /api/admins):**
- Returns `{admins: [{id, role, totp_enrolled, last_unlock}]}`
- Reads from `_session["cache"]["admins"]` — no vault re-open required

**New `_h_add_admin` (POST /api/admins):**
- Owner-only (403 if not owner)
- Calls `vault.add_keyslot(admin_id, new_bytes, role=role_internal)` inside open() context
- Creates complete admins dict entry with all TOTP/backup_codes fields
- Returns 409 on duplicate; 201 on success

**New `_h_remove_admin` (DELETE /api/admins/<id>):**
- Owner-only; rejects self-removal (409) and last-owner removal (409)
- Calls `vault.remove_keyslot(target_id)` inside open() context

**New `_h_change_admin_passphrase` (POST /api/admins/<id>/change-passphrase):**
- Owner changing another admin's passphrase: accesses `vault._session_store` directly to re-wrap keyslot without needing old passphrase
- Non-owner can only change their own; must provide `old_passphrase`

### Task 2: main.py — 4 CLI commands

- `add-admin <admin_id> [--role admin|read-only|owner]`: prompts owner passphrase + new passphrase + confirm
- `remove-admin <admin_id>`: prompts owner passphrase + confirm dialog; guards last-owner
- `list-admins`: opens vault and prints admin table (ID | Role | TOTP | Last Unlock)
- `change-admin-passphrase [admin_id]`: defaults to "owner"; prompts current + new + confirm

### Task 3: Dashboard — complete multi-admin UI

**AdminRoleBadge.tsx:** Inline pill with Tailwind colors — purple=owner, blue=admin, gray=readonly.

**Admins.tsx:** Full page with admin table (remove button disabled for last-owner/self) and add-admin form (admin_id, passphrase, role select).

**api.ts changes:**
- `AdminInfo` type: `{id, role, totp_enrolled, last_unlock}`
- `VaultInfo` extended: `multi_admin: boolean; totp_required_for: string[]`
- `unlock()` accepts optional `admin_id` parameter
- Four new methods: `listAdmins`, `addAdmin`, `removeAdmin`, `changeAdminPassphrase`

**Layout.tsx changes:**
- `multiAdmin` state populated from `vaultInfo.multi_admin`
- Admin ID input rendered above passphrase field when `multiAdmin === true` (unlock mode only)
- `adminId` state passed to `api.unlock()` when `multiAdmin` is true
- "Admins" nav link with `Users` icon added to sidebar

**routes.tsx:** `/admins` route added pointing to `Admins` component.

## Test Results

```
58 passed in 10.09s  (tests/security/ — zero regressions)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `_require_owner` signature adapted to match api.py handler pattern**
- **Found during:** Task 1 implementation
- **Issue:** Plan showed `_require_owner(send_error_fn)` callback pattern, but existing `_require_unlocked()` raises `_ApiError` directly
- **Fix:** Implemented as no-arg function that raises `_ApiError(403)` directly
- **Files modified:** `src/wireseal/api.py`

**2. [Rule 2 - Missing] Owner passphrase-change without old_passphrase**
- **Found during:** Task 1 implementation
- **Issue:** `vault.change_keyslot_passphrase()` requires `old_passphrase`, but owner changing another admin's passphrase doesn't know it
- **Fix:** When owner changes another admin's passphrase, directly accesses `vault._session_store` to re-wrap the keyslot using `create_keyslot()` with the session master key
- **Files modified:** `src/wireseal/api.py`

**3. [Rule 3 - Blocking] `_vault_path()` / `_audit_path()` helpers not in main.py**
- **Found during:** Task 2 implementation
- **Issue:** Plan references `_vault_path()` and `_audit_path()` helpers that don't exist; main.py uses `DEFAULT_VAULT_PATH` and `DEFAULT_AUDIT_LOG_PATH` constants
- **Fix:** Used existing constants directly in the four CLI commands
- **Files modified:** `src/wireseal/main.py`

## Self-Check: PASSED
