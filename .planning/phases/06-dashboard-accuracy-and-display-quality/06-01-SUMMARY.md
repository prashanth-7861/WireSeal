---
plan: "06-01"
status: complete
---

## Summary

All tasks completed successfully.

### What was done
1. Added `_peer_handshake_cache: dict[str, int] = {}` module-level dict after rate-limit constants.
2. Added `_parse_handshake_to_seconds(hs: str) -> int` — converts all WireGuard age strings ("30 seconds ago", "2 minutes, 30 seconds ago", "1 hour, 5 minutes ago", "1 day, 3 hours ago", "Never") to total seconds. Returns -1 for Never/unparseable.
3. Added `_format_transfer_bytes(raw: str) -> str` — parses IEC units (KiB/MiB/GiB) from `wg show` and emits decimal SI units (KB/MB/GB).
4. Updated `_parse_wg_show`: peer init dict now includes `public_key` (full key) and `last_handshake_seconds: -1`. Handshake parsing uses `_parse_handshake_to_seconds` + delta threshold (`0 <= secs < 180`), replacing broken keyword heuristic. Transfer parsing uses `_format_transfer_bytes`.
5. Added `_detect_new_handshakes(peers)` — compares against cache, fires `peer-connected` audit event on transition from disconnected→connected. Swallows all exceptions.
6. Called `_detect_new_handshakes(peers)` in `_h_status` after name resolution.

### Verification
All assertions passed in unit test script. The hour-ago case that was previously broken ("1 hour, 5 minutes ago" → was showing as connected via old heuristic, now correctly disconnected as 3900s >= 180).
