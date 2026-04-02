---
plan: "06-02"
status: complete
---

## Summary

All tasks completed successfully. `npm run build` exits 0.

### What was done
1. `api.ts` — Added `last_handshake_seconds: number` to `Peer` interface with comments for pre-formatted transfer strings.
2. `Dashboard.tsx` — Four targeted changes:
   - `connectedPeers`: now filters on `p.last_handshake_seconds >= 0 && p.last_handshake_seconds < 180`
   - Endpoint card: shows `status.endpoint || status.server_ip` labelled "Public IP"; shows VPN IP as secondary when both are set
   - Added `formatHandshakeAge`, `handshakeBadgeClass`, `handshakeDotClass`, `handshakeBadgeLabel` helpers
   - Badge replaced with three-state version: green (< 180s), yellow (180-600s), grey (> 600s or never), with formatted age sub-label below

### Verification
`npm run build` exits 0 with no TypeScript errors.
