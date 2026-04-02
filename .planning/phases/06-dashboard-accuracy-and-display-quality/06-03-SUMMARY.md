---
plan: "06-03"
status: complete
---

## Summary

All tasks completed successfully. `npm run build` exits 0.

### What was done
`Clients.tsx` — Four targeted changes:
1. Import: added `type Status` from `../api`
2. State: added `const [peerStatus, setPeerStatus] = useState<Status | null>(null)`
3. Polling useEffect: polls `/api/status` every 5s via `window.setInterval(poll, 5000)`, cleans up on unmount. Failures keep previous state silently.
4. Before `return (`: added `peerMap` (Map from IP host → Peer), `badgeClass`, `dotClass`, `badgeLabel` helpers matching Dashboard.tsx thresholds exactly.
5. Table header: added "Status" column between "Assigned IP" and "Actions".
6. Table cell: IIFE looks up `peerMap.get(client.ip.split("/")[0])`, shows neutral dash badge when peerStatus is null (loading), otherwise three-state badge using `last_handshake_seconds`.

### Verification
`npm run build` exits 0 with no TypeScript errors.
