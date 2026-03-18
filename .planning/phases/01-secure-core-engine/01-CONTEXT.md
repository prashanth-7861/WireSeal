# Phase 1: Secure Core Engine - Context

**Gathered:** 2026-03-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Build the security primitives and encrypted state storage that all downstream phases depend on: `SecretBytes` type, `secrets_wipe` module, encrypted vault (AES-256-GCM + Argon2id KDF), key generation (Curve25519 + PSK), IP pool manager, WireGuard config builder, pre-apply validator, config integrity tracking, and atomic write + permissions enforcement. CLI commands, platform adapters, DNS, and packaging are separate phases.

</domain>

<decisions>
## Implementation Decisions

### Passphrase Policy
- Hard enforce minimum 12 characters — tool rejects shorter passphrases with no override option
- Optional passphrase hint: user may store a plaintext hint alongside vault during `init` (hint is NOT encrypted, just a memory aid — tool warns user of this)
- Passphrase confirmation: user types passphrase twice during vault creation; mismatch → retry (standard confirm)
- After 3 wrong passphrase attempts, tool exits cleanly (brute-force protection; Argon2id's ~500ms delay is additional protection)

### Error Verbosity
- Wrong passphrase → generic message only: `"Vault unlock failed"` — never confirm whether passphrase or ciphertext is wrong
- Config validation failures → full detail: show exactly which field and why (e.g., `"Client name 'bad=name' contains invalid character '=' at position 4"`) — precise errors help legitimate users fix issues
- No `--verbose` / `--debug` flag — tool output is always minimal; secrets never appear in any output mode
- Config tampering detected (SHA-256 mismatch) → hard stop with `"SECURITY ALERT: Config file tampered — aborting. Do not reload WireGuard."` then exit — no prompt, no diff, no recovery path from this command

### Config Template Style
- Server and client configs: minimal, no field-level comments
- Single standard header on all generated configs: `# Managed by wg-automate — do not edit manually`
- Client configs include `DNS = <server>` line; DNS server address is collected from user during `init` and stored in vault
- Firewall rules (PostUp/PostDown) placement: Claude's Discretion — pick the cleaner approach between embedding in wg0.conf vs platform adapter management

### Vault State Schema
- Vault stores: server keypair, per-client (keypair + PSK + allocated IP), server port, VPN subnet, DNS server address — all encrypted, single source of truth
- Client records: keys + IP only — no metadata (no creation dates, labels, last-seen timestamps) in Phase 1
- Removed clients: fully purged immediately from vault — no tombstoning, no historical record
- Schema versioning: Claude's Discretion — decide whether to include a `schema_version` field for future migration support

### Claude's Discretion
- Firewall rule placement: PostUp/PostDown in wg0.conf vs managed by platform adapter (Phase 2 concern — planner should coordinate)
- Schema versioning: include `schema_version` field or not — Claude picks what future-proofs best at minimal cost
- Exact error retry UX flow for passphrase (prompt text, spacing)
- Argon2id parameter tuning (256MB/4iter/4par from requirements, but exact benchmarking approach)

</decisions>

<specifics>
## Specific Ideas

- Wrong passphrase error must be generic (`"Vault unlock failed"`) — not `"Wrong passphrase"` — to avoid confirming vault file validity to an attacker
- The passphrase hint is a UX compromise: user wanted recovery option; full unrecoverable lock-out was rejected. Hint is plaintext, tool must warn user clearly during init that the hint is not protected.
- "3 attempts then exit" is a usability + security balance — Argon2id already slows brute-force; 3 attempts prevents lockout frustration for legitimate users while still protecting against scripted attacks
- Config validation errors should be as precise as a compiler error — exact field, exact character, exact position — because the user needs to fix it and wrong information wastes time

</specifics>

<deferred>
## Deferred Ideas

- None — discussion stayed within Phase 1 scope

</deferred>

---

*Phase: 01-secure-core-engine*
*Context gathered: 2026-03-17*
