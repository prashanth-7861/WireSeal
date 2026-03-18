---
phase: 01-secure-core-engine
plan: "03"
subsystem: core
tags: [x25519, keygen, psk, ip-pool, wireguard, cryptography, secret-types, rfc1918]

# Dependency graph
requires:
  - "01-01 (SecretBytes, wipe_bytes)"
provides:
  - "generate_keypair(): X25519 key pair generation with private key in SecretBytes, raw bytes wiped after encoding"
  - "generate_psk(): 32-byte os.urandom PSK wrapped in SecretBytes, raw bytes wiped after encoding"
  - "IPPool: VPN subnet address manager with server at .1, sequential client allocation from .2, RFC 1918 validation, state serialization"
affects:
  - 01-04
  - all downstream phases (key pairs and PSKs feed vault state; IPPool tracks VPN addressing)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "KEYGEN-01 Pattern: X25519PrivateKey.generate() in-process -- never via wg genkey subprocess (visible in ps aux)"
    - "KEYGEN-02/04 Pattern: extract raw key bytes into bytearray, encode to base64, wipe_bytes() raw bytes immediately"
    - "IPPool Pattern: sequential allocation skips server IP, dict lookup for conflict detection, immediate pop on release"

key-files:
  created:
    - src/wg_automate/core/keygen.py
    - src/wg_automate/core/psk.py
    - src/wg_automate/core/ip_pool.py
  modified:
    - src/wg_automate/core/__init__.py

key-decisions:
  - "Public key is returned as plain bytes (not SecretBytes) -- public keys are intentionally non-secret in WireGuard"
  - "Standard base64 (not url-safe) used for key encoding -- matches wg CLI output format for interoperability"
  - "IPPool uses strict=False for ip_network() -- allows user-friendly input with host bits set (e.g., 10.0.0.1/24)"
  - "IPPool.get_client_ip() iterates allocated dict for reverse lookup -- pool sizes are small (<<253 for /24), linear scan acceptable"

patterns-established:
  - "Secret key flow: generate() -> bytearray(raw) -> b64encode -> wipe_bytes(raw) -> SecretBytes(bytearray(b64))"
  - "IPPool state round-trip: get_allocated() -> vault persist -> load_state() on next unlock"

requirements-completed: [KEYGEN-01, KEYGEN-02, KEYGEN-03, KEYGEN-04, IP-01, IP-02, IP-03]

# Metrics
duration: 2min
completed: 2026-03-18
---

# Phase 1 Plan 03: Key Generation and IP Pool Summary

**X25519 keypairs and PSKs generated in-process with SecretBytes wrapping and intermediate wipe, plus RFC 1918 IP pool with sequential allocation, conflict detection, and vault state serialization**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-18T02:47:47Z
- **Completed:** 2026-03-18T02:49:38Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- `keygen.py`: `generate_keypair()` generates X25519 key pairs in-process via `X25519PrivateKey.generate()`. Raw private bytes extracted into `bytearray`, base64-encoded, raw bytes wiped via `wipe_bytes()`, result wrapped in `SecretBytes`. Public key returned as plain `bytes`.
- `psk.py`: `generate_psk()` generates 32 bytes from `os.urandom`, base64-encodes, wipes raw bytes, wraps in `SecretBytes`.
- `ip_pool.py`: `IPPool` class with configurable subnet, server at first host (.1), clients allocated sequentially from .2, RFC 1918 validation, conflict detection via allocation dict, immediate release, `load_state`/`get_allocated` for vault persistence round-trips.

## Task Commits

Each task was committed atomically:

1. **Task 1: X25519 key generation and PSK generation** - `e849f50` (feat)
2. **Task 2: IP pool manager with subnet allocation and conflict detection** - `9747222` (feat)

## Files Created/Modified

- `src/wg_automate/core/keygen.py` - `generate_keypair()` returning `(SecretBytes, bytes)` with X25519 and intermediate wipe
- `src/wg_automate/core/psk.py` - `generate_psk()` returning `SecretBytes` with os.urandom and intermediate wipe
- `src/wg_automate/core/ip_pool.py` - `IPPool` class with allocation, release, RFC 1918 validation, state serialization
- `src/wg_automate/core/__init__.py` - Exports `generate_keypair`, `generate_psk`, `IPPool`

## Decisions Made

- Public key is plain `bytes`, not `SecretBytes`. Public keys are intentionally non-secret in WireGuard (they are distributed to peers). Wrapping in SecretBytes would be misleading and would complicate usage.
- Standard base64 (`base64.b64encode`) rather than url-safe variant. WireGuard's `wg` CLI uses standard base64 for key encoding; using the same format ensures interoperability.
- `ip_network(subnet, strict=False)` used in IPPool to accept user input with host bits set (e.g., `10.0.0.1/24`). This is explicitly required by the plan for UX.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `generate_keypair()`, `generate_psk()`, and `IPPool` are ready for Plan 01-04 (config builder) to consume.
- The key generation pattern (SecretBytes wrapping, intermediate wipe) is established and consistent with what the vault expects for server and client key fields.
- `IPPool.load_state()` / `get_allocated()` provides the serialization interface the vault needs for persisting IP assignments.

---
*Phase: 01-secure-core-engine*
*Completed: 2026-03-18*
