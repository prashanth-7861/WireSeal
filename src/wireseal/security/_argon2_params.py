"""Shared Argon2id parameters used by both vault.py and keyslot.py.

Extracted to a standalone module to break the circular import between
vault.py (imports keyslot operations) and keyslot.py (needs these bounds).
This module has zero imports from the wireseal package.
"""

ARGON2_MEMORY_COST_KIB = 262144  # 256 MiB
ARGON2_TIME_COST = 13
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 32

ARGON2_MEMORY_COST_MIN_KIB = 65536
ARGON2_MEMORY_COST_MAX_KIB = 2 * 1024 * 1024
ARGON2_TIME_COST_MIN = 2
ARGON2_TIME_COST_MAX = 64
ARGON2_PARALLELISM_MIN = 1
ARGON2_PARALLELISM_MAX = 16
