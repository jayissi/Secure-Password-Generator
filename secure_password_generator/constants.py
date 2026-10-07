"""
Centralized constants and defaults for Secure Password Generator.
"""

import os
from pathlib import Path

# =========================
# Password Generation
# =========================
MIN_PASSWORD_LENGTH = 8
DEFAULT_PASSWORD_LENGTH = 12
MAX_GENERATION_ATTEMPTS = 100

# =========================
# Security
# =========================
SECURE_DELETE_PASSES = 3
CLIPBOARD_CLEAR_SECONDS = 60
MIN_ENCRYPTED_LENGTH = 28  # 12-byte nonce + 16-byte GCM tag minimum

DEFAULT_FILE_PERMISSIONS = 0o600
DEFAULT_DIR_PERMISSIONS = 0o700

SIMILAR_CHARS = "il1Lo0O"

# Latin-1 Supplement printable characters (U+00A1 to U+00FF).
# Excludes U+00A0 (NBSP) and U+00AD (soft hyphen) — both are
# invisible/non-printable.  93 characters total.
LATIN_EXT_CHARS = "".join(
    chr(cp) for cp in range(0x00A1, 0x0100)
    if cp != 0x00AD
)

# Argon2id parameters
ARGON2_DIGEST_LENGTH = 64       # 512-bit digest (per-password hashing)
MASTER_KDF_LENGTH = 32          # 256-bit derived key (master password)
ARGON2_ITERATIONS = 100         # time cost
ARGON2_LANES = 4                # parallelism
ARGON2_MEMORY_COST = 64 * 1024  # 64 MiB

# Test-mode override: set SPG_TEST_KDF=1 to use minimal Argon2id params.
# This is safe because the variable is never set outside test harnesses.
if os.environ.get("SPG_TEST_KDF"):
    ARGON2_ITERATIONS = 1
    ARGON2_MEMORY_COST = 8 * 1024  # 8 MiB

# Master password complexity requirements
MASTER_PASSWORD_MIN_LENGTH = 12
MASTER_PASSWORD_MIN_TYPES = 3   # of 4 (upper, lower, digit, special)

# =========================
# File Paths
# =========================
PASSWORD_DIR = Path.home() / ".secure_passwords"
PASSWORD_FILE = PASSWORD_DIR / "vault.enc"
KEY_FILE = PASSWORD_DIR / "encryption.key"
PEPPER_FILE = PASSWORD_DIR / "pepper.key"
MASTER_SALT_FILE = PASSWORD_DIR / "master_salt.bin"

# =========================
# ANSI Colors
# =========================
COLOR_RED = "\033[91m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_BRIGHT_GREEN = "\033[1;92m"
COLOR_RESET = "\033[0m"

# =========================
# Config File Support
# =========================
VALID_CONFIG_KEYS = {
    "length", "upper", "lower", "digits", "symbols",
    "no_repeats", "exclude_similar", "min_chars",
    "allowed_symbols", "blank_space", "latin_ext",
    "label", "category", "tags",
    "save_history",
}

CONFIG_KEY_MAP = {
    "blank_space": "blank",
}

# =========================
# Environment Variables
# =========================
ENV_MASTER_CREDENTIAL = "SPG_MASTER_CREDENTIAL"

# =========================
# Associated Authenticated Data
# =========================
VAULT_AAD = b"vault-entry"
