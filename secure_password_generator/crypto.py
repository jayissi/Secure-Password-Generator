"""
Cryptographic operations: AES-GCM-SIV encryption, Argon2id hashing,
key management, and master-password handling.
"""

import base64
import getpass
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from secure_password_generator.constants import (
    ARGON2_DIGEST_LENGTH,
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_COST,
    DEFAULT_DIR_PERMISSIONS,
    DEFAULT_FILE_PERMISSIONS,
    ENV_MASTER_PASSWORD,
    KEY_FILE,
    MASTER_KDF_LENGTH,
    MASTER_PASSWORD_MIN_LENGTH,
    MASTER_PASSWORD_MIN_TYPES,
    MASTER_SALT_FILE,
    MIN_ENCRYPTED_LENGTH,
    PASSWORD_DIR,
    PASSWORD_FILE,
    PEPPER_FILE,
)
from secure_password_generator.utils import (
    secure_delete_file,
    verify_file_permissions,
)

logger = logging.getLogger("secure_password_generator")

# ---------------------------------------------------------------------------
# Encryption-key caching (per-process)
# ---------------------------------------------------------------------------
_KEY_CACHE: dict[str, tuple[bytes, float]] = {}
_FINAL_KEY_CACHE: dict[str, bytes] = {}
_SESSION_TOKEN: str | None = None


# ---------------------------------------------------------------------------
# Security-file initialisation
# ---------------------------------------------------------------------------
def initialize_security_files() -> None:
    """Ensure secure directory and encryption/pepper key files exist."""
    if not PASSWORD_DIR.exists():
        PASSWORD_DIR.mkdir(mode=DEFAULT_DIR_PERMISSIONS)
        PASSWORD_DIR.chmod(DEFAULT_DIR_PERMISSIONS)

    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(secrets.token_bytes(32))
        KEY_FILE.chmod(DEFAULT_FILE_PERMISSIONS)

    if not PEPPER_FILE.exists():
        PEPPER_FILE.write_bytes(secrets.token_bytes(32))
        PEPPER_FILE.chmod(DEFAULT_FILE_PERMISSIONS)


def _get_cached_key(file_path: Path, cache_key: str) -> bytes:
    """Retrieve a cached key file, refreshing when the file is modified."""
    initialize_security_files()
    verify_file_permissions(file_path)

    current_mtime = file_path.stat().st_mtime if file_path.exists() else 0.0
    cached = _KEY_CACHE.get(cache_key)

    if cached is None or cached[1] != current_mtime:
        key_bytes = file_path.read_bytes()
        _KEY_CACHE[cache_key] = (key_bytes, current_mtime)
        return key_bytes

    return cached[0]


# ---------------------------------------------------------------------------
# Master-password helpers
# ---------------------------------------------------------------------------
def is_master_password_enabled() -> bool:
    """Return True when a master-password salt file exists."""
    return MASTER_SALT_FILE.exists()


def _validate_master_password(password: str) -> None:
    """Enforce complexity requirements on a new master password.

    Requirements:
        * Minimum 12 characters
        * At least 3 of 4 character types (upper, lower, digit, special)

    Raises:
        ValueError: If the password does not meet requirements.
    """
    errors: list[str] = []
    if len(password) < MASTER_PASSWORD_MIN_LENGTH:
        errors.append(
            f"Must be at least {MASTER_PASSWORD_MIN_LENGTH} characters "
            f"(got {len(password)})"
        )

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    types_present = sum([has_upper, has_lower, has_digit, has_special])

    if types_present < MASTER_PASSWORD_MIN_TYPES:
        missing: list[str] = []
        if not has_upper:
            missing.append("uppercase letter")
        if not has_lower:
            missing.append("lowercase letter")
        if not has_digit:
            missing.append("digit")
        if not has_special:
            missing.append("special character")
        errors.append(
            f"Requires at least {MASTER_PASSWORD_MIN_TYPES} of 4 character "
            f"types (upper, lower, digit, special). Missing: "
            + ", ".join(missing)
        )

    if errors:
        raise ValueError(
            "Master password does not meet complexity requirements:\n  - "
            + "\n  - ".join(errors)
        )


def prompt_master_password(prompt: str = "Master password: ") -> str:
    """Prompt for the master password via getpass.

    Raises:
        ValueError: When stdin is not a TTY (non-interactive).
    """
    if not sys.stdin.isatty():
        raise ValueError(
            "Master password required but stdin is not a TTY. "
            "Use --master-password, --master-password-file, or "
            f"{ENV_MASTER_PASSWORD} for non-interactive use."
        )
    password = getpass.getpass(prompt)
    if not password:
        raise ValueError("Master password cannot be empty")
    return password


def derive_master_key(
    master_password: str, salt: bytes | None = None
) -> bytes:
    """Derive a 32-byte key from the master password via Argon2id.

    Args:
        master_password: The user's master password.
        salt: Optional salt bytes; reads MASTER_SALT_FILE when ``None``.

    Returns:
        32-byte derived key.
    """
    if salt is None:
        if not MASTER_SALT_FILE.exists():
            raise ValueError(
                "Master salt file not found; run --set-master-password first"
            )
        verify_file_permissions(MASTER_SALT_FILE)
        salt = MASTER_SALT_FILE.read_bytes()

    kdf = Argon2id(
        salt=salt,
        length=MASTER_KDF_LENGTH,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST,
    )
    return kdf.derive(master_password.encode("utf-8"))


def combine_keys(derived: bytes, file_key: bytes) -> bytes:
    """XOR a master-password-derived key with the on-disk encryption key."""
    if len(derived) != len(file_key):
        raise ValueError("Derived key and file key must be the same length")
    return bytes(a ^ b for a, b in zip(derived, file_key))


# ---------------------------------------------------------------------------
# Encryption key resolution
# ---------------------------------------------------------------------------
def get_file_encryption_key() -> bytes:
    """Retrieve the persistent on-disk AES key material (cached)."""
    return _get_cached_key(KEY_FILE, "encryption")


def get_encryption_key(master_password: str | None = None) -> bytes:
    """Resolve the final AES-256 key.

    When a master password is configured the final key is
    ``derived_key XOR file_key`` (two-factor encryption).  Otherwise the
    on-disk file key is used alone.
    """
    global _SESSION_TOKEN

    file_key = get_file_encryption_key()

    if is_master_password_enabled():
        if master_password is None:
            raise ValueError("Master password required but not provided")

        if _SESSION_TOKEN and _SESSION_TOKEN in _FINAL_KEY_CACHE:
            return _FINAL_KEY_CACHE[_SESSION_TOKEN]

        derived = derive_master_key(master_password)
        final_key = combine_keys(derived, file_key)

        _SESSION_TOKEN = secrets.token_hex(16)
        _FINAL_KEY_CACHE[_SESSION_TOKEN] = final_key
        return final_key

    return file_key


def get_pepper() -> bytes:
    """Get the dedicated pepper key for Argon2id (cached)."""
    return _get_cached_key(PEPPER_FILE, "pepper")


# ---------------------------------------------------------------------------
# AES-GCM-SIV encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt a JSON payload using AES-GCM-SIV."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCMSIV(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return nonce + ciphertext


def decrypt_data(encrypted: bytes, key: bytes) -> str:
    """Decrypt AES-GCM-SIV ciphertext (nonce || ciphertext)."""
    if len(encrypted) < MIN_ENCRYPTED_LENGTH:
        raise ValueError("Encrypted data too short -- possibly corrupted")
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCMSIV(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def argon2id_hash(password: str) -> dict[str, Any]:
    """Derive Argon2id digest with salt + pepper.

    Salt is unique per password.  Pepper is loaded from a separate secure
    file.
    """
    salt = secrets.token_bytes(32)
    pepper = get_pepper()

    params = {
        "length": ARGON2_DIGEST_LENGTH,
        "iterations": ARGON2_ITERATIONS,
        "lanes": ARGON2_LANES,
        "memory_cost": ARGON2_MEMORY_COST,
    }

    kdf = Argon2id(
        salt=salt,
        length=params["length"],
        iterations=params["iterations"],
        lanes=params["lanes"],
        memory_cost=params["memory_cost"],
        secret=pepper,
    )
    digest = kdf.derive(password.encode("utf-8"))

    return {
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "digest_b64": base64.b64encode(digest).decode("ascii"),
        "params": params,
    }


# ---------------------------------------------------------------------------
# Master-password resolution
# ---------------------------------------------------------------------------
def resolve_master_password(args: Any) -> str | None:
    """Resolve the master password from CLI args, env, file, or prompt.

    Resolution order:
      1. ``--master-password VALUE`` (warns about process-list exposure)
      2. ``SPG_MASTER_PASSWORD`` env-var (warns about /proc exposure)
      3. ``--master-password-file PATH`` (reads first line, no warning)
      4. Interactive prompt when ``master_salt.bin`` exists
      5. ``None`` when master password is not configured
    """
    # 1. Explicit CLI flag
    if getattr(args, "master_password", None):
        logger.warning(
            "--master-password exposes the password in process lists. "
            "Prefer interactive -U/--unlock for normal use."
        )
        return args.master_password

    # 2. Environment variable
    env_pw = os.environ.get(ENV_MASTER_PASSWORD)
    if env_pw:
        logger.warning(
            "%s is set. Environment variables may be visible via "
            "/proc on Linux. Prefer interactive -U/--unlock or "
            "--master-password-file for better security.",
            ENV_MASTER_PASSWORD,
        )
        return env_pw

    # 3. Password file
    pw_file = getattr(args, "master_password_file", None)
    if pw_file:
        path = Path(pw_file)
        if not path.exists():
            raise ValueError(f"Master password file not found: {pw_file}")
        verify_file_permissions(path)
        password = path.read_text().splitlines()[0].strip()
        if not password:
            raise ValueError(
                f"Master password file is empty: {pw_file}"
            )
        return password

    # 4. Interactive prompt
    if is_master_password_enabled():
        return prompt_master_password()

    # 5. Not configured
    return None


# ---------------------------------------------------------------------------
# Master-password set / change
# ---------------------------------------------------------------------------
def set_master_password(
    new_password: str | None = None,
    current_password: str | None = None,
) -> None:
    """Configure or change the master password and re-encrypt the vault.

    Args:
        new_password: New master password (prompted if ``None``).
        current_password: Current master password when one already exists
            (prompted if ``None`` and master is already enabled).
    """
    initialize_security_files()

    # Determine old key
    if is_master_password_enabled():
        if current_password is None:
            current_password = prompt_master_password(
                "Current master password: "
            )
        old_key = get_encryption_key(current_password)
    else:
        old_key = get_encryption_key()

    # Decrypt existing vault entries with old key
    plaintext_entries: list[str] = []
    if PASSWORD_FILE.exists():
        verify_file_permissions(PASSWORD_FILE)
        with open(PASSWORD_FILE, "rb") as f:
            lines = [line.strip() for line in f if line.strip()]
        for line in lines:
            blob = base64.b64decode(line, validate=True)
            plaintext_entries.append(decrypt_data(blob, old_key))

    # Obtain new master password
    if new_password is None:
        pw1 = prompt_master_password("New master password: ")
        pw2 = prompt_master_password("Confirm master password: ")
        if pw1 != pw2:
            raise ValueError("Master passwords do not match")
        new_password = pw1
    elif not new_password:
        raise ValueError("Master password cannot be empty")

    _validate_master_password(new_password)

    # Create fresh salt and derive new combined key
    salt = secrets.token_bytes(32)
    MASTER_SALT_FILE.write_bytes(salt)
    MASTER_SALT_FILE.chmod(DEFAULT_FILE_PERMISSIONS)

    # Invalidate cached keys so new salt is used
    _KEY_CACHE.clear()
    _FINAL_KEY_CACHE.clear()
    global _SESSION_TOKEN
    _SESSION_TOKEN = None

    derived = derive_master_key(new_password, salt=salt)
    file_key = get_file_encryption_key()
    new_key = combine_keys(derived, file_key)

    # Re-encrypt vault with new key
    if plaintext_entries:
        temp_path = PASSWORD_FILE.with_suffix(".enc.tmp")
        with open(temp_path, "wb") as f:
            for plaintext in plaintext_entries:
                encrypted = encrypt_data(plaintext, new_key)
                f.write(base64.b64encode(encrypted) + b"\n")
        temp_path.chmod(DEFAULT_FILE_PERMISSIONS)
        if PASSWORD_FILE.exists():
            secure_delete_file(PASSWORD_FILE)
        temp_path.rename(PASSWORD_FILE)
        PASSWORD_FILE.chmod(DEFAULT_FILE_PERMISSIONS)

    print(f"[+] Master password configured. Salt stored at {MASTER_SALT_FILE}")
    print(
        "[+] Vault re-encrypted with two-factor key "
        "(master password + encryption.key)"
    )


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
def cleanup_files() -> None:
    """Securely delete all password and key files."""
    files_to_cleanup = [PASSWORD_FILE, KEY_FILE, PEPPER_FILE, MASTER_SALT_FILE]

    for file in files_to_cleanup:
        if file.exists():
            try:
                secure_delete_file(file)
                print(f"[+] Securely removed: {file}")
            except Exception as exc:
                logger.error("Failed to securely remove %s: %s", file, exc)

    if PASSWORD_DIR.exists():
        try:
            PASSWORD_DIR.rmdir()
            print(f"[+] Removed directory: {PASSWORD_DIR}")
        except OSError:
            logger.warning("Directory not empty, keeping: %s", PASSWORD_DIR)
