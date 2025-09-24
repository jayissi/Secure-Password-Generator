#!/usr/bin/env python3

"""
Secure Password Generator with Encryption Storage

This script generates cryptographically secure random passwords with various
configurations and securely stores them using AES-GCM-SIV encryption.
Passwords are hashed with Argon2id for verification purposes then base64 encoded.
"""

import os
import sys
import json
import base64
import secrets
import string
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any, cast
from datetime import datetime

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV


# =========================
# Configuration Constants
# =========================
MIN_PASSWORD_LENGTH = 8
DEFAULT_PASSWORD_LENGTH = 12
MAX_GENERATION_ATTEMPTS = 100

DEFAULT_FILE_PERMISSIONS = 0o600
PASSWORD_FILE = Path.home().joinpath(".password_list.enc")
KEY_FILE = Path.home().joinpath(".password_key.aes256")
PEPPER_FILE = Path.home().joinpath(".password_pepper.key")

SIMILAR_CHARS = "il1Lo0O"  # Characters to exclude when --exclude-similar is used


# =========================
# Security Utilities
# =========================
def initialize_security_files() -> None:
    """Ensure encryption and pepper key files exist with secure permissions."""
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(secrets.token_bytes(32))  # 256-bit AES key
        KEY_FILE.chmod(DEFAULT_FILE_PERMISSIONS)

    if not PEPPER_FILE.exists():
        PEPPER_FILE.write_bytes(secrets.token_bytes(32))  # 256-bit Pepper key
        PEPPER_FILE.chmod(DEFAULT_FILE_PERMISSIONS)


def get_encryption_key() -> bytes:
    """Retrieve or create the persistent AES key."""
    initialize_security_files()
    return KEY_FILE.read_bytes()


def get_pepper() -> bytes:
    """Get the dedicated pepper key for Argon2id."""
    initialize_security_files()
    return PEPPER_FILE.read_bytes()


def encrypt_data(data: str) -> bytes:
    """Encrypt JSON Payload using AES-GCM-SIV."""
    key = get_encryption_key()
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCMSIV(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return nonce + ciphertext  # Store nonce with ciphertext


def decrypt_data(encrypted: bytes) -> str:
    """Decrypt AES-GCM-SIV ciphertext (nonce||ciphertext)."""
    key = get_encryption_key()
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCMSIV(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def argon2id_hash(password: str) -> Dict[str, Any]:
    """
    Derive Argon2id digest with salt + pepper.
    Salt is unique per password. Pepper is loaded from a separate secure file.
    """
    salt = secrets.token_bytes(32)  # 256-bit unique salt per password
    pepper = get_pepper()  # 🔐 the "pepper"

    # Parameters chosen for a reasonable balance; tune to your environment
    params = {
        "length": 64,  # 512-bit digest
        "iterations": 100,  # time cost
        "lanes": 4,  # parallelism
        "memory_cost": 64 * 1024,  # 64 MiB
    }

    kdf = Argon2id(
        salt=salt,
        length=params["length"],
        iterations=params["iterations"],
        lanes=params["lanes"],
        memory_cost=params["memory_cost"],
        secret=pepper,  # Dedicated pepper
    )
    digest = kdf.derive(password.encode("utf-8"))

    return {
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "digest_b64": base64.b64encode(digest).decode("ascii"),
        "params": params,
    }


def generate_symbol_only_password(length: int, symbols: str) -> str:
    """
    Generate password using only symbols with no consecutive repeats.

    Args:
        length: Desired password length
        symbols: Allowed symbols to use

    Returns:
        Generated password string

    Raises:
        ValueError: If unable to generate password with given constraints
    """
    unique_symbols = list(set(symbols))
    num_symbols = len(unique_symbols)

    if num_symbols == 1:
        raise ValueError(
            "Cannot generate password with --no-repeats using only 1 symbol. "
            "Add more symbols or enable other character types."
        )

    password = []
    last_char = None
    symbol_counts = {s: 0 for s in unique_symbols}
    target_count = length // num_symbols

    while len(password) < length:
        candidates = [s for s in unique_symbols if s != last_char]
        underused = [s for s in candidates if symbol_counts[s] < target_count]
        if underused:
            candidates = underused

        char = secrets.choice(candidates)
        password.append(char)
        symbol_counts[char] += 1
        last_char = char

    return "".join(password)


# =========================
# Password Generation
# =========================
def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    min_characters_per_type: Optional[int] = None,
    exclude_similar: bool = False,
    allowed_symbols: Optional[str] = None,
    no_repeats: bool = False,
    blank: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    This implementation reserves distinct positions for each selected character
    type to satisfy the --min requirement (including blank when requested).
    Reserving prevents later placements from overwriting earlier enforced minima.

    Args:
        length: Desired password length
        use_upper: Include uppercase letters
        use_lower: Include lowercase letters
        use_digits: Include digits
        use_symbols: Include symbols
        min_characters_per_type: Minimum characters from each selected type
        exclude_similar: Exclude similar-looking characters
        allowed_symbols: Specific symbols to allow
        no_repeats: Prevent consecutive duplicate characters
        blank: Include space character as an available character (never first/last)

    Returns:
        Generated password string

    Raises:
        ValueError: If unable to generate password with given constraints
    """
    if length < MIN_PASSWORD_LENGTH:
        print(
            f"[!] Password length increased to minimum of {MIN_PASSWORD_LENGTH} characters"
        )
        length = MIN_PASSWORD_LENGTH

    effective_symbols = (
        allowed_symbols
        if allowed_symbols
        else (string.punctuation if use_symbols else "")
    )

    # Handle symbol-only case separately (space char isn't part of effective_symbols)
    if effective_symbols and not (use_upper or use_lower or use_digits):
        if no_repeats:
            return generate_symbol_only_password(length, effective_symbols)
        elif len(set(effective_symbols)) < 2 and length > 1:
            raise ValueError(
                "Cannot generate password with only 1 symbol and length > 1. "
                "Add more symbols or enable other character types."
            )

    # Build tuple-list of (name, chars) for selected character types
    charset_tuples = []
    if use_upper:
        up = string.ascii_uppercase
        if exclude_similar:
            up = "".join(c for c in up if c not in SIMILAR_CHARS)
        charset_tuples.append(("upper", up))
    if use_lower:
        lo = string.ascii_lowercase
        if exclude_similar:
            lo = "".join(c for c in lo if c not in SIMILAR_CHARS)
        charset_tuples.append(("lower", lo))
    if use_digits:
        dg = string.digits
        if exclude_similar:
            dg = "".join(c for c in dg if c not in SIMILAR_CHARS)
        charset_tuples.append(("digits", dg))
    if effective_symbols:
        # May contain characters not affected by SIMILAR_CHARS filter (mostly letters/digits)
        charset_tuples.append(("symbols", effective_symbols))
    if blank:
        # Add blank (space) as its own character set if requested
        charset_tuples.append(("blank", " "))

    # Validate character sets
    for name, chars in charset_tuples:
        if not chars:
            raise ValueError(f"No {name} characters available after filtering")

    if not charset_tuples:
        raise ValueError("At least one character type must be selected.")

    # Concatenate all chars for filling non-reserved slots
    all_chars = "".join(chars for _n, chars in charset_tuples)

    # Attempt password generation with retries
    for attempt in range(MAX_GENERATION_ATTEMPTS):
        try:
            # slots holds final characters (None for unfilled)
            slots: List[Optional[str]] = [None] * length
            reserved_positions = set()

            # helper: check if placing ch at pos would violate no_repeats with already-filled neighbors
            def violates_no_repeats(ch: str, pos: int) -> bool:
                if not no_repeats:
                    return False
                if pos > 0 and slots[pos - 1] is not None and slots[pos - 1] == ch:
                    return True
                if (
                    pos < length - 1
                    and slots[pos + 1] is not None
                    and slots[pos + 1] == ch
                ):
                    return True
                return False

            # Reserve positions and place characters to satisfy minima first (avoid overwrites)
            if min_characters_per_type:
                available_positions = set(range(length))
                for name, chars in charset_tuples:
                    filtered = (
                        "".join(c for c in chars if c not in SIMILAR_CHARS)
                        if exclude_similar
                        else chars
                    )
                    if not filtered:
                        continue

                    # Determine how many of this charset we need to place
                    # At this point there are no pre-existing placements, so existing_count == 0
                    needed = max(0, min_characters_per_type)

                    if needed == 0:
                        continue

                    # Candidate positions: still available and obey blank-not-at-ends rule
                    candidates = [p for p in range(length) if p in available_positions]
                    if name == "blank":
                        candidates = [
                            p for p in candidates if p != 0 and p != length - 1
                        ]

                    if len(candidates) < needed:
                        raise ValueError(
                            "Not enough positions to satisfy minimum characters for selected types"
                        )

                    chosen_positions = secrets.SystemRandom().sample(candidates, needed)
                    for pos in chosen_positions:
                        # Try selecting a concrete character from filtered that doesn't break no_repeats
                        placed = False
                        trials = 0
                        while trials < 200 and not placed:
                            ch = secrets.choice(filtered)
                            if violates_no_repeats(ch, pos):
                                trials += 1
                                continue
                            slots[pos] = ch
                            reserved_positions.add(pos)
                            if pos in available_positions:
                                available_positions.remove(pos)
                            placed = True

                        if not placed:
                            # If we couldn't place a char at this pos, abort this attempt and retry
                            raise ValueError(
                                "Unable to place required characters without violating constraints"
                            )

            # Fill remaining (non-reserved) slots
            for i in range(length):
                if slots[i] is not None:
                    continue

                choices = list(all_chars)

                # blank not allowed at first or last positions
                if blank and (i == 0 or i == length - 1):
                    choices = [c for c in choices if c != " "]

                # enforce no_repeats against already filled left neighbor
                if no_repeats and i > 0 and slots[i - 1] is not None:
                    choices = [c for c in choices if c != slots[i - 1]]

                if not choices:
                    raise ValueError(
                        "No available characters to fill slot considering constraints"
                    )

                slots[i] = secrets.choice(choices)

            if any(ch is None for ch in slots):
                raise ValueError("Internal error: incomplete password construction")
            password = "".join(cast(List[str], slots))

            # Verify minima were satisfied for each selected charset
            if min_characters_per_type:
                for name, chars in charset_tuples:
                    filtered = (
                        "".join(c for c in chars if c not in SIMILAR_CHARS)
                        if exclude_similar
                        else chars
                    )
                    if not filtered:
                        continue
                    count = sum(1 for c in password if c in filtered)
                    if count < min_characters_per_type:
                        raise ValueError(
                            "Minima not satisfied after construction - retrying"
                        )

            # Final sanity checks
            if blank and (password[0] == " " or password[-1] == " "):
                # If blanks ended up at edges, this attempt fails and we retry
                raise ValueError(
                    "Blank character landed at the first or last position - retrying"
                )

            if no_repeats:
                for i in range(1, length):
                    if password[i] == password[i - 1]:
                        raise ValueError(
                            "Consecutive duplicate characters detected - retrying"
                        )

            return password

        except ValueError:
            if attempt == MAX_GENERATION_ATTEMPTS - 1:
                raise ValueError(
                    f"Failed to generate password after {MAX_GENERATION_ATTEMPTS} attempts"
                )
            continue

    raise ValueError(f"Failed to generate password after {MAX_GENERATION_ATTEMPTS} attempts")


# =========================
# History Management
# =========================
def save_password(password: str, filename: Path = PASSWORD_FILE) -> None:
    """Securely save encrypted password record to file."""
    try:
        record = {
            "timestamp": datetime.now().strftime("%a, %b %d, %Y %I:%M:%S:%f %p"),
            "password": password,
            "argon2id": argon2id_hash(password),
        }
        plaintext = json.dumps(record, separators=(",", ":"))
        encrypted = encrypt_data(plaintext)
        line = base64.b64encode(encrypted) + b"\n"

        with open(filename, "ab") as f:
            f.write(line)
        filename.chmod(DEFAULT_FILE_PERMISSIONS)
    except Exception as e:
        print(f"Error saving password: {e}", file=sys.stderr)
        raise


def show_password_history(filename: Path = PASSWORD_FILE) -> None:
    """Display decrypted password history."""
    try:
        if not filename.exists():
            print("No password history available")
            return

        print("\nPassword History:")
        print("-" * 60)
        with open(filename, "rb") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    print(f"{idx}. [INVALID ENTRY - empty line]")
                    continue

                try:
                    blob = base64.b64decode(line, validate=True)
                    rec_json = decrypt_data(blob)
                    rec = json.loads(rec_json)

                    timestamp = rec.get("timestamp", "?")
                    password = rec.get("password", "?")
                    # salt_b64 = rec.get("argon2id", {}).get("salt_b64", "?")

                    print(f"{idx}. Password: {password}")
                    # print(f"   Salt: {salt_b64}")
                    print(f"   Timestamp: {timestamp}\n")
                except Exception as e:
                    print(f"{idx}. [INVALID ENTRY - {e}]")
        print("-" * 60)
    except Exception as e:
        print(f"Error reading history: {e}", file=sys.stderr)


def cleanup_files() -> None:
    """Clean up the password and key files."""
    for file in (PASSWORD_FILE, KEY_FILE, PEPPER_FILE):
        if file.exists():
            try:
                file.unlink()
                print(f"[✓] Removed file: {file}")
            except Exception as e:
                print(f"[!] Failed to remove {file}: {e}", file=sys.stderr)
                sys.exit(1)


# =========================
# CLI Arguments
# =========================
def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""

    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_usage(self, usage, actions, groups, prefix):
            help_text = super()._format_usage(usage, actions, groups, prefix)
            help_text += "\nExamples:\n"
            help_text += "  Generate a password:\n"
            help_text += "    python password_generator.py -L 24 -blunders \n\n"
            help_text += "  Generate multiple passwords with specific requirements:\n"
            help_text += "    python password_generator.py --length 24 \\\n"
            help_text += "      --upper --lower --digits --symbols --blank \\\n"
            help_text += "      --allowed-symbols '@#$%%' --min 2 --count 5 \\\n"
            help_text += "      --exclude-similar --no-repeats --no-save\n\n"
            return help_text

    parser = argparse.ArgumentParser(
        description="Generate strong random passwords.",
        formatter_class=CustomHelpFormatter,
        add_help=False,
    )

    # Argument groups for better organization
    basic_group = parser.add_argument_group("Basic Options")
    char_group = parser.add_argument_group("Character Type Options")
    advanced_group = parser.add_argument_group("Advanced Options")
    file_group = parser.add_argument_group("File Operations")

    # Basic options
    basic_group.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Show this help message and exit",
    )
    basic_group.add_argument(
        "-P",
        "--passphrase",
        type=str,
        help="Use a custom passphrase instead of generating a secure password (supersedes other options)",
    )
    basic_group.add_argument(
        "-L",
        "--length",
        type=int,
        default=DEFAULT_PASSWORD_LENGTH,
        help=f"Password length (minimum: {MIN_PASSWORD_LENGTH})",
    )
    basic_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help="Number of passwords to generate",
    )

    # Character type options
    char_group.add_argument(
        "-u",
        "--upper",
        action="store_true",
        help="Include uppercase letters",
    )
    char_group.add_argument(
        "-l",
        "--lower",
        action="store_true",
        help="Include lowercase letters",
    )
    char_group.add_argument(
        "-d",
        "--digits",
        action="store_true",
        help="Include digits",
    )
    char_group.add_argument(
        "-s",
        "--symbols",
        action="store_true",
        help="Include symbols",
    )
    char_group.add_argument(
        "-a",
        "--allowed-symbols",
        type=str,
        help="Specify allowed symbols (implies --symbols, e.g., @#$%%)",
    )
    char_group.add_argument(
        "-b",
        "--blank",
        action="store_true",
        help="Include blank (space) character (never placed as first or last character)",
    )

    # Advanced options
    advanced_group.add_argument(
        "-m",
        "--min",
        type=int,
        dest="min_chars",
        default=1,
        help="Minimum characters from each selected type",
    )
    advanced_group.add_argument(
        "-e",
        "--exclude-similar",
        action="store_true",
        help="Exclude similar-looking characters (i, l, 1, L, o, 0, O)",
    )
    advanced_group.add_argument(
        "-r",
        "--no-repeats",
        action="store_true",
        help="Prevent consecutive duplicate characters",
    )

    # File operations
    file_group.add_argument(
        "-n",
        "--no-save",
        action="store_true",
        help="Do not save the password to file",
    )
    file_group.add_argument(
        "-H",
        "--show-history",
        action="store_true",
        help="Show password generation history",
    )
    file_group.add_argument(
        "-C",
        "--cleanup",
        action="store_true",
        help="Clean up password and key files",
    )

    return parser


# =========================
# CLI Interface
# =========================
def main() -> None:
    """Main entry point for the password generator."""
    parser = create_argument_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    if args.cleanup:
        cleanup_files()
        sys.exit(0)

    if args.show_history:
        show_password_history()
        sys.exit(0)

    if args.allowed_symbols:
        args.symbols = True

    try:
        if args.passphrase:
            # Passphrase mode - supersedes all other options
            print("[ Custom Passphrase Mode ]")
            print(f"Using provided passphrase: {args.passphrase}")

            if not args.no_save:
                save_password(args.passphrase)
                print(f"✓ Passphrase securely saved to {PASSWORD_FILE}")
            else:
                print("⚠ Passphrase not saved (--no-save flag was set)")

            sys.exit(0)

        for i in range(args.count):
            password = generate_password(
                length=args.length,
                use_upper=args.upper,
                use_lower=args.lower,
                use_digits=args.digits,
                use_symbols=args.symbols,
                min_characters_per_type=args.min_chars,
                exclude_similar=args.exclude_similar,
                allowed_symbols=args.allowed_symbols,
                no_repeats=args.no_repeats,
                blank=args.blank,
            )
            print(f"Generated Password {i+1}: {password}")

            if not args.no_save:
                save_password(password)

        if not args.no_save and args.count > 0:
            print(f"[✓] Passwords securely saved to {PASSWORD_FILE}")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()