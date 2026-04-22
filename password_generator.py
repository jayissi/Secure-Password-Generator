#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

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
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, cast, Callable, Tuple
from datetime import datetime

import argcomplete
from argcomplete.completers import FilesCompleter
import yaml
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV


# =========================
# Configuration Constants
# =========================
MIN_PASSWORD_LENGTH = 8
DEFAULT_PASSWORD_LENGTH = 12
MAX_GENERATION_ATTEMPTS = 100
SECURE_DELETE_PASSES = 3

DEFAULT_FILE_PERMISSIONS = 0o600
DEFAULT_DIR_PERMISSIONS = 0o700

# Secure directory structure
PASSWORD_DIR = Path.home().joinpath(".secure_passwords")
PASSWORD_FILE = PASSWORD_DIR.joinpath("vault.enc")
KEY_FILE = PASSWORD_DIR.joinpath("encryption.key")
PEPPER_FILE = PASSWORD_DIR.joinpath("pepper.key")

SIMILAR_CHARS = "il1Lo0O"  # Characters to exclude when --exclude-similar is used

# Argon2id parameters (tune to your environment)
ARGON2_DIGEST_LENGTH = 64      # 512-bit digest
ARGON2_ITERATIONS = 100        # time cost
ARGON2_LANES = 4               # parallelism
ARGON2_MEMORY_COST = 64 * 1024 # 64 MiB

# ANSI color codes for strength meter
COLOR_RED = "\033[91m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"


# =========================
# Performance Optimization: Clipboard Caching
# =========================
_CLIPBOARD_INITIALIZED = False
_CLIPBOARD_METHOD: Optional[Callable[[str], bool]] = None


# =========================
# Performance Optimization: Encryption Key Caching
# =========================
_KEY_CACHE: Dict[str, Tuple[bytes, float]] = {}


# =========================
# Security Utilities
# =========================
def initialize_security_files() -> None:
    """Ensure secure directory and encryption/pepper key files exist with secure permissions."""
    if not PASSWORD_DIR.exists():
        PASSWORD_DIR.mkdir(mode=DEFAULT_DIR_PERMISSIONS)
        PASSWORD_DIR.chmod(DEFAULT_DIR_PERMISSIONS)

    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(secrets.token_bytes(32))  # 256-bit AES key
        KEY_FILE.chmod(DEFAULT_FILE_PERMISSIONS)

    if not PEPPER_FILE.exists():
        PEPPER_FILE.write_bytes(secrets.token_bytes(32))  # 256-bit Pepper key
        PEPPER_FILE.chmod(DEFAULT_FILE_PERMISSIONS)


def _get_cached_key(file_path: Path, cache_key: str) -> bytes:
    """Helper to retrieve a cached key file, refreshing if file was modified."""
    initialize_security_files()
    
    current_mtime = file_path.stat().st_mtime if file_path.exists() else 0.0
    cached = _KEY_CACHE.get(cache_key)
    
    if cached is None or cached[1] != current_mtime:
        key_bytes = file_path.read_bytes()
        _KEY_CACHE[cache_key] = (key_bytes, current_mtime)
        return key_bytes
    
    return cached[0]


def get_encryption_key() -> bytes:
    """Retrieve or create the persistent AES key (cached)."""
    return _get_cached_key(KEY_FILE, "encryption")


def get_pepper() -> bytes:
    """Get the dedicated pepper key for Argon2id (cached)."""
    return _get_cached_key(PEPPER_FILE, "pepper")


def secure_delete_file(file_path: Path, passes: int = SECURE_DELETE_PASSES) -> None:
    """
    Securely delete a file by overwriting with random data multiple times.
    
    Args:
        file_path: Path to file to securely delete
        passes: Number of overwrite passes (default: SECURE_DELETE_PASSES)
    """
    if not file_path.exists():
        return
    
    file_size = file_path.stat().st_size
    
    # Overwrite with random data multiple times
    with open(file_path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(secrets.token_bytes(file_size))
            f.flush()
            os.fsync(f.fileno())
    
    # Delete the file
    file_path.unlink()


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


def calculate_password_strength(password: str) -> int:
    """
    Calculate password strength based on length, character types, and uniqueness.
    
    Scoring factors:
    - Length (PRIMARY): Longer passwords score higher
    - Character type diversity (SECONDARY): More types = bonus
    - Character uniqueness (TERTIARY): Repeated chars = penalty
    
    Args:
        password: Password string to evaluate
        
    Returns:
        Strength score from 1-10 (int)
    """
    if not password:
        return 1
    
    length = len(password)
    
    # Count character types (complexity)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() and c != ' ' for c in password)
    has_blank = ' ' in password
    
    char_types = sum([has_upper, has_lower, has_digit, has_symbol, has_blank])
    
    # PRIMARY: Base score from length
    # Aggressive thresholds to encourage longer passwords
    if length >= 24:
        base_score = 8
    elif length >= 20:
        base_score = 7
    elif length >= 16:
        base_score = 6
    elif length >= 14:
        base_score = 5
    elif length >= 12:
        base_score = 4
    elif length >= 10:
        base_score = 3
    elif length >= 8:
        base_score = 2
    else:
        base_score = 1
    
    # SECONDARY: Character type diversity bonus
    # Rewards using multiple character types
    if char_types >= 5:
        base_score = min(10, base_score + 2)  # All types + space
    elif char_types >= 4:
        base_score = min(10, base_score + 2)  # All types
    elif char_types == 3:
        base_score = min(10, base_score + 1)  # Three types
    elif char_types == 2:
        # No bonus for 2 types (encourage more)
        pass
    else:
        # Penalty for single type (strongly encourage diversity)
        base_score = max(1, base_score - 1)
    
    # TERTIARY: Character uniqueness penalty
    # Penalize passwords with repeated characters
    unique_chars = len(set(password))
    uniqueness_ratio = unique_chars / length if length > 0 else 0
    
    # Penalty for low uniqueness (high repetition)
    if uniqueness_ratio < 0.5:
        # More than half the characters are repeats
        base_score = max(1, base_score - 2)
    elif uniqueness_ratio < 0.7:
        # 30-50% repetition
        base_score = max(1, base_score - 1)
    # No penalty for uniqueness_ratio >= 0.7 (good diversity)
    
    # Additional penalty for consecutive repeated characters
    consecutive_penalty = 0
    consecutive_count = 1
    for i in range(1, len(password)):
        if password[i] == password[i-1]:
            consecutive_count += 1
            if consecutive_count >= 3:
                consecutive_penalty += 1
        else:
            consecutive_count = 1
    
    base_score = max(1, base_score - consecutive_penalty)
    
    # Pattern penalty (catch weak patterns)
    pattern_penalty = 0
    simple_patterns = ['123', 'abc', 'qwe', 'asd', 'password', 'admin']
    for pattern in simple_patterns:
        if pattern in password.lower():
            pattern_penalty += 2
    
    base_score = max(1, base_score - pattern_penalty)
    
    return max(1, min(10, base_score))


def get_strength_color(score: int) -> str:
    """Get color code based on password strength score."""
    if score >= 8:
        return COLOR_GREEN
    elif score >= 6:
        return COLOR_YELLOW
    elif score >= 4:
        return COLOR_ORANGE
    else:
        return COLOR_RED


def format_strength_meter(score: int) -> str:
    """Format strength score with color and visual meter."""
    color = get_strength_color(score)
    bars = "█" * score + "░" * (10 - score)
    return f"{color}{bars} {score}/10{COLOR_RESET}"


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


def generate_password_from_pattern(pattern: str, allowed_symbols: str = string.punctuation) -> str:
    """
    Generate password based on a pattern string.
    
    Pattern codes:
    l = lowercase letter
    u = uppercase letter  
    d = digit
    s = symbol
    b = blank (space)
    * = random character from all types
    
    Args:
        pattern: Pattern string (e.g., "lluuddss" for 2 lower, 2 upper, 2 digits, 2 symbols)
        allowed_symbols: Symbols to use for 's' pattern
        
    Returns:
        Generated password string
    """
    char_sets = {
        'l': string.ascii_lowercase,
        'u': string.ascii_uppercase,
        'd': string.digits,
        's': allowed_symbols,
        'b': ' ',
        '*': string.ascii_letters + string.digits + allowed_symbols
    }
    
    password = []
    for code in pattern:
        if code in char_sets:
            chars = char_sets[code]
            if not chars:
                raise ValueError(f"No characters available for pattern code '{code}'")
            password.append(secrets.choice(chars))
        else:
            # Use literal character
            password.append(code)
    
    return ''.join(password)


# =========================
# Performance Optimization: Password Generation Helpers
# =========================
def _filter_similar_chars(chars: str, exclude_similar: bool) -> str:
    """Filter similar characters if requested (cached operation)."""
    if not exclude_similar:
        return chars
    return "".join(c for c in chars if c not in SIMILAR_CHARS)


def _validate_generation_feasibility(
    length: int,
    charset_tuples: List[Tuple[str, str]],
    min_chars: Optional[int],
    no_repeats: bool,
    blank: bool
) -> None:
    """Validate that password generation is feasible before attempting."""
    if not charset_tuples:
        raise ValueError("At least one character type must be selected.")
    
    if min_chars:
        total_min_needed = sum(1 for name, _ in charset_tuples if name != "blank") * min_chars
        if blank:
            total_min_needed += min_chars
        
        # Account for blank not being at ends
        available_positions = length - (2 if blank else 0)
        
        if total_min_needed > available_positions:
            raise ValueError(
                f"Not enough positions ({available_positions}) to satisfy "
                f"minimum characters requirement ({total_min_needed})"
            )
    
    # Check if no_repeats is feasible
    if no_repeats:
        unique_chars = set()
        for _, chars in charset_tuples:
            unique_chars.update(chars)
        if len(unique_chars) < 2 and length > 1:
            raise ValueError(
                "Cannot generate password with --no-repeats using only 1 unique character"
            )


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
    pattern: Optional[str] = None,
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
        pattern: Generate password from pattern string

    Returns:
        Generated password string

    Raises:
        ValueError: If unable to generate password with given constraints
    """
    # Handle pattern-based generation
    if pattern:
        effective_symbols = allowed_symbols if allowed_symbols else string.punctuation
        return generate_password_from_pattern(pattern, effective_symbols)

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

    # Build and filter character sets ONCE (optimization)
    charset_tuples = []
    if use_upper:
        up = _filter_similar_chars(string.ascii_uppercase, exclude_similar)
        if up:
            charset_tuples.append(("upper", up))
    if use_lower:
        lo = _filter_similar_chars(string.ascii_lowercase, exclude_similar)
        if lo:
            charset_tuples.append(("lower", lo))
    if use_digits:
        dg = _filter_similar_chars(string.digits, exclude_similar)
        if dg:
            charset_tuples.append(("digits", dg))
    if effective_symbols:
        sym = _filter_similar_chars(effective_symbols, exclude_similar)
        if sym:
            charset_tuples.append(("symbols", sym))
    if blank:
        charset_tuples.append(("blank", " "))

    # Validate character sets
    for name, chars in charset_tuples:
        if not chars:
            raise ValueError(f"No {name} characters available after filtering")

    # Validate BEFORE attempting generation (optimization)
    _validate_generation_feasibility(
        length, charset_tuples, min_characters_per_type, no_repeats, blank
    )

    # Pre-compute all_chars string (no list conversion needed)
    all_chars = "".join(chars for _, chars in charset_tuples)

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
                    # Use already-filtered chars (optimization: no redundant filtering)
                    if not chars:
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
                        # Try selecting a concrete character from chars that doesn't break no_repeats
                        placed = False
                        trials = 0
                        while trials < 200 and not placed:
                            ch = secrets.choice(chars)
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

                # Optimization: Use string operations instead of list conversion
                choices_str = all_chars

                # blank not allowed at first or last positions
                if blank and (i == 0 or i == length - 1):
                    choices_str = choices_str.replace(" ", "")

                # enforce no_repeats against already filled left neighbor
                if no_repeats and i > 0:
                    prev_char = slots[i - 1]
                    if prev_char is not None:
                        choices_str = choices_str.replace(prev_char, "")

                if not choices_str:
                    raise ValueError(
                        "No available characters to fill slot considering constraints"
                    )

                slots[i] = secrets.choice(choices_str)

            if any(ch is None for ch in slots):
                raise ValueError("Internal error: incomplete password construction")
            password = "".join(cast(List[str], slots))

            # Verify minima were satisfied for each selected charset
            if min_characters_per_type:
                for name, chars in charset_tuples:
                    if not chars:
                        continue
                    count = sum(1 for c in password if c in chars)
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
def format_history_table(entries: List[Dict[str, Any]]) -> str:
    """
    Format password history as a table.
    
    Args:
        entries: List of password record dictionaries
        
    Returns:
        Formatted table string
    """
    if not entries:
        return "No entries to display."
    
    # Table headers
    headers = ["#", "Label", "Password", "Strength", "Category", "Created"]
    
    # Calculate column widths
    col_widths = {
        "#": 3,
        "Label": max(12, max(len(str(e.get("label", "N/A"))) for e in entries)),
        "Password": max(20, max(len(str(e.get("password", ""))) for e in entries)),
        "Strength": 12,
        "Category": max(10, max(len(str(e.get("category", "N/A"))) for e in entries)),
        "Created": 20
    }
    
    # Build table
    lines = []
    
    # Header row
    header_row = "│ " + " │ ".join(h.ljust(col_widths[h]) for h in headers) + " │"
    separator = "├" + "┼".join("─" * (w + 2) for w in col_widths.values()) + "┤"
    top_border = "┌" + "┬".join("─" * (w + 2) for w in col_widths.values()) + "┐"
    bottom_border = "└" + "┴".join("─" * (w + 2) for w in col_widths.values()) + "┘"
    
    lines.append(top_border)
    lines.append(header_row)
    lines.append(separator)
    
    # Data rows
    for idx, entry in enumerate(entries, 1):
        label = str(entry.get("label", "N/A"))
        password = str(entry.get("password", "?"))
        strength = entry.get("strength", 0)
        strength_numeric = f"{strength}/10"
        category = str(entry.get("category", "N/A"))
        timestamp = entry.get("timestamp", "?")
        # Format timestamp to shorter format
        try:
            dt = datetime.strptime(timestamp, "%a, %b %d, %Y %I:%M:%S:%f %p")
            short_time = dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            short_time = timestamp[:16] if len(timestamp) > 16 else timestamp
        
        row = (
            f"│ {str(idx).ljust(col_widths['#'])} │ "
            f"{label[:col_widths['Label']].ljust(col_widths['Label'])} │ "
            f"{password[:col_widths['Password']].ljust(col_widths['Password'])} │ "
            f"{strength_numeric.ljust(col_widths['Strength'])} │ "
            f"{category[:col_widths['Category']].ljust(col_widths['Category'])} │ "
            f"{short_time.ljust(col_widths['Created'])} │"
        )
        lines.append(row)
    
    lines.append(bottom_border)
    
    return "\n".join(lines)


def save_password(
    password: str,
    filename: Path = PASSWORD_FILE,
    label: Optional[str] = None,
    category: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> None:
    """Securely save encrypted password record with metadata."""
    try:
        strength = calculate_password_strength(password)
        record = {
            "timestamp": datetime.now().strftime("%a, %b %d, %Y %I:%M:%S:%f %p"),
            "password": password,
            "strength": strength,
            "label": label or "Unnamed",
            "category": category or "General",
            "tags": tags or [],
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


def show_password_history(
    filename: Path = PASSWORD_FILE,
    limit: Optional[int] = None,
    search: Optional[str] = None,
    filter_strength: Optional[int] = None,
    filter_category: Optional[str] = None,
    since: Optional[str] = None,
    use_table: bool = True
) -> None:
    """Display password history with optional filtering and table format."""
    try:
        if not filename.exists():
            print("No password history available")
            return

        # Read all entries (newest first)
        with open(filename, "rb") as f:
            entries = [line.strip() for line in f if line.strip()]
        entries.reverse()
        
        # Decrypt and filter entries
        filtered_entries = []
        for line in entries:
            try:
                blob = base64.b64decode(line, validate=True)
                rec_json = decrypt_data(blob)
                rec = json.loads(rec_json)
                
                # Apply filters
                if search:
                    search_lower = search.lower()
                    if (search_lower not in rec.get("label", "").lower() and
                        search_lower not in rec.get("category", "").lower() and
                        search_lower not in " ".join(rec.get("tags", [])).lower()):
                        continue
                
                if filter_strength is not None:
                    if rec.get("strength", 0) < filter_strength:
                        continue
                
                if filter_category:
                    if rec.get("category", "").lower() != filter_category.lower():
                        continue
                
                if since:
                    try:
                        since_dt = datetime.strptime(since, "%Y-%m-%d")
                        entry_dt = datetime.strptime(rec.get("timestamp", ""), "%a, %b %d, %Y %I:%M:%S:%f %p")
                        if entry_dt < since_dt:
                            continue
                    except ValueError:
                        pass
                
                filtered_entries.append(rec)
            except Exception as e:
                continue  # Skip invalid entries
        
        # Apply limit
        if limit:
            filtered_entries = filtered_entries[:limit]
        
        # Display
        if use_table:
            print("\n" + format_history_table(filtered_entries))
        else:
            # Original format
            print("\nPassword History:")
            print("-" * 80)
            for idx, entry in enumerate(filtered_entries, 1):
                timestamp = entry.get("timestamp", "?")
                password = entry.get("password", "?")
                strength = entry.get("strength", 0)
                strength_display = format_strength_meter(strength)
                label = entry.get("label", "N/A")
                category = entry.get("category", "N/A")
                tags = entry.get("tags", [])
                
                print(f"{idx}. Label: {label}")
                print(f"   Password: {password}")
                print(f"   Strength: {strength_display}")
                print(f"   Category: {category}")
                if tags:
                    print(f"   Tags: {', '.join(tags)}")
                print(f"   Timestamp: {timestamp}\n")
            print("-" * 80)
    except Exception as e:
        print(f"Error reading history: {e}", file=sys.stderr)


def delete_entry_by_index(
    index: int,
    filename: Path = PASSWORD_FILE
) -> None:
    """Delete a specific entry by index with secure deletion."""
    if not filename.exists():
        print("No password history available")
        return
    
    # Read all entries (newest first for display)
    with open(filename, "rb") as f:
        entries = [line.strip() for line in f if line.strip()]
    entries.reverse()
    
    if index < 1 or index > len(entries):
        print(f"Invalid index. Valid range: 1-{len(entries)}")
        return
    
    # Remove the entry
    target_entry = entries[index - 1]
    entries.remove(target_entry)
    
    # Securely delete old file
    secure_delete_file(filename)
    
    # Write remaining entries (back to file order: oldest first)
    entries.reverse()
    with open(filename, "wb") as f:
        for entry in entries:
            f.write(entry + b"\n")
    
    filename.chmod(DEFAULT_FILE_PERMISSIONS)
    print(f"[✓] Entry {index} securely deleted")


def _initialize_clipboard() -> Optional[Callable[[str], bool]]:
    """Initialize and cache clipboard method once (RHEL/Fedora Linux only)."""
    global _CLIPBOARD_INITIALIZED, _CLIPBOARD_METHOD
    if _CLIPBOARD_INITIALIZED:
        return _CLIPBOARD_METHOD
    
    # Try pyperclip first (preferred for Linux)
    try:
        import pyperclip
        def _pyperclip_copy(text: str) -> bool:
            try:
                pyperclip.copy(text)
                return True
            except Exception:
                return False
        _CLIPBOARD_METHOD = _pyperclip_copy
        _CLIPBOARD_INITIALIZED = True
        return _CLIPBOARD_METHOD
    except ImportError:
        pass
    
    # Try xclip for Linux (fallback)
    try:
        def _xclip_copy(text: str) -> bool:
            try:
                process = subprocess.Popen(
                    ['xclip', '-selection', 'clipboard'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                process.communicate(text.encode('utf-8'), timeout=2)
                return process.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                return False
        _CLIPBOARD_METHOD = _xclip_copy
        _CLIPBOARD_INITIALIZED = True
        return _CLIPBOARD_METHOD
    except Exception:
        pass
    
    _CLIPBOARD_INITIALIZED = True
    return None


def copy_to_clipboard(password: str) -> bool:
    """Copy password to system clipboard using cached method."""
    method = _initialize_clipboard()
    if method is None:
        return False
    try:
        return method(password)
    except Exception:
        return False


def cleanup_files() -> None:
    """Clean up password and key files with secure deletion."""
    files_to_cleanup = [PASSWORD_FILE, KEY_FILE, PEPPER_FILE]
    
    for file in files_to_cleanup:
        if file.exists():
            try:
                secure_delete_file(file)
                print(f"[✓] Securely removed: {file}")
            except Exception as e:
                print(f"[!] Failed to securely remove {file}: {e}", file=sys.stderr)
    
    # Remove directory if empty
    if PASSWORD_DIR.exists():
        try:
            PASSWORD_DIR.rmdir()
            print(f"[✓] Removed directory: {PASSWORD_DIR}")
        except OSError:
            print(f"[!] Directory not empty, keeping: {PASSWORD_DIR}")


# =========================
# Config File Support
# =========================
VALID_CONFIG_KEYS = {
    "length", "upper", "lower", "digits", "symbols",
    "no_repeats", "exclude_similar", "min_chars",
    "allowed_symbols", "blank_space", "label", "category", "tags",
    "save_history",
}

CONFIG_KEY_MAP = {
    "blank_space": "blank",
}


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load and validate a YAML or JSON config file.

    Format is auto-detected by file extension (.yaml/.yml for YAML, .json for JSON).
    All fields are optional; unknown keys cause an error.

    Args:
        config_path: Path to the config file

    Returns:
        Dictionary of config values with keys mapped to argparse dest names
    """
    path = Path(config_path)
    if not path.exists():
        print(f"[!] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    suffix = path.suffix.lower()

    try:
        with open(path) as f:
            if suffix in (".yaml", ".yml"):
                config = yaml.safe_load(f) or {}
            elif suffix == ".json":
                config = json.load(f)
            else:
                print(
                    f"[!] Unsupported config format '{suffix}'. Use .yaml, .yml, or .json",
                    file=sys.stderr,
                )
                sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[!] Invalid YAML in config file: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in config file: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(config, dict):
        print("[!] Config file must contain a YAML mapping or JSON object", file=sys.stderr)
        sys.exit(1)

    unknown = set(config.keys()) - VALID_CONFIG_KEYS
    if unknown:
        print(f"[!] Unknown config keys: {', '.join(sorted(unknown))}", file=sys.stderr)
        sys.exit(1)

    mapped: Dict[str, Any] = {}
    for key, value in config.items():
        dest = CONFIG_KEY_MAP.get(str(key), str(key))
        mapped[dest] = value

    return mapped


# =========================
# CLI Arguments
# =========================
def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""

    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_usage(self, usage, actions, groups, prefix):
            help_text = super()._format_usage(usage, actions, groups, prefix)
            help_text += "\nExamples:\n"
            help_text += "  # Generate strong password with all character types\n"
            help_text += "  python password_generator.py -F -L 24\n\n"
            help_text += "  # Generate password from pattern and copy to clipboard\n"
            help_text += "  python password_generator.py --pattern 'llbuubddbss' --no-save-history --clipboard\n\n"
            help_text += "  # Generate multiple passwords with custom symbols w/o saving\n"
            help_text += "  python password_generator.py -n -L 30 -r -e -u -l -d -b -a '!@#$' -c 3 -m 3\n\n"
            help_text += "  # Generate password using config file defaults\n"
            help_text += "  python password_generator.py -f config.yaml\n\n"
            help_text += "  # Config file defaults with CLI override\n"
            help_text += "  python password_generator.py -f config.json -L 32\n\n\n"
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
    organizing_group = parser.add_argument_group("Password Organization Options")
    filter_group = parser.add_argument_group("History Search & Filter Options")
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
    config_action = basic_group.add_argument(
        "-f",
        "--config",
        type=str,
        metavar="FILE",
        help="Load defaults from a YAML or JSON config file (CLI args override config values)",
    )
    setattr(config_action, "completer", FilesCompleter(["yaml", "yml", "json"]))
    basic_group.add_argument(
        "-X",
        "--clipboard",
        action="store_true",
        help="Copy password to clipboard",
    )

    # Character type options
    char_group.add_argument(
        "-F",
        "--full",
        action="store_true",
        help="Use all character types (upper, lower, digits, symbols) and enable no-repeats",
    )
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
    char_group.add_argument(
        "-p",
        "--pattern",
        type=str,
        help="Generate password from pattern (l=lower, u=upper, d=digit, s=symbol, b=blank, *=any)",
    )

    # Password organization options
    organizing_group.add_argument(
        "--label",
        type=str,
        help="Label/name for this password (e.g., 'Gmail Account')",
    )
    organizing_group.add_argument(
        "--category",
        type=str,
        help="Category for this password (e.g., 'Email', 'Banking', 'Social')",
    )
    organizing_group.add_argument(
        "--tags",
        type=str,
        help="Comma-separated tags (e.g., 'work,important,2fa')",
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

    # History search & filter options
    filter_group.add_argument(
        "--search",
        type=str,
        help="Search history by label, category, or tags",
    )
    filter_group.add_argument(
        "--filter-strength",
        type=int,
        help="Show only passwords with strength >= this value",
    )
    filter_group.add_argument(
        "--filter-category",
        type=str,
        help="Show only passwords in this category",
    )
    filter_group.add_argument(
        "--since",
        type=str,
        help="Show passwords created since date (YYYY-MM-DD)",
    )
    filter_group.add_argument(
        "--delete-entry",
        type=int,
        help="Delete specific entry by index number",
    )

    # File operations
    file_group.add_argument(
        "-n",
        "--no-save-history",
        action="store_false",
        dest="save_history",
        default=True,
        help="Do not save the password to history",
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
    file_group.add_argument(
        "--limit",
        type=int,
        help="Limit number of history entries to display",
    )

    return parser


# =========================
# CLI Interface
# =========================
def main() -> None:
    """Main entry point for the password generator."""
    parser = create_argument_parser()
    argcomplete.autocomplete(parser)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Apply config file defaults (CLI args take precedence)
    if args.config:
        config = load_config(args.config)
        defaults = parser.parse_args([])
        for key, value in config.items():
            if hasattr(args, key) and getattr(args, key) == getattr(defaults, key):
                setattr(args, key, value)

    if args.help:
        parser.print_help()
        sys.exit(0)

    if args.cleanup:
        cleanup_files()
        sys.exit(0)

    if args.show_history:
        show_password_history(
            limit=args.limit,
            search=args.search,
            filter_strength=args.filter_strength,
            filter_category=args.filter_category,
            since=args.since,
            use_table=True
        )
        sys.exit(0)

    if args.delete_entry:
        delete_entry_by_index(args.delete_entry)
        sys.exit(0)

    # Handle --full option
    if args.full:
        args.upper = True
        args.lower = True
        args.digits = True
        args.symbols = True
        args.no_repeats = True

    if args.allowed_symbols:
        args.symbols = True

    # Parse tags if provided
    tags = None
    if args.tags:
        tags = [tag.strip() for tag in args.tags.split(",")]

    try:
        if args.passphrase:
            # Passphrase mode - supersedes all other options
            print("[ Custom Passphrase Mode ]")
            print(f"Using provided passphrase: {args.passphrase}")

            if args.save_history:
                save_password(
                    args.passphrase,
                    label=args.label,
                    category=args.category,
                    tags=tags
                )
                print(f"✓ Passphrase securely saved to {PASSWORD_FILE}")
            else:
                print("⚠ Passphrase not saved (--no-save-history flag was set)")

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
                pattern=args.pattern,
            )
            
            # Calculate and display strength
            strength = calculate_password_strength(password)
            strength_display = format_strength_meter(strength)
            
            print(f"Generated Password {i+1}: {password}")
            print(f"Strength: {strength_display}")

            # Copy to clipboard if requested
            if args.clipboard:
                if copy_to_clipboard(password):
                    print("✓ Password copied to clipboard")
                else:
                    print("⚠ Could not copy to clipboard (install pyperclip for better support)")

            if args.save_history:
                save_password(
                    password,
                    label=args.label,
                    category=args.category,
                    tags=tags
                )

        if args.save_history and args.count > 0:
            print(f"[✓] Passwords securely saved to {PASSWORD_FILE}")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
