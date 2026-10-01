"""
Password generation, charset construction, and strength scoring.
"""

import functools
import logging
import math
import secrets
import string
import unicodedata
from typing import cast

from secure_password_generator.config import CharsetConfig
from secure_password_generator.constants import (
    COLOR_GREEN,
    COLOR_ORANGE,
    COLOR_RED,
    COLOR_RESET,
    COLOR_YELLOW,
    LATIN_EXT_CHARS,
    MAX_GENERATION_ATTEMPTS,
    MIN_PASSWORD_LENGTH,
    SIMILAR_CHARS,
)

logger = logging.getLogger("secure_password_generator")

_SYSRAND = secrets.SystemRandom()


# ── Charset helpers ──────────────────────────────────────────────────────

@functools.lru_cache(maxsize=16)
def _filter_similar_chars(chars: str, exclude_similar: bool) -> str:
    """Remove similar-looking characters when requested."""
    if not exclude_similar:
        return chars
    return "".join(c for c in chars if c not in SIMILAR_CHARS)


def build_charset(cfg: CharsetConfig) -> list[tuple[str, str]]:
    """Build the list of ``(name, filtered_chars)`` tuples for generation.

    Args:
        cfg: Character-set configuration.

    Returns:
        Ordered list of ``(category_name, characters)`` pairs.
    """
    charset_tuples: list[tuple[str, str]] = []

    if cfg.use_upper:
        up = _filter_similar_chars(string.ascii_uppercase, cfg.exclude_similar)
        if up:
            charset_tuples.append(("upper", up))
    if cfg.use_lower:
        lo = _filter_similar_chars(string.ascii_lowercase, cfg.exclude_similar)
        if lo:
            charset_tuples.append(("lower", lo))
    if cfg.use_digits:
        dg = _filter_similar_chars(string.digits, cfg.exclude_similar)
        if dg:
            charset_tuples.append(("digits", dg))

    effective_symbols = cfg.allowed_symbols or (
        string.punctuation if cfg.use_symbols else ""
    )
    if effective_symbols:
        sym = _filter_similar_chars(effective_symbols, cfg.exclude_similar)
        if sym:
            charset_tuples.append(("symbols", "".join(dict.fromkeys(sym))))

    if cfg.blank:
        charset_tuples.append(("blank", " "))

    if cfg.latin_ext:
        charset_tuples.append(("latin_ext", LATIN_EXT_CHARS))

    return charset_tuples


def compute_charset_size(cfg: CharsetConfig) -> int:
    """Compute the effective character-pool size from a :class:`CharsetConfig`.

    Returns:
        Pool size (minimum 1).
    """
    size = sum(len(chars) for _, chars in build_charset(cfg))
    return max(size, 1)


def expected_unique_chars(pool_size: int, length: int) -> float:
    """Expected distinct characters when drawing *length* chars uniformly
    from *pool_size* (birthday-problem formula)."""
    if pool_size <= 0 or length <= 0:
        return 0.0
    return pool_size * (1 - ((pool_size - 1) / pool_size) ** length)


# ── Strength scoring ─────────────────────────────────────────────────────

def calculate_password_strength(
    password: str,
    charset_size: int | None = None,
) -> int:
    """Calculate password strength using entropy and complexity grading.

    Scoring factors:
      * **Entropy bits** (PRIMARY): ``length * log2(charset_size)`` mapped
        to a 1-10 base score.
      * **Character-type diversity** (SECONDARY): progressive bonus —
        6 types = +4, 5 = +3, 4 = +2, 3 = +1, 2 = +0, 1 = -1.
      * **Expected uniqueness** (TERTIARY): penalise when actual unique
        chars fall significantly below the statistical expectation.
      * Consecutive-repeat and simple-pattern penalties.

    Args:
        password: Password string to evaluate.
        charset_size: Size of the character pool used to generate the
            password.  When ``None`` the pool is inferred from the
            characters present (safe lower-bound for ad-hoc input).

    Returns:
        Strength score from 1 to 10.
    """
    if not password:
        return 1

    length = len(password)

    # -- Infer charset_size when not provided ---------------------------------
    if charset_size is None:
        pool = 0
        if any(c.isupper() for c in password):
            pool += 26
        if any(c.islower() for c in password):
            pool += 26
        if any(c.isdigit() for c in password):
            pool += 10
        if any(not c.isalnum() and c != " " for c in password):
            pool += 32
        if " " in password:
            pool += 1
        if any(ord(c) > 127 for c in password):
            pool += 94  # Latin-1 Supplement
        charset_size = max(pool, 1)

    # -- Single-pass character-type detection ---------------------------------
    has_upper = has_lower = has_digit = has_symbol = has_blank = False
    has_latin_ext = False
    for c in password:
        if ord(c) > 127:
            has_latin_ext = True
        elif c.isupper():
            has_upper = True
        elif c.islower():
            has_lower = True
        elif c.isdigit():
            has_digit = True
        elif c == " ":
            has_blank = True
        elif not c.isalnum():
            has_symbol = True

    char_types = sum([
        has_upper, has_lower, has_digit, has_symbol, has_blank, has_latin_ext,
    ])

    # -- PRIMARY: entropy-based base score ------------------------------------
    entropy_bits = length * math.log2(charset_size) if charset_size > 1 else 0

    if entropy_bits >= 128:
        base_score = 8
    elif entropy_bits >= 100:
        base_score = 7
    elif entropy_bits >= 80:
        base_score = 6
    elif entropy_bits >= 64:
        base_score = 5
    elif entropy_bits >= 48:
        base_score = 4
    elif entropy_bits >= 36:
        base_score = 3
    elif entropy_bits >= 24:
        base_score = 2
    else:
        base_score = 1

    # -- SECONDARY: progressive character-type diversity ----------------------
    if char_types >= 6:
        base_score = min(10, base_score + 4)
    elif char_types >= 5:
        base_score = min(10, base_score + 3)
    elif char_types >= 4:
        base_score = min(10, base_score + 2)
    elif char_types == 3:
        base_score = min(10, base_score + 1)
    elif char_types == 2:
        pass
    else:
        base_score = max(1, base_score - 1)

    # -- TERTIARY: expected-uniqueness comparison -----------------------------
    unique_chars = len(set(password))
    expected = expected_unique_chars(charset_size, length)

    if expected > 0:
        ratio_of_expected = unique_chars / expected
        if ratio_of_expected < 0.40:
            base_score = max(1, base_score - 2)
        elif ratio_of_expected < 0.60:
            base_score = max(1, base_score - 1)

    # -- Consecutive-repeat penalty (capped at -1) ----------------------------
    consecutive_count = 1
    has_consecutive_run = False
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            consecutive_count += 1
            if consecutive_count >= 3:
                has_consecutive_run = True
                break
        else:
            consecutive_count = 1

    if has_consecutive_run:
        base_score = max(1, base_score - 1)

    # -- Pattern penalty (-1 per match, capped at -2) -------------------------
    pattern_penalty = 0
    simple_patterns = ["123", "abc", "qwe", "asd", "password", "admin"]
    for pat in simple_patterns:
        if pat in password.lower():
            pattern_penalty += 1

    base_score = max(1, base_score - min(pattern_penalty, 2))

    return max(1, min(10, base_score))


def get_strength_color(score: int) -> str:
    """Return an ANSI colour code based on password strength *score*."""
    if score >= 8:
        return COLOR_GREEN
    elif score >= 6:
        return COLOR_YELLOW
    elif score >= 4:
        return COLOR_ORANGE
    else:
        return COLOR_RED


def format_strength_meter(score: int) -> str:
    """Format *score* as a coloured bar ``████░░░░ 8/10``."""
    color = get_strength_color(score)
    bars = "\u2588" * score + "\u2591" * (10 - score)
    return f"{color}{bars} {score}/10{COLOR_RESET}"


# ── Password generation helpers ──────────────────────────────────────────

def _violates_no_repeats(
    slots: list[str | None],
    ch: str,
    pos: int,
    length: int,
    no_repeats: bool,
) -> bool:
    """Return True if placing *ch* at *pos* would create a consecutive dup."""
    if not no_repeats:
        return False
    if pos > 0 and slots[pos - 1] is not None and slots[pos - 1] == ch:
        return True
    return pos < length - 1 and slots[pos + 1] is not None and slots[pos + 1] == ch


def _validate_generation_feasibility(
    length: int,
    charset_tuples: list[tuple[str, str]],
    min_chars: int | None,
    no_repeats: bool,
    blank: bool,
) -> None:
    """Pre-validate that password generation is feasible."""
    if not charset_tuples:
        raise ValueError("At least one character type must be selected.")

    if min_chars:
        non_blank_needed = (
            sum(1 for name, _ in charset_tuples if name != "blank") * min_chars
        )
        blank_needed = min_chars if blank else 0

        if blank and blank_needed > (length - 2):
            raise ValueError(
                "Not enough interior positions for blank characters"
            )

        if non_blank_needed + blank_needed > length:
            raise ValueError(
                f"Not enough positions ({length}) to satisfy minimum "
                f"characters requirement ({non_blank_needed + blank_needed})"
            )

    if no_repeats:
        unique_chars = set()
        for _, chars in charset_tuples:
            unique_chars.update(chars)
        if len(unique_chars) < 2 and length > 1:
            raise ValueError(
                "Cannot generate password with --no-repeats using only "
                "1 unique character"
            )


def generate_symbol_only_password(length: int, symbols: str) -> str:
    """Generate a symbol-only password with no consecutive repeats.

    Args:
        length: Desired password length.
        symbols: Allowed symbol characters.

    Returns:
        Generated password string.

    Raises:
        ValueError: If generation is impossible with the given constraints.
    """
    unique_symbols = list(set(symbols))
    num_symbols = len(unique_symbols)

    if num_symbols == 1:
        raise ValueError(
            "Cannot generate password with --no-repeats using only 1 symbol. "
            "Add more symbols or enable other character types."
        )

    password: list[str] = []
    last_char: str | None = None
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


def generate_password_from_pattern(
    pattern: str,
    allowed_symbols: str = string.punctuation,
) -> str:
    """Generate a password based on a pattern string.

    Pattern codes: ``l`` = lower, ``u`` = upper, ``d`` = digit,
    ``s`` = symbol, ``b`` = blank, ``*`` = random from all types.
    Other characters are used literally.

    Args:
        pattern: Pattern string.
        allowed_symbols: Symbols to use for the ``s`` code.

    Returns:
        Generated password string.
    """
    if len(pattern) < MIN_PASSWORD_LENGTH:
        logger.warning(
            "Pattern length increased to minimum of %d characters",
            MIN_PASSWORD_LENGTH,
        )
        pattern = pattern + "*" * (MIN_PASSWORD_LENGTH - len(pattern))

    char_sets = {
        "l": string.ascii_lowercase,
        "u": string.ascii_uppercase,
        "d": string.digits,
        "s": allowed_symbols,
        "b": " ",
        "*": string.ascii_letters + string.digits + allowed_symbols,
    }

    password: list[str] = []
    for code in pattern:
        if code in char_sets:
            chars = char_sets[code]
            if not chars:
                raise ValueError(
                    f"No characters available for pattern code '{code}'"
                )
            password.append(secrets.choice(chars))
        else:
            password.append(code)

    return unicodedata.normalize("NFC", "".join(password))


# ── Main generation function ─────────────────────────────────────────────



def generate_password(
    length: int,
    cfg: CharsetConfig,
    min_characters_per_type: int | None = None,
    no_repeats: bool = False,
    pattern: str | None = None,
) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Desired password length.
        cfg: Character-set configuration.
        min_characters_per_type: Minimum characters from each selected type.
        no_repeats: Prevent consecutive duplicate characters.
        pattern: Generate password from a pattern string instead.

    Returns:
        Generated password string.

    Raises:
        ValueError: If generation fails after maximum attempts.
    """
    if pattern:
        effective_symbols = (
            cfg.allowed_symbols or string.punctuation
        )
        return generate_password_from_pattern(pattern, effective_symbols)

    if length < MIN_PASSWORD_LENGTH:
        logger.warning(
            "Password length increased to minimum of %d characters",
            MIN_PASSWORD_LENGTH,
        )
        length = MIN_PASSWORD_LENGTH

    effective_symbols = (
        cfg.allowed_symbols or (string.punctuation if cfg.use_symbols else "")
    )

    # Handle symbol-only case
    if effective_symbols and not (
        cfg.use_upper or cfg.use_lower or cfg.use_digits
    ):
        if no_repeats:
            return generate_symbol_only_password(length, effective_symbols)
        elif len(set(effective_symbols)) < 2 and length > 1:
            raise ValueError(
                "Cannot generate password with only 1 symbol and length > 1. "
                "Add more symbols or enable other character types."
            )

    charset_tuples = build_charset(cfg)

    for name, chars in charset_tuples:
        if not chars:
            raise ValueError(
                f"No {name} characters available after filtering"
            )

    _validate_generation_feasibility(
        length, charset_tuples, min_characters_per_type, no_repeats, cfg.blank
    )

    all_chars = "".join(chars for _, chars in charset_tuples)
    charset_sets = [(name, frozenset(chars)) for name, chars in charset_tuples]

    for attempt in range(MAX_GENERATION_ATTEMPTS):
        try:
            slots: list[str | None] = [None] * length

            if min_characters_per_type:
                available_positions = set(range(length))
                for name, chars in charset_tuples:
                    if not chars:
                        continue

                    needed = max(0, min_characters_per_type)
                    if needed == 0:
                        continue

                    candidates = [
                        p for p in range(length) if p in available_positions
                    ]
                    if name == "blank":
                        candidates = [
                            p
                            for p in candidates
                            if p != 0 and p != length - 1
                        ]

                    if len(candidates) < needed:
                        raise ValueError(
                            "Not enough positions to satisfy minimum "
                            "characters for selected types"
                        )

                    chosen_positions = _SYSRAND.sample(candidates, needed)
                    for pos in chosen_positions:
                        placed = False
                        trials = 0
                        while trials < 200 and not placed:
                            ch = secrets.choice(chars)
                            if _violates_no_repeats(
                                slots, ch, pos, length, no_repeats
                            ):
                                trials += 1
                                continue
                            slots[pos] = ch
                            available_positions.discard(pos)
                            placed = True

                        if not placed:
                            raise ValueError(
                                "Unable to place required characters "
                                "without violating constraints"
                            )

            for i in range(length):
                if slots[i] is not None:
                    continue

                choices_str = all_chars

                if cfg.blank and (i == 0 or i == length - 1):
                    choices_str = choices_str.replace(" ", "")

                if no_repeats and i > 0:
                    prev_char = slots[i - 1]
                    if prev_char is not None:
                        choices_str = choices_str.replace(prev_char, "")

                if not choices_str:
                    raise ValueError(
                        "No available characters to fill slot "
                        "considering constraints"
                    )

                slots[i] = secrets.choice(choices_str)

            if any(ch is None for ch in slots):
                raise ValueError(
                    "Internal error: incomplete password construction"
                )
            password = "".join(cast(list[str], slots))

            if min_characters_per_type:
                for _name, char_set in charset_sets:
                    if not char_set:
                        continue
                    count = sum(1 for c in password if c in char_set)
                    if count < min_characters_per_type:
                        raise ValueError(
                            "Minima not satisfied after construction "
                            "- retrying"
                        )

            if cfg.blank and (
                password[0] == " " or password[-1] == " "
            ):
                raise ValueError(
                    "Blank character at first or last position - retrying"
                )

            if no_repeats:
                for i in range(1, length):
                    if password[i] == password[i - 1]:
                        raise ValueError(
                            "Consecutive duplicate characters - retrying"
                        )

            return unicodedata.normalize("NFC", password)

        except ValueError as exc:
            if attempt == MAX_GENERATION_ATTEMPTS - 1:
                raise ValueError(
                    f"Failed to generate password after "
                    f"{MAX_GENERATION_ATTEMPTS} attempts"
                ) from exc
            continue

    raise ValueError(
        f"Failed to generate password after {MAX_GENERATION_ATTEMPTS} attempts"
    )
