#!/usr/bin/env python3

"""
Pytest suite for entropy-based password strength scoring.

Covers:
- Consistency (zero flicker under blank-space config)
- Entropy boundary mapping
- Character diversity bonuses / penalties
- Edge cases (empty, single char, all spaces)
- Expected-uniqueness formula sanity
- compute_charset_size sanity
"""

import math
import string
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from password_generator import (
    calculate_password_strength,
    compute_charset_size,
    expected_unique_chars,
    generate_password,
)


# ── Helpers ──────────────────────────────────────────────────────────────

BLANK_CONFIG = {
    "length": 33,
    "use_upper": True,
    "use_lower": True,
    "use_digits": True,
    "use_symbols": True,
    "min_characters_per_type": 4,
    "exclude_similar": True,
    "allowed_symbols": "!@#$%^&*?",
    "no_repeats": True,
    "blank": True,
}

FULL_CONFIG = {
    "length": 24,
    "use_upper": True,
    "use_lower": True,
    "use_digits": True,
    "use_symbols": True,
    "min_characters_per_type": 2,
    "exclude_similar": False,
    "allowed_symbols": None,
    "no_repeats": True,
    "blank": False,
}


def _pool(cfg: dict) -> int:
    return compute_charset_size(
        use_upper=cfg["use_upper"],
        use_lower=cfg["use_lower"],
        use_digits=cfg["use_digits"],
        use_symbols=cfg["use_symbols"],
        allowed_symbols=cfg.get("allowed_symbols"),
        exclude_similar=cfg.get("exclude_similar", False),
        blank=cfg.get("blank", False),
    )


# ── 1. Consistency: zero flicker under blank-space config ────────────────

class TestConsistency:
    """Generate many passwords with the flicker-prone config and verify
    v2 produces a single consistent score."""

    ITERATIONS = 50

    def test_blank_config_no_flicker(self):
        pool = _pool(BLANK_CONFIG)
        scores = set()
        for _ in range(self.ITERATIONS):
            pw = generate_password(**BLANK_CONFIG)
            scores.add(calculate_password_strength(pw, charset_size=pool))
        assert len(scores) == 1, (
            f"v2 produced {len(scores)} distinct scores under blank config: {scores}"
        )

    def test_blank_config_score_is_10(self):
        pool = _pool(BLANK_CONFIG)
        pw = generate_password(**BLANK_CONFIG)
        assert calculate_password_strength(pw, charset_size=pool) == 10

    def test_full_config_no_flicker(self):
        pool = _pool(FULL_CONFIG)
        scores = set()
        for _ in range(self.ITERATIONS):
            pw = generate_password(**FULL_CONFIG)
            scores.add(calculate_password_strength(pw, charset_size=pool))
        assert len(scores) == 1, (
            f"v2 produced {len(scores)} distinct scores under full config: {scores}"
        )


# ── 2. Entropy boundary tests ───────────────────────────────────────────

class TestEntropyBoundaries:
    """Verify entropy-to-score mapping at known thresholds.

    Uses diverse, non-repeating passwords to isolate the entropy base
    score from consecutive-repeat and uniqueness penalties.
    """

    @pytest.mark.parametrize("pw,pool,min_score", [
        ("DGHKMPQX", 26, 2),           # 37.6 bits → base 3, single type -1 = 2
        ("dGhKmPqX", 52, 3),           # 45.6 bits → base 3, two types = 3
        ("dGh2Km5PqX8w", 62, 6),       # 71.4 bits → base 5, three types +1 = 6
        ("dGh2!Km5@PqX8#wR", 95, 9),   # 105 bits → base 7, four types +2 = 9
        ("dGh2!Km5@PqX8#wR7$tVeYz4", 95, 10),  # 157 bits → base 8, +2 = 10
        ("dGh2!Km5@PqX8#wR7$tVeYz4uFnJsB6&W", 64, 10),  # 198 bits → base 8, +2 = 10
    ])
    def test_base_score_from_entropy(self, pw, pool, min_score):
        score = calculate_password_strength(pw, charset_size=pool)
        assert score >= min_score, (
            f"pw={pw!r} pool={pool} → expected >= {min_score}, got {score}"
        )

    def test_short_password_scores_low(self):
        pw = "Ab1!"
        assert calculate_password_strength(pw, charset_size=95) <= 5

    def test_long_diverse_password_scores_high(self):
        pw = "aB3!xY9@ kM2#pQ7&rWsEtFuG5vH6jNz"
        pool = 95 + 1
        assert calculate_password_strength(pw, charset_size=pool) >= 7


# ── 3. Character diversity tests ────────────────────────────────────────

class TestDiversity:

    def test_single_type_penalized(self):
        pw = "a" * 20
        score = calculate_password_strength(pw, charset_size=26)
        assert score <= 6

    def test_two_types_no_bonus(self):
        pw = "aAbBcCdDeEfFgGhH"
        score_2 = calculate_password_strength(pw, charset_size=52)

        pw3 = "aA1bB2cC3dD4eE5f"
        score_3 = calculate_password_strength(pw3, charset_size=62)
        assert score_3 >= score_2

    def test_all_five_types_gets_max_bonus(self):
        pw = "aA1! bB2@cC3#dD4$eE5%"
        pool = 26 + 26 + 10 + 32 + 1
        score = calculate_password_strength(pw, charset_size=pool)
        assert score >= 9


# ── 4. Edge cases ────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_empty_password(self):
        assert calculate_password_strength("") == 1

    def test_single_character(self):
        assert calculate_password_strength("x", charset_size=26) == 1

    def test_all_spaces(self):
        pw = " " * 20
        score = calculate_password_strength(pw, charset_size=1)
        assert score <= 2

    def test_charset_size_none_infers_pool(self):
        pw = "aB3!xY9@"
        score_inferred = calculate_password_strength(pw)
        score_explicit = calculate_password_strength(pw, charset_size=94)
        assert 1 <= score_inferred <= 10
        assert 1 <= score_explicit <= 10

    def test_score_always_in_range(self):
        for pw in ["", "a", "aB3!", "x" * 100, "aB3! kM2#pQ7&rW"]:
            score = calculate_password_strength(pw)
            assert 1 <= score <= 10


# ── 5. Expected-uniqueness formula sanity ────────────────────────────────

class TestExpectedUniqueness:

    def test_single_draw(self):
        assert expected_unique_chars(26, 1) == pytest.approx(1.0, abs=0.01)

    def test_large_pool_small_length(self):
        result = expected_unique_chars(100, 5)
        assert 4.5 < result < 5.1

    def test_small_pool_large_length(self):
        result = expected_unique_chars(10, 100)
        assert 9.9 < result <= 10.0

    def test_pool_equals_length(self):
        result = expected_unique_chars(26, 26)
        assert 15 < result < 26

    def test_zero_inputs(self):
        assert expected_unique_chars(0, 10) == 0.0
        assert expected_unique_chars(10, 0) == 0.0

    def test_monotonic_in_length(self):
        prev = 0.0
        for length in [1, 5, 10, 20, 50, 100]:
            val = expected_unique_chars(62, length)
            assert val >= prev
            prev = val


# ── 6. compute_charset_size sanity ───────────────────────────────────────

class TestComputeCharsetSize:

    def test_upper_only(self):
        assert compute_charset_size(use_upper=True) == 26

    def test_upper_lower(self):
        assert compute_charset_size(use_upper=True, use_lower=True) == 52

    def test_all_types_no_filter(self):
        size = compute_charset_size(
            use_upper=True, use_lower=True,
            use_digits=True, use_symbols=True,
        )
        assert size == 26 + 26 + 10 + len(string.punctuation)

    def test_exclude_similar_reduces_pool(self):
        full = compute_charset_size(
            use_upper=True, use_lower=True, use_digits=True
        )
        filtered = compute_charset_size(
            use_upper=True, use_lower=True, use_digits=True,
            exclude_similar=True,
        )
        assert filtered < full

    def test_blank_adds_one(self):
        without = compute_charset_size(use_upper=True)
        with_blank = compute_charset_size(use_upper=True, blank=True)
        assert with_blank == without + 1

    def test_custom_symbols(self):
        size = compute_charset_size(
            use_symbols=True,
            allowed_symbols="!@#$%^&*?",
        )
        assert size == 9

    def test_user_config_pool(self):
        size = _pool(BLANK_CONFIG)
        assert size > 50
