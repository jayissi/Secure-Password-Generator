#!/usr/bin/env python3

"""
Tests for secure_password_generator.generator module.

Covers:
- CharsetConfig + build_charset
- compute_charset_size
- Pattern minimum-length enforcement
- Blank-position constraints
- _filter_similar_chars caching
- generate_password constraints
- Progressive strength scoring
"""

import string

import pytest

from secure_password_generator.config import CharsetConfig
from secure_password_generator.generator import (
    _filter_similar_chars,
    build_charset,
    calculate_password_strength,
    compute_charset_size,
    generate_password,
)
from secure_password_generator.constants import MIN_PASSWORD_LENGTH


# ── CharsetConfig + build_charset ────────────────────────────────────────

class TestBuildCharset:

    def test_empty_config_returns_empty(self):
        cfg = CharsetConfig()
        assert build_charset(cfg) == []

    def test_upper_only(self):
        cfg = CharsetConfig(use_upper=True)
        tuples = build_charset(cfg)
        assert len(tuples) == 1
        assert tuples[0][0] == "upper"
        assert tuples[0][1] == string.ascii_uppercase

    def test_all_types_plus_blank(self):
        cfg = CharsetConfig(
            use_upper=True, use_lower=True,
            use_digits=True, use_symbols=True, blank=True,
        )
        tuples = build_charset(cfg)
        names = [name for name, _ in tuples]
        assert "upper" in names
        assert "lower" in names
        assert "digits" in names
        assert "symbols" in names
        assert "blank" in names

    def test_custom_symbols(self):
        cfg = CharsetConfig(use_symbols=True, allowed_symbols="!@#")
        tuples = build_charset(cfg)
        assert len(tuples) == 1
        assert set(tuples[0][1]) == {"!", "@", "#"}

    def test_exclude_similar_reduces_pool(self):
        cfg_full = CharsetConfig(
            use_upper=True, use_lower=True, use_digits=True
        )
        cfg_filtered = CharsetConfig(
            use_upper=True, use_lower=True, use_digits=True,
            exclude_similar=True,
        )
        assert compute_charset_size(cfg_filtered) < compute_charset_size(
            cfg_full
        )


# ── compute_charset_size ─────────────────────────────────────────────────

class TestComputeCharsetSize:

    def test_minimum_is_one(self):
        assert compute_charset_size(CharsetConfig()) == 1

    def test_blank_adds_one(self):
        without = compute_charset_size(CharsetConfig(use_upper=True))
        with_blank = compute_charset_size(
            CharsetConfig(use_upper=True, blank=True)
        )
        assert with_blank == without + 1


# ── Pattern minimum-length enforcement ───────────────────────────────────

class TestPatternMinLength:

    def test_short_pattern_padded(self):
        cfg = CharsetConfig(use_lower=True)
        password = generate_password(
            length=4, cfg=cfg, pattern="ld"
        )
        assert len(password) >= MIN_PASSWORD_LENGTH

    def test_long_pattern_unchanged(self):
        cfg = CharsetConfig(use_lower=True)
        pattern = "l" * 20
        password = generate_password(
            length=20, cfg=cfg, pattern=pattern
        )
        assert len(password) == 20


# ── Blank-position constraints ───────────────────────────────────────────

class TestBlankPosition:

    def test_blank_never_first_or_last(self):
        cfg = CharsetConfig(
            use_upper=True, use_lower=True,
            use_digits=True, use_symbols=True, blank=True,
        )
        for _ in range(100):
            pw = generate_password(
                length=16, cfg=cfg,
                min_characters_per_type=2, no_repeats=True,
            )
            assert pw[0] != " ", f"Blank at first position: {pw!r}"
            assert pw[-1] != " ", f"Blank at last position: {pw!r}"


# ── _filter_similar_chars caching ────────────────────────────────────────

class TestFilterSimilarCache:

    def test_cache_returns_same_object(self):
        _filter_similar_chars.cache_clear()
        result1 = _filter_similar_chars(string.ascii_uppercase, True)
        result2 = _filter_similar_chars(string.ascii_uppercase, True)
        assert result1 is result2

    def test_false_returns_original(self):
        original = string.ascii_lowercase
        assert _filter_similar_chars(original, False) is original


# ── generate_password constraints ────────────────────────────────────────

class TestGeneratePassword:

    def test_minimum_length_enforced(self):
        cfg = CharsetConfig(use_lower=True)
        pw = generate_password(length=4, cfg=cfg)
        assert len(pw) >= MIN_PASSWORD_LENGTH

    def test_no_repeats_honoured(self):
        cfg = CharsetConfig(
            use_upper=True, use_lower=True, use_digits=True,
        )
        for _ in range(50):
            pw = generate_password(length=20, cfg=cfg, no_repeats=True)
            for i in range(1, len(pw)):
                assert pw[i] != pw[i - 1], (
                    f"Consecutive repeat at {i}: {pw!r}"
                )

    def test_min_chars_per_type(self):
        cfg = CharsetConfig(
            use_upper=True, use_lower=True, use_digits=True,
        )
        for _ in range(20):
            pw = generate_password(
                length=12, cfg=cfg, min_characters_per_type=3,
            )
            upper_count = sum(1 for c in pw if c.isupper())
            lower_count = sum(1 for c in pw if c.islower())
            digit_count = sum(1 for c in pw if c.isdigit())
            assert upper_count >= 3
            assert lower_count >= 3
            assert digit_count >= 3

    def test_empty_charset_raises(self):
        cfg = CharsetConfig()
        with pytest.raises(ValueError, match="character type"):
            generate_password(length=12, cfg=cfg)


# ── Progressive strength scoring ─────────────────────────────────────────

class TestProgressiveScoring:

    def test_five_types_beats_four(self):
        pw5 = "aA1! bB2@cC3#dD4$eE5%"
        pw4 = "aA1!bB2@cC3#dD4$eE5%x"
        pool5 = 26 + 26 + 10 + 32 + 1
        pool4 = 26 + 26 + 10 + 32
        score5 = calculate_password_strength(pw5, charset_size=pool5)
        score4 = calculate_password_strength(pw4, charset_size=pool4)
        assert score5 >= score4, (
            f"5-type ({score5}) should be >= 4-type ({score4})"
        )

    def test_four_types_beats_three(self):
        pw4 = "aA1!bB2@cC3#dD4$"
        pw3 = "aA1bB2cC3dD4eE5f"
        pool4 = 26 + 26 + 10 + 32
        pool3 = 26 + 26 + 10
        score4 = calculate_password_strength(pw4, charset_size=pool4)
        score3 = calculate_password_strength(pw3, charset_size=pool3)
        assert score4 >= score3

    def test_single_type_penalised(self):
        pw = "a" * 20
        score = calculate_password_strength(pw, charset_size=26)
        assert score <= 6
