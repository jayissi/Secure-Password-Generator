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
from secure_password_generator.constants import MIN_PASSWORD_LENGTH
from secure_password_generator.generator import (
    _filter_similar_chars,
    build_charset,
    calculate_password_strength,
    compute_charset_size,
    format_strength_inline,
    generate_password,
)

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


# ── Latin-ext generation ─────────────────────────────────────────────────

class TestLatinExt:

    def test_build_charset_includes_latin_ext(self):
        cfg = CharsetConfig(use_lower=True, latin_ext=True)
        tuples = build_charset(cfg)
        names = [name for name, _ in tuples]
        assert "latin_ext" in names

    def test_build_charset_latin_ext_count(self):
        cfg = CharsetConfig(use_lower=True, latin_ext=True)
        tuples = build_charset(cfg)
        latin_chars = [chars for name, chars in tuples if name == "latin_ext"]
        assert len(latin_chars) == 1
        assert len(latin_chars[0]) == 94

    def test_build_charset_latin_ext_range(self):
        cfg = CharsetConfig(use_lower=True, latin_ext=True)
        tuples = build_charset(cfg)
        latin_chars = next(chars for name, chars in tuples if name == "latin_ext")
        for c in latin_chars:
            assert 0x00A1 <= ord(c) <= 0x00FF
            assert ord(c) != 0x00AD

    def test_compute_charset_size_with_latin_ext(self):
        without = compute_charset_size(CharsetConfig(use_lower=True))
        with_latin = compute_charset_size(
            CharsetConfig(use_lower=True, latin_ext=True)
        )
        assert with_latin == without + 94

    def test_generate_password_latin_ext_contains_non_ascii(self):
        cfg = CharsetConfig(use_lower=True, latin_ext=True)
        has_non_ascii = False
        for _ in range(20):
            pw = generate_password(length=16, cfg=cfg)
            if any(ord(c) > 127 for c in pw):
                has_non_ascii = True
                break
        assert has_non_ascii, "Expected at least one non-ASCII character"

    def test_generate_password_latin_ext_no_repeats(self):
        cfg = CharsetConfig(
            use_upper=True, use_lower=True, use_digits=True,
            latin_ext=True,
        )
        for _ in range(20):
            pw = generate_password(length=20, cfg=cfg, no_repeats=True)
            for i in range(1, len(pw)):
                assert pw[i] != pw[i - 1], (
                    f"Consecutive repeat at {i}: {pw!r}"
                )

    def test_generate_password_latin_ext_min_chars(self):
        cfg = CharsetConfig(
            use_upper=True, use_lower=True, latin_ext=True,
        )
        for _ in range(10):
            pw = generate_password(
                length=20, cfg=cfg, min_characters_per_type=2,
            )
            latin_count = sum(1 for c in pw if ord(c) > 127)
            assert latin_count >= 2


# ── format_strength_inline ───────────────────────────────────────────────

class TestFormatStrengthInline:

    def test_returns_bracketed_score(self):
        result = format_strength_inline(8)
        assert "[8/10]" in result

    def test_contains_ansi_color(self):
        result = format_strength_inline(8)
        assert "\033[" in result

    def test_max_score_bright_green(self):
        result = format_strength_inline(10)
        assert "\033[1;92m" in result  # COLOR_BRIGHT_GREEN

    def test_high_score_green(self):
        result = format_strength_inline(9)
        assert "\033[92m" in result  # COLOR_GREEN (not bright)

    def test_low_score_red(self):
        result = format_strength_inline(1)
        assert "\033[91m" in result  # COLOR_RED
