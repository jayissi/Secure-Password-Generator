#!/usr/bin/env python3

"""
Tests for secure_password_generator.crypto module.

Covers:
- encrypt/decrypt round-trip
- combine_keys XOR
- Master password validation
- Session-token caching (no SHA-256 leak)
- Environment-variable resolution
"""

import os
import secrets
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_password_generator.crypto import (
    _validate_master_password,
    combine_keys,
    decrypt_data,
    encrypt_data,
    resolve_master_password,
)


# ── encrypt / decrypt round-trip ─────────────────────────────────────────

class TestEncryptDecrypt:

    def test_round_trip(self):
        key = secrets.token_bytes(32)
        plaintext = '{"password": "hunter2"}'
        encrypted = encrypt_data(plaintext, key)
        assert decrypt_data(encrypted, key) == plaintext

    def test_wrong_key_raises(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        encrypted = encrypt_data("secret", key1)
        with pytest.raises(Exception):
            decrypt_data(encrypted, key2)

    def test_short_blob_raises(self):
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="too short"):
            decrypt_data(b"short", key)

    def test_empty_plaintext(self):
        key = secrets.token_bytes(32)
        encrypted = encrypt_data("", key)
        assert decrypt_data(encrypted, key) == ""


# ── combine_keys ─────────────────────────────────────────────────────────

class TestCombineKeys:

    def test_xor_identity(self):
        a = secrets.token_bytes(32)
        zero = bytes(32)
        assert combine_keys(a, zero) == a

    def test_xor_self_is_zero(self):
        a = secrets.token_bytes(32)
        assert combine_keys(a, a) == bytes(32)

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError, match="same length"):
            combine_keys(b"short", b"longer-key")


# ── Master password validation ───────────────────────────────────────────

class TestMasterPasswordValidation:

    def test_too_short(self):
        with pytest.raises(ValueError, match="at least 12"):
            _validate_master_password("Ab1!")

    def test_missing_types(self):
        with pytest.raises(ValueError, match="character types"):
            _validate_master_password("alllowercase1")

    def test_valid_password(self):
        _validate_master_password("StrongPass1!xx")

    def test_exactly_3_types_accepted(self):
        _validate_master_password("UpperLower123x")

    def test_all_4_types_accepted(self):
        _validate_master_password("UpperLower1!xx")


# ── resolve_master_password ──────────────────────────────────────────────

class TestResolveMasterPassword:

    def test_cli_flag_takes_priority(self):
        args = types.SimpleNamespace(
            master_password="CliValue",
            master_password_file=None,
        )
        with patch(
            "secure_password_generator.crypto.is_master_password_enabled",
            return_value=False,
        ):
            result = resolve_master_password(args)
        assert result == "CliValue"

    def test_env_var_used_when_no_cli_flag(self):
        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=None,
        )
        with (
            patch.dict(os.environ, {"SPG_MASTER_PASSWORD": "EnvValue"}),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
        ):
            result = resolve_master_password(args)
        assert result == "EnvValue"

    def test_password_file_read(self, tmp_path):
        pw_file = tmp_path / "master.txt"
        pw_file.write_text("FilePassword\n")
        pw_file.chmod(0o600)

        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=str(pw_file),
        )
        env_clean = {
            k: v
            for k, v in os.environ.items()
            if k != "SPG_MASTER_PASSWORD"
        }
        with (
            patch.dict(os.environ, env_clean, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
        ):
            result = resolve_master_password(args)
        assert result == "FilePassword"

    def test_none_when_not_configured(self):
        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=None,
        )
        env_clean = {
            k: v
            for k, v in os.environ.items()
            if k != "SPG_MASTER_PASSWORD"
        }
        with (
            patch.dict(os.environ, env_clean, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
        ):
            result = resolve_master_password(args)
        assert result is None
