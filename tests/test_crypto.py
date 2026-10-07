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
from unittest.mock import patch

import cryptography.exceptions
import pytest

from secure_password_generator.crypto import (
    _validate_master_password,
    argon2id_hash,
    combine_keys,
    decrypt_data,
    encrypt_data,
    initialize_security_files,
    resolve_master_password,
)

# ── encrypt / decrypt round-trip ─────────────────────────────────────────

class TestEncryptDecrypt:

    def test_round_trip(self):
        key = secrets.token_bytes(32)
        plaintext = '{"password": "hunter2"}'
        encrypted = encrypt_data(plaintext, key, aad=b"test")
        assert decrypt_data(encrypted, key, aad=b"test") == plaintext

    def test_wrong_key_raises(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        encrypted = encrypt_data("secret", key1)
        with pytest.raises(cryptography.exceptions.InvalidTag):
            decrypt_data(encrypted, key2)

    def test_short_blob_raises(self):
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="too short"):
            decrypt_data(b"short", key)

    def test_empty_plaintext(self):
        key = secrets.token_bytes(32)
        encrypted = encrypt_data("", key, aad=b"test")
        assert decrypt_data(encrypted, key, aad=b"test") == ""

    def test_mismatched_aad_raises(self):
        key = secrets.token_bytes(32)
        encrypted = encrypt_data("secret", key, aad=b"a")
        with pytest.raises(cryptography.exceptions.InvalidTag):
            decrypt_data(encrypted, key, aad=b"b")

    def test_none_aad_round_trip(self):
        key = secrets.token_bytes(32)
        plaintext = "no-aad-test"
        encrypted = encrypt_data(plaintext, key, aad=None)
        assert decrypt_data(encrypted, key, aad=None) == plaintext


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
        env = os.environ.copy()
        env["SPG_MASTER_CREDENTIAL"] = "EnvValue"
        with (
            patch.dict(os.environ, env, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
        ):
            result = resolve_master_password(args)
            assert result == "EnvValue"
            assert "SPG_MASTER_CREDENTIAL" not in os.environ

    def test_env_var_consumed_on_read(self):
        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=None,
        )
        env = os.environ.copy()
        env["SPG_MASTER_CREDENTIAL"] = "OnceOnly"
        with (
            patch.dict(os.environ, env, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
        ):
            first = resolve_master_password(args)
            second = resolve_master_password(args)
        assert first == "OnceOnly"
        assert second is None

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
            if k != "SPG_MASTER_CREDENTIAL"
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
            if k != "SPG_MASTER_CREDENTIAL"
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


# ── argon2id_hash ────────────────────────────────────────────────────────

class TestArgon2idHash:

    def test_argon2id_hash_returns_expected_keys(self, vault_dir):
        initialize_security_files()
        result = argon2id_hash("test")
        assert "salt_b64" in result
        assert "digest_b64" in result
        assert "params" in result
        params = result["params"]
        assert "length" in params
        assert "iterations" in params
        assert "lanes" in params
        assert "memory_cost" in params

    def test_argon2id_hash_unique_salts(self, vault_dir):
        initialize_security_files()
        result1 = argon2id_hash("test")
        result2 = argon2id_hash("test")
        assert result1["salt_b64"] != result2["salt_b64"]


# ── set_master_password ──────────────────────────────────────────────────

class TestSetMasterPassword:

    def test_set_master_password_explicit(self, vault_dir):
        from secure_password_generator.crypto import (
            is_master_password_enabled,
            set_master_password,
        )
        initialize_security_files()
        assert not is_master_password_enabled()
        set_master_password(new_password="StrongPass1!xx")
        assert is_master_password_enabled()

    def test_set_master_password_reencrypt(self, vault_dir):
        from secure_password_generator.crypto import (
            get_encryption_key,
            set_master_password,
        )
        from secure_password_generator.history import save_password
        initialize_security_files()
        key = get_encryption_key()
        save_password("testpw", key=key, label="Before")

        set_master_password(new_password="StrongPass1!xx")
        new_key = get_encryption_key("StrongPass1!xx")
        assert new_key != key

    def test_set_master_password_empty_raises(self, vault_dir):
        from secure_password_generator.crypto import set_master_password
        initialize_security_files()
        with pytest.raises(ValueError, match="cannot be empty"):
            set_master_password(new_password="")


# ── cleanup_files ────────────────────────────────────────────────────────

class TestCleanupFiles:

    def test_cleanup_error_handling(self, vault_dir, caplog):
        from unittest.mock import patch as mock_patch

        from secure_password_generator.crypto import cleanup_files
        initialize_security_files()
        with (
            mock_patch(
                "secure_password_generator.crypto.secure_delete_file",
                side_effect=OSError("mocked"),
            ),
            caplog.at_level("ERROR"),
        ):
            cleanup_files()
        assert "Failed to securely remove" in caplog.text

    def test_cleanup_removes_temp_file(self, vault_dir, capsys):
        from secure_password_generator.crypto import (
            _crypto_state,
            cleanup_files,
        )
        initialize_security_files()
        from secure_password_generator.constants import PASSWORD_FILE
        temp = PASSWORD_FILE.with_suffix(".enc.tmp")
        temp.write_bytes(b"leftover temp data")
        cleanup_files()
        assert not temp.exists()
        assert _crypto_state["files_initialized"] is False

    def test_cleanup_removes_lock_file(self, vault_dir, capsys):
        from secure_password_generator.constants import PASSWORD_DIR
        from secure_password_generator.crypto import cleanup_files
        initialize_security_files()
        lock = PASSWORD_DIR / ".vault.lock"
        lock.write_bytes(b"")
        cleanup_files()
        assert not lock.exists()

    def test_cleanup_resets_files_initialized(self, vault_dir):
        from secure_password_generator.crypto import (
            _crypto_state,
            cleanup_files,
        )
        initialize_security_files()
        assert _crypto_state["files_initialized"] is True
        cleanup_files()
        assert _crypto_state["files_initialized"] is False

    def test_cleanup_already_clean(self, vault_dir, capsys):
        from secure_password_generator.crypto import cleanup_files
        cleanup_files()
        out = capsys.readouterr().out
        assert "already clean" in out


# ── initialize_security_files caching ────────────────────────────────────

class TestInitCaching:

    def test_files_initialized_flag_set(self, vault_dir):
        from secure_password_generator.crypto import _crypto_state
        _crypto_state["files_initialized"] = False
        initialize_security_files()
        assert _crypto_state["files_initialized"] is True

    def test_skips_when_already_initialized(self, vault_dir):
        from secure_password_generator.crypto import _crypto_state
        _crypto_state["files_initialized"] = False
        initialize_security_files()
        from secure_password_generator.constants import KEY_FILE
        key_data = KEY_FILE.read_bytes()
        initialize_security_files()
        assert KEY_FILE.read_bytes() == key_data


# ── validate_master_password edge cases ──────────────────────────────────

class TestMasterPasswordEdgeCases:

    def test_empty_password(self):
        with pytest.raises(ValueError, match="at least 12"):
            _validate_master_password("")

    def test_only_lower(self):
        """Only lower — only 1 type, needs 3."""
        with pytest.raises(ValueError, match="character types"):
            _validate_master_password("alllowercasey")

    def test_only_two_types(self):
        """Lower + digits — only 2 types, needs 3."""
        with pytest.raises(ValueError, match="character types"):
            _validate_master_password("alllower12345")


# ── prompt_master_password ───────────────────────────────────────────────

class TestPromptMasterPassword:

    def test_non_tty_raises(self):
        from secure_password_generator.crypto import prompt_master_password
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with pytest.raises(ValueError, match="not a TTY"):
                prompt_master_password()

    def test_empty_input_raises(self):
        from secure_password_generator.crypto import prompt_master_password
        with (
            patch("sys.stdin") as mock_stdin,
            patch("getpass.getpass", return_value=""),
        ):
            mock_stdin.isatty.return_value = True
            with pytest.raises(ValueError, match="cannot be empty"):
                prompt_master_password()


# ── get_encryption_key ───────────────────────────────────────────────────

class TestGetEncryptionKey:

    def test_no_master_returns_file_key(self, vault_dir):
        from secure_password_generator.crypto import get_encryption_key
        initialize_security_files()
        key = get_encryption_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_master_required_but_none_raises(self, vault_dir):
        from secure_password_generator.crypto import get_encryption_key
        initialize_security_files()
        with (
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=True,
            ),
            pytest.raises(ValueError, match="required"),
        ):
            get_encryption_key(None)

    def test_session_cache_hit(self, vault_dir):
        from secure_password_generator.crypto import (
            _FINAL_KEY_CACHE,
            _crypto_state,
            get_encryption_key,
        )
        initialize_security_files()
        token = "test-token-123"
        cached_key = secrets.token_bytes(32)
        _crypto_state["session_id"] = token
        _FINAL_KEY_CACHE[token] = cached_key
        with patch(
            "secure_password_generator.crypto.is_master_password_enabled",
            return_value=True,
        ):
            result = get_encryption_key("anything")
        assert result == cached_key


# ── resolve_master_password edge cases ───────────────────────────────────

class TestResolveMasterPasswordEdge:

    def test_password_file_not_found(self, tmp_path):
        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=str(tmp_path / "missing.txt"),
        )
        env_clean = {
            k: v for k, v in os.environ.items()
            if k != "SPG_MASTER_CREDENTIAL"
        }
        with (
            patch.dict(os.environ, env_clean, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
            pytest.raises(ValueError, match="not found"),
        ):
            resolve_master_password(args)

    def test_password_file_empty(self, tmp_path):
        pw_file = tmp_path / "empty.txt"
        pw_file.write_text("\n")
        pw_file.chmod(0o600)
        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=str(pw_file),
        )
        env_clean = {
            k: v for k, v in os.environ.items()
            if k != "SPG_MASTER_CREDENTIAL"
        }
        with (
            patch.dict(os.environ, env_clean, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=False,
            ),
            pytest.raises(ValueError, match="empty"),
        ):
            resolve_master_password(args)

    def test_interactive_prompt_when_master_enabled(self):
        args = types.SimpleNamespace(
            master_password=None,
            master_password_file=None,
        )
        env_clean = {
            k: v for k, v in os.environ.items()
            if k != "SPG_MASTER_CREDENTIAL"
        }
        with (
            patch.dict(os.environ, env_clean, clear=True),
            patch(
                "secure_password_generator.crypto.is_master_password_enabled",
                return_value=True,
            ),
            patch(
                "secure_password_generator.crypto.prompt_master_password",
                return_value="InteractivePW",
            ),
        ):
            result = resolve_master_password(args)
        assert result == "InteractivePW"


# ── set_master_password temp file safety ─────────────────────────────────

class TestSetMasterTempFile:

    def test_temp_file_cleaned_on_encrypt_failure(self, vault_dir):
        from secure_password_generator.crypto import (
            get_encryption_key,
            set_master_password,
        )
        from secure_password_generator.history import save_password
        initialize_security_files()
        key = get_encryption_key()
        save_password("testpw", key=key)

        from secure_password_generator.constants import PASSWORD_FILE
        temp = PASSWORD_FILE.with_suffix(".enc.tmp")

        with (
            patch(
                "secure_password_generator.crypto.encrypt_data",
                side_effect=ValueError("mock failure"),
            ),
            pytest.raises(ValueError, match="mock failure"),
        ):
            set_master_password(new_password="StrongPass1!xx")
        assert not temp.exists()

    def test_change_master_password(self, vault_dir):
        from secure_password_generator.crypto import (
            get_encryption_key,
            is_master_password_enabled,
            set_master_password,
        )
        from secure_password_generator.history import save_password
        initialize_security_files()
        set_master_password(new_password="StrongPass1!xx")
        assert is_master_password_enabled()

        key = get_encryption_key("StrongPass1!xx")
        save_password("savedpw", key=key)

        set_master_password(
            new_password="NewStrong12!xx",
            current_password="StrongPass1!xx",
        )
        new_key = get_encryption_key("NewStrong12!xx")
        assert new_key != key
