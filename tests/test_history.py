#!/usr/bin/env python3

"""
Tests for secure_password_generator.history module.

Covers:
- save_password and vault file creation
- save with metadata (label, category, tags) and round-trip
- show_password_history (empty vault, populated, table output)
- search by label, category, tags
- filter by strength, category, date
- combined filters and limit
- authenticated delete (correct key, wrong key)
- format_history_table (tabulate output structure)
"""

import base64
import json
import secrets
from datetime import datetime

import pytest

from secure_password_generator.constants import VAULT_AAD
from secure_password_generator.crypto import (
    decrypt_data,
    get_encryption_key,
    initialize_security_files,
)
from secure_password_generator.history import (
    delete_entry_by_index,
    format_history_table,
    save_password,
    show_password_history,
    update_entry_metadata,
)

# ── Helpers ──────────────────────────────────────────────────────────────

@pytest.fixture()
def vault_key(vault_dir):
    """Initialise security files and return the encryption key."""
    initialize_security_files()
    return get_encryption_key()


@pytest.fixture()
def vault_file(vault_dir):
    """Return the patched vault file path."""
    from secure_password_generator import constants
    return constants.PASSWORD_FILE


# ── save_password ────────────────────────────────────────────────────────

class TestSavePassword:

    def test_creates_vault_file(self, vault_dir, vault_key, vault_file):
        assert not vault_file.exists()
        save_password("hunter2", vault_key, filename=vault_file)
        assert vault_file.exists()

    def test_metadata_round_trip(self, vault_dir, vault_key, vault_file, capsys):
        save_password(
            "Secret123!",
            vault_key,
            filename=vault_file,
            label="Gmail",
            category="Email",
            tags=["work", "important"],
        )
        show_password_history(vault_key, filename=vault_file, use_table=False)
        out = capsys.readouterr().out
        assert "Gmail" in out
        assert "Email" in out
        assert "Secret123!" in out

    def test_multiple_entries(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, label="First")
        save_password("pw2", vault_key, filename=vault_file, label="Second")
        show_password_history(vault_key, filename=vault_file, use_table=False)
        out = capsys.readouterr().out
        assert "First" in out
        assert "Second" in out


# ── show_password_history ────────────────────────────────────────────────

class TestShowHistory:

    def test_empty_vault(self, vault_dir, vault_key, vault_file, capsys):
        show_password_history(vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "No password history" in out

    def test_table_format(self, vault_dir, vault_key, vault_file, capsys):
        save_password("myPass1!", vault_key, filename=vault_file, label="TestLabel")
        show_password_history(vault_key, filename=vault_file, use_table=True)
        out = capsys.readouterr().out
        assert "TestLabel" in out
        assert "myPass1!" in out

    def test_search_by_label(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, label="Gmail")
        save_password("pw2", vault_key, filename=vault_file, label="Bank")
        show_password_history(vault_key, filename=vault_file, search="Gmail")
        out = capsys.readouterr().out
        assert "Gmail" in out
        assert "Bank" not in out

    def test_search_by_category(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, category="Email")
        save_password("pw2", vault_key, filename=vault_file, category="Banking")
        show_password_history(vault_key, filename=vault_file, search="Banking")
        out = capsys.readouterr().out
        assert "Banking" in out
        assert "Email" not in out

    def test_search_by_tags(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, tags=["work"])
        save_password("pw2", vault_key, filename=vault_file, tags=["personal"])
        show_password_history(vault_key, filename=vault_file, search="work")
        out = capsys.readouterr().out
        assert "work" in out or "pw1" in out

    def test_filter_by_category(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, category="Email")
        save_password("pw2", vault_key, filename=vault_file, category="Banking")
        show_password_history(vault_key, filename=vault_file, filter_category="Email")
        out = capsys.readouterr().out
        assert "Email" in out
        assert "Banking" not in out

    def test_filter_by_strength(self, vault_dir, vault_key, vault_file, capsys):
        save_password("a", vault_key, filename=vault_file, label="Weak")
        save_password(
            "Str0ng!Pass#word99", vault_key, filename=vault_file, label="Strong"
        )
        show_password_history(vault_key, filename=vault_file, filter_strength=5)
        out = capsys.readouterr().out
        assert "Strong" in out
        assert "Weak" not in out

    def test_filter_by_date(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, label="Today")
        today = datetime.now().strftime("%Y-%m-%d")
        show_password_history(vault_key, filename=vault_file, since=today)
        out = capsys.readouterr().out
        assert "Today" in out

    def test_limit(self, vault_dir, vault_key, vault_file, capsys):
        for i in range(5):
            save_password(f"pw{i}", vault_key, filename=vault_file, label=f"Entry{i}")
        show_password_history(vault_key, filename=vault_file, limit=2, use_table=False)
        out = capsys.readouterr().out
        lines = [
            line for line in out.splitlines()
            if line.strip().startswith(("1.", "2.", "3."))
        ]
        assert len(lines) <= 2


# ── delete_entry_by_index ────────────────────────────────────────────────

class TestDeleteEntry:

    def test_authenticated_delete(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, label="First")
        save_password("pw2", vault_key, filename=vault_file, label="Second")
        delete_entry_by_index(1, vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "securely deleted" in out

        show_password_history(vault_key, filename=vault_file, use_table=False)
        out2 = capsys.readouterr().out
        assert "First" in out2
        assert "Second" not in out2

    def test_wrong_key_fails(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file, label="Protected")
        wrong_key = secrets.token_bytes(32)
        delete_entry_by_index(1, wrong_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "securely deleted" not in out

    def test_invalid_index(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file)
        delete_entry_by_index(99, vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "Invalid index" in out

    def test_empty_vault(self, vault_dir, vault_key, vault_file, capsys):
        delete_entry_by_index(1, vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "No password history" in out


# ── update_entry_metadata ────────────────────────────────────────────────

class TestUpdateEntryMetadata:

    def test_update_label(self, vault_dir, vault_key, vault_file, capsys):
        save_password(
            "pw1", vault_key, filename=vault_file,
            label="Original", category="General", tags=["init"],
        )
        update_entry_metadata(
            1, vault_key, label="Updated", filename=vault_file,
        )
        out = capsys.readouterr().out
        assert "updated" in out.lower()

        show_password_history(vault_key, filename=vault_file, use_table=False)
        out2 = capsys.readouterr().out
        assert "Updated" in out2

    def test_preserves_other_fields(self, vault_dir, vault_key, vault_file, capsys):
        save_password(
            "pw1", vault_key, filename=vault_file,
            label="Original", category="Work", tags=["important"],
        )
        update_entry_metadata(
            1, vault_key, label="NewLabel", filename=vault_file,
        )
        capsys.readouterr()

        show_password_history(vault_key, filename=vault_file, use_table=False)
        out = capsys.readouterr().out
        assert "NewLabel" in out
        assert "Work" in out
        assert "important" in out

    def test_invalid_index(self, vault_dir, vault_key, vault_file, capsys):
        save_password("pw1", vault_key, filename=vault_file)
        update_entry_metadata(99, vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "Invalid index" in out

    def test_empty_vault(self, vault_dir, vault_key, vault_file, capsys):
        update_entry_metadata(1, vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "No password history" in out


# ── format_history_table ─────────────────────────────────────────────────

class TestFormatHistoryTable:

    def test_empty_entries(self):
        assert format_history_table([]) == "No entries to display."

    def test_table_has_headers(self):
        entries = [{
            "label": "Test",
            "password": "abc123",
            "strength": 5,
            "category": "General",
            "timestamp": "Mon, Jan 01, 2024 12:00:00:000000 PM",
        }]
        table = format_history_table(entries)
        assert "Label" in table
        assert "Password" in table
        assert "Strength" in table
        assert "Test" in table
        assert "abc123" in table

    def test_table_has_coloured_score(self):
        entries = [{
            "label": "Test",
            "password": "abc123",
            "strength": 5,
            "category": "General",
            "timestamp": "Mon, Jan 01, 2024 12:00:00:000000 PM",
        }]
        table = format_history_table(entries)
        assert "\033[" in table

    def test_table_timestamp_format(self):
        entries = [{
            "label": "Test",
            "password": "abc123",
            "strength": 5,
            "category": "General",
            "timestamp": "Mon, Jan 01, 2024 12:00:00:000000 PM",
        }]
        table = format_history_table(entries)
        assert "2024-01-01" in table


# ── Corrupt vault entry warning ──────────────────────────────────────────

class TestCorruptEntryWarning:

    def test_skipped_entry_warning(self, vault_dir, vault_key, vault_file, capsys):
        """A corrupt entry triggers a visible warning in show_password_history."""
        save_password("GoodPassword1!", vault_key, filename=vault_file)

        with open(vault_file, "ab") as f:
            corrupt_line = base64.b64encode(b"\x00\x01\x02bad_data") + b"\n"
            f.write(corrupt_line)

        show_password_history(vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "1 vault entry(ies) could not be decrypted" in out
        assert "GoodPassword1!" in out

    def test_multiple_corrupt_entries(self, vault_dir, vault_key, vault_file, capsys):
        """Multiple corrupt entries are counted."""
        save_password("ValidPw!", vault_key, filename=vault_file)

        corrupt = base64.b64encode(b"\xde\xad\xbe\xef" * 8) + b"\n"
        with open(vault_file, "ab") as f:
            f.writelines(corrupt for _ in range(3))

        show_password_history(vault_key, filename=vault_file)
        out = capsys.readouterr().out
        assert "3 vault entry(ies) could not be decrypted" in out


# ── NFC save normalization ───────────────────────────────────────────────

class TestNFCSaveNormalization:

    def test_save_normalizes_nfc(self, vault_dir, vault_key, vault_file):
        nfd_password = "e\u0301test"
        nfc_password = "\u00e9test"

        save_password(nfd_password, vault_key, filename=vault_file)

        raw = vault_file.read_bytes().strip()
        encrypted = base64.b64decode(raw)
        plaintext = decrypt_data(encrypted, vault_key, aad=VAULT_AAD)
        record = json.loads(plaintext)
        assert record["password"] == nfc_password
