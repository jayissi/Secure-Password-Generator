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

import secrets
from datetime import datetime

import pytest

from secure_password_generator.crypto import (
    decrypt_data,
    encrypt_data,
    get_encryption_key,
    initialize_security_files,
)
from secure_password_generator.history import (
    delete_entry_by_index,
    format_history_table,
    save_password,
    show_password_history,
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
        lines = [l for l in out.splitlines() if l.strip().startswith(("1.", "2.", "3."))]
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
