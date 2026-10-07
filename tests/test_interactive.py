#!/usr/bin/env python3

"""
Tests for secure_password_generator.interactive module.

Covers:
- quick command (default length, custom length, regenerate, inline score)
- new command (defaults wizard, custom length, save with label, cancel)
- browse command (empty vault, populated vault, view detail)
- health command (empty vault, populated vault with distribution)
- Session lifecycle (quit, help, unknown command, EOF, CLI flag)
- generate command (single, batch, save prompt, copy, regenerate,
  no-save flag, batch display, save clears state, metadata flags)
- history, delete, cleanup, label commands
"""

import io

import pytest

from secure_password_generator.crypto import initialize_security_files
from secure_password_generator.history import save_password
from secure_password_generator.interactive import PwgenShell

# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture()
def vault(vault_dir):
    """Initialise security files in the isolated vault directory."""
    initialize_security_files()
    return vault_dir


@pytest.fixture()
def key(vault):
    """Return a usable encryption key for the isolated vault."""
    from secure_password_generator.crypto import get_encryption_key
    return get_encryption_key(None)


@pytest.fixture()
def populated_vault(vault, key):
    """Vault with three saved passwords."""
    save_password("Alpha1!xyz", key=key, label="Gmail",
                  category="Email", tags=["work"])
    save_password("Beta22@abc", key=key, label="Bank",
                  category="Finance", tags=["important"])
    save_password("Gamma3#qrs", key=key, label="VPN",
                  category="Network")
    return vault


def _make_repl(stdin_text: str) -> PwgenShell:
    """Create a PwgenShell driven by a StringIO stdin for cmdloop() tests."""
    shell = PwgenShell(stdin=io.StringIO(stdin_text))
    shell.use_rawinput = False
    return shell


# ── TestQuickCommand ─────────────────────────────────────────────────────

class TestQuickCommand:

    def test_default_length(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert "/10]" in out

    def test_custom_length(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_quick("32")
        out = capsys.readouterr().out
        assert "/10]" in out

    def test_invalid_length(self, vault, capsys):
        shell = PwgenShell()
        shell.do_quick("abc")
        out = capsys.readouterr().out
        assert "Invalid length" in out

    def test_regenerate_prompt(self, vault, capsys, monkeypatch):
        inputs = iter(["r", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert out.count("/10]") >= 2


# ── TestNewCommand ───────────────────────────────────────────────────────

class TestNewCommand:

    def test_defaults_wizard(self, vault, capsys, monkeypatch):
        inputs = iter(["", "", "", "", "", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_new("")
        out = capsys.readouterr().out
        assert "/10]" in out

    def test_custom_length(self, vault, capsys, monkeypatch):
        inputs = iter(["16", "", "", "", "", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_new("")
        out = capsys.readouterr().out
        assert "/10]" in out

    def test_save_with_label(self, vault, capsys, monkeypatch):
        inputs = iter([
            "", "", "", "", "",
            "s", "MyLabel", "MyCategory", "tag1,tag2",
        ])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_new("")
        out = capsys.readouterr().out
        assert "saved to vault" in out

    def test_cancel_wizard_eof(self, vault, capsys, monkeypatch):
        def _raise_eof(_p=""):
            raise EOFError
        monkeypatch.setattr("builtins.input", _raise_eof)
        shell = PwgenShell()
        shell.do_new("")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()


# ── TestBrowseCommand ────────────────────────────────────────────────────

class TestBrowseCommand:

    def test_empty_vault(self, vault, capsys):
        shell = PwgenShell()
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "empty" in out.lower()

    def test_populated_vault_shows_entries(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Gmail" in out
        assert "Bank" in out

    def test_view_entry_detail(self, populated_vault, key, capsys, monkeypatch):
        inputs = iter(["v 1", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Label:" in out
        assert "Password:" in out


# ── TestHealthCommand ────────────────────────────────────────────────────

class TestHealthCommand:

    def test_empty_vault(self, vault, capsys):
        shell = PwgenShell()
        shell.do_health("")
        out = capsys.readouterr().out
        assert "empty" in out.lower()

    def test_populated_vault(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_health("")
        out = capsys.readouterr().out
        assert "Total passwords: 3" in out
        assert "Score distribution" in out


# ── TestSessionLifecycle ─────────────────────────────────────────────────

class TestSessionLifecycle:

    def test_quit_returns_true(self, vault, capsys):
        shell = PwgenShell()
        result = shell.do_quit("")
        assert result is True
        out = capsys.readouterr().out
        assert "Goodbye" in out

    def test_help_lists_commands(self, vault, capsys):
        shell = _make_repl("help\nquit\n")
        shell.cmdloop()
        out = capsys.readouterr().out
        assert "quick" in out
        assert "browse" in out
        assert "health" in out

    def test_unknown_command(self, vault, capsys):
        shell = _make_repl("foobar\nquit\n")
        shell.cmdloop()
        out = capsys.readouterr().out
        assert "Unknown command" in out

    def test_eof_exits(self, vault, capsys):
        shell = PwgenShell()
        result = shell.do_EOF("")
        assert result is True

    def test_clear_does_not_crash(self, vault, capsys):
        shell = PwgenShell()
        result = shell.do_clear("")
        assert result is None
        out = capsys.readouterr().out
        assert "\033[H\033[2J" in out

    def test_interactive_flag_accepted(self, vault):
        from secure_password_generator.cli import create_argument_parser
        parser = create_argument_parser()
        args = parser.parse_args(["-i"])
        assert args.interactive is True

    def test_exit_returns_true(self, vault, capsys):
        shell = PwgenShell()
        result = shell.do_exit("")
        assert result is True

    def test_emptyline_does_nothing(self, vault, capsys):
        shell = PwgenShell()
        result = shell.emptyline()
        assert result is False
        out = capsys.readouterr().out
        assert out == ""


# ── TestGenerateCommand ──────────────────────────────────────────────────

class TestGenerateCommand:

    def test_generate_full(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_generate("-F -L 20")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out
        assert "/10]" in out
        assert "Strength Summary" in out

    def test_generate_count(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_generate("-F -L 12 -c 3")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out
        assert "Generated Password 3:" in out
        assert out.count("/10]") >= 3
        assert "Strength Summary" in out

    def test_generate_sets_last_password(self, vault, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_generate("-F -L 16")
        assert shell._last_password is not None
        assert len(shell._last_password) == 16
        assert shell._last_pool_size is not None

    def test_generate_invalid_flag(self, vault, capsys):
        shell = PwgenShell()
        shell.do_generate("--bad-flag")
        out = capsys.readouterr().out
        assert "unrecognized" in out.lower()

    def test_quick_sets_last_password(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_quick("16")
        assert shell._last_password is not None
        assert shell._last_pool_size is not None

    def test_generate_save_prompt(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "TestSave", "Testing", "a,b"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 16")
        out = capsys.readouterr().out
        assert "saved to vault" in out

    def test_generate_batch_save(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "Batch", "General", ""])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12 -c 3")
        out = capsys.readouterr().out
        assert "3 passwords saved to vault" in out

    def test_generate_copy_prompt(self, vault, capsys, monkeypatch):
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert "Copied" in out or "Clipboard not available" in out

    def test_generate_regenerate_prompt(self, vault, capsys, monkeypatch):
        inputs = iter(["r", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert out.count("Generated Password 1:") >= 2

    def test_generate_no_save_flag_skips_prompt(self, vault, capsys):
        shell = PwgenShell()
        shell.do_generate("-F -L 12 -n")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out
        assert "Strength Summary" in out

    def test_generate_batch_display(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "q")
        shell = PwgenShell()
        shell.do_generate("-F -L 12 -c 3")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out
        assert "Generated Password 2:" in out
        assert "Generated Password 3:" in out

    def test_generate_save_clears_last_password(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        assert shell._last_password is None
        assert shell._last_pool_size is None

    def test_generate_with_metadata(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12 --label Gmail --category Email")
        capsys.readouterr()

        shell.do_history("")
        out = capsys.readouterr().out
        assert "Gmail" in out


# ── TestHistoryCommand ───────────────────────────────────────────────────

class TestHistoryCommand:

    def test_history_empty(self, vault, capsys):
        shell = PwgenShell()
        shell.do_history("")
        out = capsys.readouterr().out
        assert "No" in out or "history" in out.lower()

    def test_history_populated(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_history("")
        out = capsys.readouterr().out
        assert "Gmail" in out
        assert "Bank" in out

    def test_history_search(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_history("--search Gmail")
        out = capsys.readouterr().out
        assert "Gmail" in out

    def test_history_limit(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_history("--limit 1")
        out = capsys.readouterr().out
        assert "Gmail" in out or "Bank" in out or "VPN" in out


# ── TestDeleteCommand ────────────────────────────────────────────────────

class TestDeleteCommand:

    def test_delete_entry(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_delete("1")
        out = capsys.readouterr().out
        assert "deleted" in out.lower()

    def test_delete_no_arg(self, vault, capsys):
        shell = PwgenShell()
        shell.do_delete("")
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_delete_invalid_index(self, vault, capsys):
        shell = PwgenShell()
        shell.do_delete("abc")
        out = capsys.readouterr().out
        assert "Invalid index" in out


# ── TestCleanupCommand ───────────────────────────────────────────────────

class TestCleanupCommand:

    def test_cleanup_confirmed(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "y")
        shell = PwgenShell()
        shell.do_cleanup("")
        out = capsys.readouterr().out
        assert "Session key cleared" in out

    def test_cleanup_cancelled(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "n")
        shell = PwgenShell()
        shell.do_cleanup("")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()

    def test_cleanup_eof(self, vault, capsys, monkeypatch):
        def _raise_eof(_p=""):
            raise EOFError
        monkeypatch.setattr("builtins.input", _raise_eof)
        shell = PwgenShell()
        shell.do_cleanup("")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()


# ── TestLabelCommand ─────────────────────────────────────────────────────

class TestLabelCommand:

    def test_label_updates_metadata(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_label('1 --label Updated')
        out = capsys.readouterr().out
        assert "updated" in out.lower()

        shell.do_history('')
        out2 = capsys.readouterr().out
        assert "Updated" in out2

    def test_label_invalid_index(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_label('99')
        out = capsys.readouterr().out
        assert "Invalid index" in out

    def test_label_no_args(self, vault, capsys):
        shell = PwgenShell()
        shell.do_label('')
        out = capsys.readouterr().out
        assert (
            out == ""
            or "error" in out.lower()
            or "usage" in out.lower()
            or "required" in out.lower()
        )

    def test_generate_with_metadata(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate('-F -L 12 --label Gmail --category Email')
        capsys.readouterr()

        shell.do_history('')
        out = capsys.readouterr().out
        assert "Gmail" in out


# ── TestBrowseExtended ───────────────────────────────────────────────────

class TestBrowseExtended:

    def test_browse_next_prev(self, vault, key, capsys, monkeypatch):
        """Test pagination: next, prev, then quit."""
        from secure_password_generator.crypto import initialize_security_files
        initialize_security_files()
        for i in range(7):
            save_password(f"pw{i}", key=key, label=f"Entry{i}")
        inputs = iter(["n", "p", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Page 1/" in out

    def test_browse_search(self, populated_vault, key, capsys, monkeypatch):
        inputs = iter(["s", "gmail", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "match" in out.lower()

    def test_browse_invalid_entry(self, populated_vault, key, capsys, monkeypatch):
        inputs = iter(["v 99", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Invalid entry" in out

    def test_browse_view_copy_back(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v 1", "c", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Password:" in out
        assert "Copied" in out or "Clipboard not available" in out

    def test_browse_eof(self, populated_vault, key, capsys, monkeypatch):
        call_count = [0]
        def _eof_on_second(_p=""):
            call_count[0] += 1
            if call_count[0] > 1:
                raise EOFError
            return "q"
        monkeypatch.setattr("builtins.input", _eof_on_second)
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")

    def test_browse_invalid_choice(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["x", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Please choose" in out

    def test_browse_view_number_prompt(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v", "1", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Password:" in out

    def test_browse_search_no_match(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["s", "zzzznonexistent", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "No matches" in out

    def test_browse_already_last_page(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["n", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "last page" in out.lower()

    def test_browse_already_first_page(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["p", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "first page" in out.lower()

    def test_browse_invalid_view_number(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v abc", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Invalid number" in out


# ── TestHealthExtended ───────────────────────────────────────────────────

class TestHealthExtended:

    def test_health_weak_warning(self, vault, key, capsys):
        from secure_password_generator.crypto import initialize_security_files
        initialize_security_files()
        save_password("a", key=key, label="Weak")
        shell = PwgenShell()
        shell._key = key
        shell.do_health("")
        out = capsys.readouterr().out
        assert "below 5/10" in out

    def test_health_duplicate_labels(self, vault, key, capsys):
        from secure_password_generator.crypto import initialize_security_files
        initialize_security_files()
        save_password("pw1", key=key, label="Dupe")
        save_password("pw2", key=key, label="Dupe")
        shell = PwgenShell()
        shell._key = key
        shell.do_health("")
        out = capsys.readouterr().out
        assert "Duplicate labels" in out


# ── TestQuickExtended ────────────────────────────────────────────────────

class TestQuickExtended:

    def test_quick_copy(self, vault, capsys, monkeypatch):
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert "Copied" in out or "Clipboard not available" in out

    def test_quick_save(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "QuickLabel", "QuickCat", "tag1"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert "saved to vault" in out

    def test_quick_eof(self, vault, capsys, monkeypatch):
        def _raise_eof(_p=""):
            raise EOFError
        monkeypatch.setattr("builtins.input", _raise_eof)
        shell = PwgenShell()
        shell.do_quick("")

    def test_quick_invalid_then_quit(self, vault, capsys, monkeypatch):
        inputs = iter(["z", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert "Please choose" in out


# ── TestGenerateExtended ─────────────────────────────────────────────────

class TestGenerateExtended:

    def test_generate_save_batch_eof(self, vault, capsys, monkeypatch):
        call_count = [0]
        def _save_then_eof(_p=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "s"
            raise EOFError
        monkeypatch.setattr("builtins.input", _save_then_eof)
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()

    def test_generate_batch_copy_multi(self, vault, capsys, monkeypatch):
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12 -c 3")
        out = capsys.readouterr().out
        assert "Copied" in out or "Clipboard not available" in out


# ── TestQRCodeInteractive ───────────────────────────────────────────────

class TestQRCodeInteractive:

    def test_quick_qr(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["Q", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.display_qr"
        ) as mock_qr:
            shell = PwgenShell()
            shell.do_quick("")
        mock_qr.assert_called_once()

    def test_generate_qr(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["Q", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.display_qr"
        ) as mock_qr:
            shell = PwgenShell()
            shell.do_generate("-F -L 12")
        mock_qr.assert_called_once()

    def test_generate_batch_qr(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["Q", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.display_qr"
        ) as mock_qr:
            shell = PwgenShell()
            shell.do_generate("-F -L 12 -c 3")
        assert mock_qr.call_count == 3

    def test_browse_view_qr(self, populated_vault, key, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["v 1", "Q", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.display_qr"
        ) as mock_qr:
            shell = PwgenShell()
            shell._key = key
            shell.do_browse("")
        mock_qr.assert_called_once()


# ── Preloop / Authentication ─────────────────────────────────────────────

class TestPreloop:

    def test_preloop_no_master(self, vault):
        """No auth prompt when master password is not configured."""
        shell = PwgenShell()
        shell.preloop()

    def test_preloop_master_auth_fail(self, vault):
        from unittest.mock import patch as mock_patch
        with (
            mock_patch(
                "secure_password_generator.interactive.is_master_password_enabled",
                return_value=True,
            ),
            mock_patch(
                "secure_password_generator.interactive.prompt_master_password",
                side_effect=ValueError("bad"),
            ),
            pytest.raises(SystemExit),
        ):
            shell = PwgenShell()
            shell.preloop()


# ── Generate batch prompt actions ────────────────────────────────────────

class TestGenerateBatchPrompt:

    def test_generate_copy_batch(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with (
            mock_patch(
                "secure_password_generator.interactive.copy_to_clipboard",
                return_value=True,
            ),
            mock_patch(
                "secure_password_generator.interactive.schedule_clipboard_clear",
            ),
        ):
            shell = PwgenShell()
            shell.do_generate("-F -L 12 -c 2")
        out = capsys.readouterr().out
        assert "Copied 2 passwords" in out

    def test_generate_copy_fail(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.copy_to_clipboard",
            return_value=False,
        ):
            shell = PwgenShell()
            shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert "Clipboard not available" in out

    def test_generate_regenerate(self, vault, capsys, monkeypatch):
        inputs = iter(["r", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert out.count("Generated Password 1:") == 2

    def test_generate_invalid_choice(self, vault, capsys, monkeypatch):
        inputs = iter(["z", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert "Please choose" in out

    def test_generate_eof_prompt(self, vault, capsys, monkeypatch):
        def _raise_eof(_p=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise_eof)
        shell = PwgenShell()
        shell.do_generate("-F -L 12")

    def test_generate_nosave(self, vault, capsys, monkeypatch):
        """--no-save flag skips the action prompt entirely."""
        shell = PwgenShell()
        shell.do_generate("-F -L 12 --no-save")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out


# ── Save batch metadata ─────────────────────────────────────────────────

class TestSaveBatch:

    def test_save_with_flags(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate(
            "-F -L 12 --label FlagLabel --category Work --tags dev,ops"
        )
        out = capsys.readouterr().out
        assert "saved to vault" in out

    def test_save_eof(self, vault, capsys, monkeypatch):
        call_count = [0]
        def mock_input(_p=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "s"
            raise EOFError
        monkeypatch.setattr("builtins.input", mock_input)
        shell = PwgenShell()
        shell.do_generate("-F -L 12")
        out = capsys.readouterr().out
        assert "Save cancelled" in out


# ── Browse edge cases ────────────────────────────────────────────────────

class TestBrowseEdge:

    def test_browse_view_invalid_number(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v 99", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Invalid entry" in out

    def test_browse_view_nan(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v abc", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Invalid number" in out

    def test_browse_previous_first_page(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["p", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Already on the first page" in out

    def test_browse_next_last_page(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["n", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Already on the last page" in out

    def test_browse_search(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["s", "gmail", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "match" in out.lower()

    def test_browse_search_no_match(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["s", "zzzznotfound", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "No matches" in out

    def test_browse_invalid_choice(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["z", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Please choose" in out

    def test_browse_eof(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        monkeypatch.setattr(
            "builtins.input",
            lambda _p="": (_ for _ in ()).throw(EOFError),
        )
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")

    def test_view_entry_copy(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        from unittest.mock import patch as mock_patch
        inputs = iter(["v 1", "c", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with (
            mock_patch(
                "secure_password_generator.interactive.copy_to_clipboard",
                return_value=True,
            ),
            mock_patch(
                "secure_password_generator.interactive.schedule_clipboard_clear",
            ),
        ):
            shell = PwgenShell()
            shell._key = key
            shell.do_browse("")
        out = capsys.readouterr().out
        assert "Copied to clipboard" in out

    def test_view_entry_invalid_choice(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v 1", "x", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Please choose c, Q, or b" in out


# ── Cleanup command (edge cases) ─────────────────────────────────────────

class TestCleanupCommandEdge:

    def test_cleanup_confirm(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "y")
        shell = PwgenShell()
        shell.do_cleanup("")
        out = capsys.readouterr().out
        assert "Session key cleared" in out

    def test_cleanup_cancel(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _p="": "n")
        shell = PwgenShell()
        shell.do_cleanup("")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()

    def test_cleanup_eof(self, vault, capsys, monkeypatch):
        def _raise_eof(_p=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise_eof)
        shell = PwgenShell()
        shell.do_cleanup("")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()


# ── Clear command ────────────────────────────────────────────────────────

class TestClearCommand:

    def test_clear_prints_ansi(self, vault, capsys):
        shell = PwgenShell()
        shell.do_clear("")
        out = capsys.readouterr().out
        assert "\033[H\033[2J" in out


# ── Label command (edge cases) ───────────────────────────────────────────

class TestLabelCommandEdge:

    def test_label_update(self, populated_vault, key, capsys, monkeypatch):
        shell = PwgenShell()
        shell._key = key
        shell.do_label("1 --label NewLabel")
        out = capsys.readouterr().out
        assert "updated" in out.lower()

    def test_label_invalid_index(self, vault, capsys, monkeypatch):
        shell = PwgenShell()
        shell.do_label("abc")

    def test_label_no_args(self, vault, capsys, monkeypatch):
        shell = PwgenShell()
        shell.do_label("")


# ── Delete command (edge cases) ──────────────────────────────────────────

class TestDeleteCommandEdge:

    def test_delete_no_arg(self, vault, capsys):
        shell = PwgenShell()
        shell.do_delete("")
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_delete_invalid_arg(self, vault, capsys):
        shell = PwgenShell()
        shell.do_delete("abc")
        out = capsys.readouterr().out
        assert "Invalid index" in out

    def test_delete_entry(self, populated_vault, key, capsys):
        shell = PwgenShell()
        shell._key = key
        shell.do_delete("1")
        out = capsys.readouterr().out
        assert "deleted" in out.lower()


# ── History command (edge cases) ─────────────────────────────────────────

class TestHistoryCommandEdge:

    def test_history_with_search(
        self, populated_vault, key, capsys,
    ):
        shell = PwgenShell()
        shell._key = key
        shell.do_history("--search gmail")
        out = capsys.readouterr().out
        assert "Gmail" in out

    def test_history_empty(self, vault, capsys):
        shell = PwgenShell()
        shell.do_history("")
        out = capsys.readouterr().out
        assert "No password history" in out


# ── Quick command edge cases ─────────────────────────────────────────────

class TestQuickEdgeCases:

    def test_quick_save(self, vault, capsys, monkeypatch):
        inputs = iter(["s", "MyLabel", "MyCategory", "tag1,tag2"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert "saved to vault" in out.lower()

    def test_quick_regenerate(self, vault, capsys, monkeypatch):
        inputs = iter(["r", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")

    def test_quick_copy(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with (
            mock_patch(
                "secure_password_generator.interactive.copy_to_clipboard",
                return_value=True,
            ),
            mock_patch(
                "secure_password_generator.interactive.schedule_clipboard_clear",
            ),
        ):
            shell = PwgenShell()
            shell.do_quick("")
        out = capsys.readouterr().out
        assert "Copied to clipboard" in out

    def test_quick_copy_fail(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["c", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.copy_to_clipboard",
            return_value=False,
        ):
            shell = PwgenShell()
            shell.do_quick("")
        out = capsys.readouterr().out
        assert "Clipboard not available" in out

    def test_quick_invalid_choice(self, vault, capsys, monkeypatch):
        inputs = iter(["z", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_quick("")
        out = capsys.readouterr().out
        assert "Please choose" in out


# ── New command edge cases ───────────────────────────────────────────────

class TestNewEdgeCases:

    def test_new_no_charset(self, vault, capsys, monkeypatch):
        inputs = iter(["24", "n", "n", "n", "n"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_new("")
        out = capsys.readouterr().out
        assert "At least one character type" in out


# ── Generate with allowed_symbols ────────────────────────────────────────

class TestGenerateAllowedSymbols:

    def test_generate_allowed_symbols(self, vault, capsys, monkeypatch):
        inputs = iter(["q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-u -l -d -L 16 --allowed-symbols @#$")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out


# ── Browse view entry clipboard fail ─────────────────────────────────────

class TestViewEntryClipboardFail:

    def test_view_copy_fail(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        from unittest.mock import patch as mock_patch
        inputs = iter(["v 1", "c", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.copy_to_clipboard",
            return_value=False,
        ):
            shell = PwgenShell()
            shell._key = key
            shell.do_browse("")
        out = capsys.readouterr().out
        assert "Clipboard not available" in out


# ── Browse key error ─────────────────────────────────────────────────────

class TestBrowseKeyError:

    def test_browse_key_error(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        with mock_patch(
            "secure_password_generator.interactive.resolve_master_password",
            side_effect=ValueError("no key"),
        ):
            shell = PwgenShell()
            shell.do_browse("")
        out = capsys.readouterr().out
        assert "no key" in out


# ── Health key error ─────────────────────────────────────────────────────

class TestHealthKeyError:

    def test_health_key_error(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        with mock_patch(
            "secure_password_generator.interactive.resolve_master_password",
            side_effect=ValueError("no key"),
        ):
            shell = PwgenShell()
            shell.do_health("")
        out = capsys.readouterr().out
        assert "no key" in out


# ── Quick save error ─────────────────────────────────────────────────────

class TestQuickSaveError:

    def test_quick_save_error(self, vault, capsys, monkeypatch):
        from unittest.mock import patch as mock_patch
        inputs = iter(["s", "", "", ""])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        with mock_patch(
            "secure_password_generator.interactive.save_password",
            side_effect=ValueError("save error"),
        ):
            shell = PwgenShell()
            shell.do_quick("")
        out = capsys.readouterr().out
        assert "Save failed" in out


# ── New wizard EOF ───────────────────────────────────────────────────────

class TestNewWizardEOF:

    def test_new_eof(self, vault, capsys, monkeypatch):
        monkeypatch.setattr(
            "builtins.input",
            lambda _p="": (_ for _ in ()).throw(EOFError),
        )
        shell = PwgenShell()
        shell.do_new("")
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()


# ── Browse view EOF ──────────────────────────────────────────────────────

class TestViewEntryEOF:

    def test_view_eof(self, populated_vault, key, capsys, monkeypatch):
        call_count = [0]
        def mock_input(_p=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "v 1"
            raise EOFError
        monkeypatch.setattr("builtins.input", mock_input)
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")


# ── View entry number input ─────────────────────────────────────────────

class TestViewEntryNumberInput:

    def test_view_prompt_for_number(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        inputs = iter(["v", "1", "b", "q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")
        out = capsys.readouterr().out
        assert "Label" in out

    def test_view_prompt_eof(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        call_count = [0]
        def mock_input(_p=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "v"
            if call_count[0] == 2:
                raise EOFError
            return "q"
        monkeypatch.setattr("builtins.input", mock_input)
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")


# ── Browse search EOF ───────────────────────────────────────────────────

class TestBrowseSearchEOF:

    def test_search_eof(
        self, populated_vault, key, capsys, monkeypatch,
    ):
        call_count = [0]
        def mock_input(_p=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "s"
            raise EOFError
        monkeypatch.setattr("builtins.input", mock_input)
        shell = PwgenShell()
        shell._key = key
        shell.do_browse("")


# ── History / Delete / Label error edge cases ────────────────────────────

class TestHistoryCommandError:

    def test_history_error(self, vault, capsys):
        from unittest.mock import patch as mock_patch
        with mock_patch(
            "secure_password_generator.interactive.resolve_master_password",
            side_effect=ValueError("no key"),
        ):
            shell = PwgenShell()
            shell.do_history("")
        out = capsys.readouterr().out
        assert "no key" in out


class TestDeleteCommandError:

    def test_delete_error(self, vault, capsys):
        from unittest.mock import patch as mock_patch
        with mock_patch(
            "secure_password_generator.interactive.resolve_master_password",
            side_effect=ValueError("no key"),
        ):
            shell = PwgenShell()
            shell.do_delete("1")
        out = capsys.readouterr().out
        assert "no key" in out


class TestLabelCommandError:

    def test_label_error(self, vault, capsys):
        from unittest.mock import patch as mock_patch
        with mock_patch(
            "secure_password_generator.interactive.resolve_master_password",
            side_effect=ValueError("no key"),
        ):
            shell = PwgenShell()
            shell.do_label("1 --label test")
        out = capsys.readouterr().out
        assert "no key" in out


# ── Generate with allowed_symbols ────────────────────────────────────────

class TestGenerateWithAllowedSymbols:

    def test_generate_sets_symbols(self, vault, capsys, monkeypatch):
        inputs = iter(["q"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        shell = PwgenShell()
        shell.do_generate("-u -l -L 16 --allowed-symbols @#")
        out = capsys.readouterr().out
        assert "Generated Password 1:" in out
