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
