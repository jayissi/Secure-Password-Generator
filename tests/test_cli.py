#!/usr/bin/env python3

"""
Tests for secure_password_generator.cli module (in-process integration).

Covers:
- Master-password lifecycle (set, reject without, env-var, password-file)
- Generation modes (-F full, -c multiple, -P passphrase, pattern)
- CLI plumbing (-h help, config file, CLI override, --no-save-history)
- Cleanup (--cleanup, verify empty)
- No-master-password backward compatibility
"""

import os
from unittest.mock import patch

import pytest

from secure_password_generator.crypto import initialize_security_files
from tests.conftest import run_cli

MASTER_PW = "TestMaster12!x"


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture()
def vault(vault_dir):
    """Initialise security files in the isolated vault directory."""
    initialize_security_files()
    return vault_dir


@pytest.fixture()
def vault_with_master(vault):
    """Set up master password on the isolated vault."""
    result = run_cli(
        "--set-master-password", "--master-password", MASTER_PW
    )
    assert result.exit_code == 0, f"set-master-password failed: {result.stderr}"
    return vault


# ── Master-password lifecycle ────────────────────────────────────────────

class TestMasterPassword:

    def test_set_master_password(self, vault):
        result = run_cli(
            "--set-master-password", "--master-password", MASTER_PW
        )
        assert result.exit_code == 0
        assert "Master password configured" in result.stdout

    def test_vault_ops_fail_without_master(self, vault_with_master):
        result = run_cli("-F", "-L", "12")
        assert result.exit_code != 0

    def test_env_var_auth(self, vault_with_master):
        env_clean = {
            k: v for k, v in os.environ.items()
            if k != "SPG_MASTER_PASSWORD"
        }
        env_with_mp = {**env_clean, "SPG_MASTER_PASSWORD": MASTER_PW}
        with patch.dict(os.environ, env_with_mp, clear=True):
            result = run_cli("-F", "-L", "12", "-n")
        assert result.exit_code == 0
        assert "Generated Password" in result.stdout

    def test_password_file_auth(self, vault_with_master, tmp_path):
        pw_file = tmp_path / "master.txt"
        pw_file.write_text(MASTER_PW + "\n")
        pw_file.chmod(0o600)
        result = run_cli(
            "-F", "-L", "12", "-n",
            "--master-password-file", str(pw_file),
        )
        assert result.exit_code == 0
        assert "Generated Password" in result.stdout

    def test_wrong_master_no_readable_entries(self, vault_with_master):
        run_cli(
            "-F", "-L", "12",
            "--label", "Secret",
            "--master-password", MASTER_PW,
        )
        # Clear crypto caches to simulate a fresh process (as a real
        # attacker would have).
        import secure_password_generator.crypto as _crypto
        _crypto._KEY_CACHE.clear()
        _crypto._FINAL_KEY_CACHE.clear()
        _crypto._SESSION_TOKEN = None

        result = run_cli("-H", "--master-password", "WrongPassw0rd!")
        assert "Secret" not in result.stdout


# ── Generation modes ─────────────────────────────────────────────────────

class TestGenerationModes:

    def test_full_mode(self, vault):
        result = run_cli("-F", "-L", "16", "-n")
        assert result.exit_code == 0
        assert "Generated Password 1:" in result.stdout

    def test_multiple_count(self, vault):
        result = run_cli("-F", "-L", "12", "-c", "3", "-n")
        assert result.exit_code == 0
        assert "Generated Password 1:" in result.stdout
        assert "Generated Password 2:" in result.stdout
        assert "Generated Password 3:" in result.stdout

    def test_passphrase_mode(self, vault):
        result = run_cli(
            "-P", "MyCustomPhrase!", "--label", "Custom", "-n"
        )
        assert result.exit_code == 0
        assert "Custom Passphrase Mode" in result.stdout
        assert "MyCustomPhrase!" in result.stdout

    def test_pattern_generation(self, vault):
        result = run_cli("-p", "lluuddss", "-n")
        assert result.exit_code == 0
        assert "Generated Password 1:" in result.stdout

    def test_pattern_with_wildcard(self, vault):
        result = run_cli("-p", "****lluu", "-n")
        assert result.exit_code == 0
        assert "Generated Password 1:" in result.stdout


# ── CLI plumbing ─────────────────────────────────────────────────────────

class TestCLIPlumbing:

    def test_help_exits_zero(self, vault):
        result = run_cli("-h")
        assert result.exit_code == 0
        assert "Generate strong random passwords" in result.stdout

    def test_no_args_shows_help(self, vault):
        result = run_cli()
        assert result.exit_code == 0

    def test_config_yaml_applied(self, vault, tmp_path):
        cfg = tmp_path / "test.yaml"
        cfg.write_text("length: 20\nupper: true\nlower: true\n")
        result = run_cli("-f", str(cfg), "-n")
        assert result.exit_code == 0
        pw = _extract_password(result.stdout)
        assert len(pw) == 20

    def test_cli_override_beats_config(self, vault, tmp_path):
        cfg = tmp_path / "test.yaml"
        cfg.write_text("length: 10\nupper: true\nlower: true\n")
        result = run_cli("-f", str(cfg), "-L", "24", "-n")
        assert result.exit_code == 0
        pw = _extract_password(result.stdout)
        assert len(pw) == 24

    def test_config_json_applied(self, vault, tmp_path):
        cfg = tmp_path / "test.json"
        cfg.write_text('{"length": 18, "upper": true, "lower": true, "digits": true}')
        result = run_cli("-f", str(cfg), "-n")
        assert result.exit_code == 0
        pw = _extract_password(result.stdout)
        assert len(pw) == 18

    def test_no_save_history(self, vault):
        result1 = run_cli("-F", "-L", "12", "-n")
        assert result1.exit_code == 0
        from secure_password_generator import constants
        assert not constants.PASSWORD_FILE.exists()


# ── Cleanup ──────────────────────────────────────────────────────────────

class TestCleanup:

    def test_cleanup_removes_files(self, vault):
        run_cli("-F", "-L", "12", "--label", "test")
        result = run_cli("-C")
        assert result.exit_code == 0
        assert "Securely removed" in result.stdout

    def test_vault_empty_after_cleanup(self, vault):
        run_cli("-F", "-L", "12", "--label", "test")
        run_cli("-C")
        result = run_cli("-H")
        assert ("No password history" in result.stdout
                or "No entries to display" in result.stdout)


# ── No master password (backward compat) ─────────────────────────────────

class TestNoMasterPassword:

    def test_vault_works_without_master(self, vault):
        result = run_cli(
            "-F", "-L", "12", "--label", "NoMaster", "--category", "Compat"
        )
        assert result.exit_code == 0
        assert "Passwords securely saved" in result.stdout

        result2 = run_cli("-H")
        assert result2.exit_code == 0
        assert "NoMaster" in result2.stdout


# ── Latin-ext CLI ────────────────────────────────────────────────────────

class TestLatinExtCLI:

    def test_latin_ext_flag(self, vault):
        result = run_cli("-x", "-l", "-L", "16", "-n")
        assert result.exit_code == 0
        pw = _extract_password(result.stdout)
        assert any(ord(c) > 127 for c in pw), (
            f"Expected non-ASCII chars in: {pw!r}"
        )

    def test_full_plus_latin_ext(self, vault):
        result = run_cli("-F", "-x", "-L", "20", "-n")
        assert result.exit_code == 0
        pw = _extract_password(result.stdout)
        assert any(ord(c) > 127 for c in pw), (
            f"Expected non-ASCII chars in: {pw!r}"
        )


# ── Strength display format ─────────────────────────────────────────────

class TestStrengthDisplay:

    def test_single_password_inline_score(self, vault):
        result = run_cli("-F", "-L", "16", "-n", "-c", "1")
        assert result.exit_code == 0
        assert "/10]" in result.stdout
        assert "Strength Summary: 1 password generated" in result.stdout

    def test_multi_password_inline_scores(self, vault):
        result = run_cli("-F", "-L", "16", "-n", "-c", "3")
        assert result.exit_code == 0
        assert result.stdout.count("/10]") == 3
        assert "Strength Summary: 3 passwords generated" in result.stdout

    def test_summary_has_meter_bar(self, vault):
        result = run_cli("-F", "-L", "16", "-n", "-c", "2")
        assert result.exit_code == 0
        assert "\u2588" in result.stdout


# ── Interactive flag ─────────────────────────────────────────────────────

class TestInteractiveFlag:

    def test_interactive_flag_parsed(self, vault):
        from secure_password_generator.cli import create_argument_parser
        parser = create_argument_parser()
        args = parser.parse_args(["-i"])
        assert args.interactive is True


# ── CLI edge cases ───────────────────────────────────────────────────────

class TestCLIEdgeCases:

    def test_version_flag(self, vault):
        result = run_cli("-V")
        assert "2.0.0" in result.stdout

    def test_delete_entry_integration(self, vault):
        result1 = run_cli("-F", "-L", "12")
        assert result1.exit_code == 0
        result2 = run_cli("--delete-entry", "1")
        assert result2.exit_code == 0
        result3 = run_cli("-H")
        assert (
            "No password history" in result3.stdout
            or result3.stdout.count("Generated") == 0
        )

    def test_passphrase_save_mode(self, vault):
        result = run_cli("-P", "MyPhrase!", "--label", "PhraseTest")
        assert result.exit_code == 0
        result2 = run_cli("-H")
        assert "PhraseTest" in result2.stdout

    def test_show_history_with_search(self, vault):
        run_cli("-F", "-L", "12", "--label", "Gmail")
        run_cli("-F", "-L", "12", "--label", "Bank")
        result = run_cli("-H", "--search", "Gmail")
        assert "Gmail" in result.stdout
        assert "Bank" not in result.stdout


# ── Helpers ──────────────────────────────────────────────────────────────

def _extract_password(stdout: str) -> str:
    """Extract the password string from CLI stdout.

    The output line format is:
        ``Generated Password 1: <password>  <coloured_score>``
    Strip the trailing inline score (everything after the last ``  ``).
    """
    import re
    for line in stdout.splitlines():
        if "Generated Password" in line:
            raw = line.split(": ", 1)[1]
            # Remove ANSI escape codes and the trailing  [score/10]
            raw = re.sub(r"\s+\x1b\[.*$", "", raw)
            return raw
    raise ValueError(f"No 'Generated Password' line found in:\n{stdout}")
