"""
Tests for secure_password_generator.utils module.

Covers:
- verify_file_permissions (insecure perms, correct perms, nonexistent file)
- configure_logging (verbose, quiet)
"""

import logging

from secure_password_generator.utils import configure_logging, verify_file_permissions

# ── verify_file_permissions ──────────────────────────────────────────────

class TestVerifyFilePermissions:

    def test_warns_on_insecure_permissions(self, tmp_path, caplog):
        f = tmp_path / "insecure.key"
        f.write_text("secret")
        f.chmod(0o644)
        with caplog.at_level(logging.WARNING, logger="secure_password_generator"):
            verify_file_permissions(f)
        assert any("insecure permissions" in r.message for r in caplog.records)

    def test_silent_on_correct_permissions(self, tmp_path, caplog):
        f = tmp_path / "secure.key"
        f.write_text("secret")
        f.chmod(0o600)
        with caplog.at_level(logging.WARNING, logger="secure_password_generator"):
            verify_file_permissions(f)
        assert not any("insecure permissions" in r.message for r in caplog.records)

    def test_nonexistent_file_no_error(self, tmp_path):
        missing = tmp_path / "does_not_exist"
        verify_file_permissions(missing)


# ── configure_logging ────────────────────────────────────────────────────

class TestConfigureLogging:

    def test_verbose_sets_debug(self):
        configure_logging(verbose=True)
        logger = logging.getLogger("secure_password_generator")
        assert logger.level == logging.DEBUG

    def test_quiet_sets_error(self):
        configure_logging(quiet=True)
        logger = logging.getLogger("secure_password_generator")
        assert logger.level == logging.ERROR
