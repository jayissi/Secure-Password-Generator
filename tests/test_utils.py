"""
Tests for secure_password_generator.utils module.

Covers:
- verify_file_permissions (insecure perms, correct perms, nonexistent file)
- configure_logging (verbose, quiet)
- vault_lock (acquire/release, directory creation)
- secure_delete_file (empty file fallback)
"""

import logging

from secure_password_generator.utils import (
    configure_logging,
    vault_lock,
    verify_file_permissions,
)

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


# ── vault_lock ───────────────────────────────────────────────────────────

class TestVaultLock:

    def test_vault_lock_acquires_and_releases(self, vault_dir):
        """vault_lock creates the lock file, acquires, then releases."""
        import secure_password_generator.constants as _constants

        with vault_lock():
            lock_path = _constants.PASSWORD_DIR / ".vault.lock"
            assert lock_path.exists()

        assert lock_path.exists()

    def test_vault_lock_creates_directory(self, tmp_path):
        """vault_lock creates PASSWORD_DIR when it does not exist."""
        from unittest.mock import patch

        new_dir = tmp_path / "fresh_vault"
        assert not new_dir.exists()

        with patch(
            "secure_password_generator.constants.PASSWORD_DIR", new_dir
        ), vault_lock():
            assert new_dir.exists()

    def test_vault_lock_reentrant_sequentially(self, vault_dir):
        """Two sequential vault_lock calls succeed."""
        with vault_lock():
            pass
        with vault_lock():
            pass


# ── secure_delete_file ───────────────────────────────────────────────────

class TestSecureDeleteFile:

    def test_empty_file_fallback_deletes(self, tmp_path):
        """Empty file is deleted in the manual-overwrite fallback path."""
        from unittest.mock import patch

        from secure_password_generator.utils import secure_delete_file

        empty_file = tmp_path / "empty.dat"
        empty_file.write_bytes(b"")
        assert empty_file.exists()

        with patch("shutil.which", return_value=None):
            secure_delete_file(empty_file)

        assert not empty_file.exists()

    def test_nonempty_file_fallback_deletes(self, tmp_path):
        """Non-empty file is overwritten then deleted in fallback path."""
        from unittest.mock import patch

        from secure_password_generator.utils import secure_delete_file

        data_file = tmp_path / "data.dat"
        data_file.write_bytes(b"sensitive data here")
        assert data_file.exists()

        with patch("shutil.which", return_value=None):
            secure_delete_file(data_file)

        assert not data_file.exists()

    def test_nonexistent_file_noop(self, tmp_path):
        """secure_delete_file on a missing path does nothing."""
        from secure_password_generator.utils import secure_delete_file

        missing = tmp_path / "ghost.dat"
        secure_delete_file(missing)
