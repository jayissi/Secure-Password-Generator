#!/usr/bin/env python3
"""
Utility functions: secure file deletion, file permission checks, logging setup.
"""

import fcntl
import logging
import os
import secrets
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

import secure_password_generator.constants as _constants
from secure_password_generator.constants import (
    DEFAULT_FILE_PERMISSIONS,
    SECURE_DELETE_PASSES,
)

logger = logging.getLogger("secure_password_generator")


@contextmanager
def vault_lock():
    """Acquire an exclusive file lock on the vault directory.

    Prevents TOCTOU race conditions during read-modify-write vault
    operations by serialising access through ``fcntl.flock(LOCK_EX)``.
    """
    pw_dir = _constants.PASSWORD_DIR
    pw_dir.mkdir(mode=_constants.DEFAULT_DIR_PERMISSIONS, exist_ok=True)
    lock_path = pw_dir / ".vault.lock"
    fd = open(lock_path, "w")  # noqa: SIM115
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()


def configure_logging(*, verbose: bool = False, quiet: bool = False) -> None:
    """Configure the package-level logger.

    Args:
        verbose: Set log level to DEBUG.
        quiet: Set log level to ERROR (suppresses warnings).
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    pkg_logger = logging.getLogger("secure_password_generator")
    pkg_logger.handlers.clear()
    pkg_logger.addHandler(handler)
    pkg_logger.setLevel(level)


def verify_file_permissions(file_path: Path) -> None:
    """Warn if a security-sensitive file has permissions other than 0600."""
    if not file_path.exists():
        return
    mode = file_path.stat().st_mode & 0o777
    if mode != DEFAULT_FILE_PERMISSIONS:
        logger.warning(
            "%s has insecure permissions (%s). Expected %s. "
            "Run: chmod 600 %s",
            file_path,
            oct(mode),
            oct(DEFAULT_FILE_PERMISSIONS),
            file_path,
        )


def secure_delete_file(
    file_path: Path, passes: int = SECURE_DELETE_PASSES
) -> None:
    """Securely delete a file using shred (preferred) or manual overwrite fallback.

    Note: shred is effective on traditional block-device-backed filesystems
    (ext3, ext4 data=ordered, XFS).  It does NOT guarantee secure erasure on
    SSDs (wear-leveling), copy-on-write filesystems (btrfs, ZFS), or
    filesystems with data journaling (ext4 data=journal).

    Args:
        file_path: Path to file to securely delete.
        passes: Number of overwrite passes.
    """
    if not file_path.exists():
        return

    shred_bin = shutil.which("shred")
    if shred_bin:
        try:
            subprocess.run(
                [shred_bin, "-vuxzn", str(passes), str(file_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.SubprocessError as exc:
            raise OSError(f"shred failed: {exc}") from exc
    else:
        logger.warning(
            "shred not found; falling back to manual overwrite "
            "(limited effectiveness on modern filesystems)"
        )
        file_size = file_path.stat().st_size
        if file_size == 0:
            file_path.unlink()
            return
        with open(file_path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        file_path.unlink()


def parse_tags(raw: str) -> list[str] | None:
    """Parse a comma-separated tag string into a list.

    Returns:
        A list of stripped, non-empty tags, or ``None`` if the input
        is empty or contains only whitespace/commas.
    """
    if not raw:
        return None
    tags = [t.strip() for t in raw.split(",") if t.strip()]
    return tags or None
