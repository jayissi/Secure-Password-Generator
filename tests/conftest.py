#!/usr/bin/env python3
"""
Shared pytest fixtures and helpers for the Secure Password Generator test suite.
"""

import io
import os
import sys
from dataclasses import dataclass
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Test-mode Argon2id: set BEFORE any secure_password_generator import.
#
# This must be a module-level statement, not a fixture, because pytest
# loads conftest.py before collecting test files.  Test files trigger
# ``from secure_password_generator.crypto import ...`` which imports
# constants.py.  The env var must already be set by that point so the
# ``if os.environ.get("SPG_TEST_KDF")`` guard in constants.py activates.
# ---------------------------------------------------------------------------
os.environ["SPG_TEST_KDF"] = "1"


# ---------------------------------------------------------------------------
# Vault directory isolation
# ---------------------------------------------------------------------------

# Map of module -> set of path constants that module actually imports.
# history.py and cli.py resolve PASSWORD_FILE at call time via
# _constants.PASSWORD_FILE, so patching constants is sufficient.
_PATH_IMPORTS: dict[str, set[str]] = {
    "secure_password_generator.constants": {
        "PASSWORD_DIR", "PASSWORD_FILE", "KEY_FILE",
        "PEPPER_FILE", "MASTER_SALT_FILE",
    },
    "secure_password_generator.crypto": {
        "PASSWORD_DIR", "PASSWORD_FILE", "KEY_FILE",
        "PEPPER_FILE", "MASTER_SALT_FILE",
    },
}


@pytest.fixture()
def vault_dir(tmp_path):
    """Redirect all vault paths to a temporary directory.

    Patches PASSWORD_DIR and its derived paths in every module that
    imports them, so no test touches ``~/.secure_passwords/``.

    Clears the crypto key caches so each test starts fresh.
    """
    pw_dir = tmp_path / ".secure_passwords"
    pw_file = pw_dir / "vault.enc"
    key_file = pw_dir / "encryption.key"
    pepper_file = pw_dir / "pepper.key"
    master_salt = pw_dir / "master_salt.bin"

    name_to_value = {
        "PASSWORD_DIR": pw_dir,
        "PASSWORD_FILE": pw_file,
        "KEY_FILE": key_file,
        "PEPPER_FILE": pepper_file,
        "MASTER_SALT_FILE": master_salt,
    }

    patches = []
    for target, names in _PATH_IMPORTS.items():
        for name in names:
            patches.append(patch(f"{target}.{name}", name_to_value[name]))

    for p in patches:
        p.start()

    # Clear crypto caches so the fresh paths take effect
    from secure_password_generator.crypto import clear_crypto_caches

    clear_crypto_caches()

    yield tmp_path

    for p in patches:
        p.stop()

    clear_crypto_caches()


# ---------------------------------------------------------------------------
# In-process CLI runner
# ---------------------------------------------------------------------------

@dataclass
class CLIResult:
    """Result of an in-process ``main()`` call."""
    exit_code: int
    stdout: str
    stderr: str


def run_cli(*args: str, env: dict | None = None) -> CLIResult:
    """Call ``cli.main()`` in-process with the given CLI arguments.

    Patches ``sys.argv`` and captures stdout/stderr.  Returns a
    :class:`CLIResult` with the exit code (0 on success).

    Args:
        *args: CLI arguments (without the program name).
        env: Optional dict of environment variable overrides.
    """
    from secure_password_generator.cli import main

    out = io.StringIO()
    err = io.StringIO()

    env_patches = []
    if env:
        for k, v in env.items():
            env_patches.append(patch.dict(os.environ, {k: v}))

    for ep in env_patches:
        ep.start()

    with patch.object(sys, "argv", ["pwgen", *args]), \
         patch.object(sys, "stdout", out), \
         patch.object(sys, "stderr", err):
        try:
            main()
            code = 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 0

    for ep in env_patches:
        ep.stop()

    return CLIResult(
        exit_code=code,
        stdout=out.getvalue(),
        stderr=err.getvalue(),
    )
