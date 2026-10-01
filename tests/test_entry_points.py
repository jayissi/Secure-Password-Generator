#!/usr/bin/env python3

"""
Subprocess smoke tests for installed entry points and system dependencies.

These are the only tests that shell out to the real binary.  Everything
else in the suite runs in-process for speed.
"""

import os
import shutil
import subprocess
import sys

import pytest


@pytest.fixture()
def _test_env():
    """Build an environment dict with SPG_TEST_KDF=1."""
    env = os.environ.copy()
    env["SPG_TEST_KDF"] = "1"
    return env


class TestEntryPoints:

    def test_pwgen_binary(self, _test_env):
        """The pip-installed ``pwgen`` binary exits 0 and prints a password."""
        result = subprocess.run(
            ["pwgen", "-F", "-L", "12", "-n"],
            capture_output=True, text=True, timeout=30, env=_test_env,
        )
        assert result.returncode == 0, (
            f"pwgen failed: {result.stderr}"
        )
        assert "Generated Password 1:" in result.stdout

    def test_python_m_entry_point(self, _test_env):
        """``python -m secure_password_generator`` exits 0."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_password_generator",
             "-F", "-L", "12", "-n"],
            capture_output=True, text=True, timeout=30, env=_test_env,
        )
        assert result.returncode == 0, (
            f"python -m failed: {result.stderr}"
        )
        assert "Generated Password 1:" in result.stdout


class TestSystemDependencies:

    def test_shred_available(self):
        """The ``shred`` binary is on PATH (required on Fedora/RHEL)."""
        assert shutil.which("shred") is not None, (
            "shred not found — install coreutils"
        )
