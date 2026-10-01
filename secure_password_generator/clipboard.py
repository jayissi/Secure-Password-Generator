"""
Clipboard operations: copy, auto-clear timer.
"""

import subprocess
import threading
from collections.abc import Callable

from secure_password_generator.constants import CLIPBOARD_CLEAR_SECONDS

_CLIPBOARD_INITIALIZED = False
_CLIPBOARD_METHOD: Callable[[str], bool] | None = None


def _initialize_clipboard() -> Callable[[str], bool] | None:
    """Detect and cache the best available clipboard method (Linux)."""
    global _CLIPBOARD_INITIALIZED, _CLIPBOARD_METHOD
    if _CLIPBOARD_INITIALIZED:
        return _CLIPBOARD_METHOD

    # Prefer pyperclip
    try:
        import pyperclip

        def _pyperclip_copy(text: str) -> bool:
            try:
                pyperclip.copy(text)
                return True
            except Exception:
                return False

        _CLIPBOARD_METHOD = _pyperclip_copy
        _CLIPBOARD_INITIALIZED = True
        return _CLIPBOARD_METHOD
    except ImportError:
        pass

    # Fallback: xclip
    try:

        def _xclip_copy(text: str) -> bool:
            try:
                process = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                process.communicate(text.encode("utf-8"), timeout=2)
                return process.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                return False

        _CLIPBOARD_METHOD = _xclip_copy
        _CLIPBOARD_INITIALIZED = True
        return _CLIPBOARD_METHOD
    except Exception:
        pass

    _CLIPBOARD_INITIALIZED = True
    return None


def _clear_clipboard() -> None:
    """Overwrite the clipboard with an empty string (auto-clear callback)."""
    method = _initialize_clipboard()
    if method is not None:
        try:
            method("")
        except Exception:
            pass


def copy_to_clipboard(password: str) -> bool:
    """Copy *password* to the system clipboard.

    Returns:
        ``True`` on success, ``False`` otherwise.
    """
    method = _initialize_clipboard()
    if method is None:
        return False
    try:
        return method(password)
    except Exception:
        return False


def schedule_clipboard_clear() -> None:
    """Schedule a daemon timer to clear the clipboard after the configured delay."""
    timer = threading.Timer(CLIPBOARD_CLEAR_SECONDS, _clear_clipboard)
    timer.daemon = True
    timer.start()
