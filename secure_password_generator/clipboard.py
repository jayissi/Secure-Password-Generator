"""
Clipboard operations: copy via pyperclip, auto-clear timer.
"""

import contextlib
import threading

import pyperclip

from secure_password_generator.constants import CLIPBOARD_CLEAR_SECONDS

_clipboard_state: dict[str, threading.Timer | None] = {"timer": None}


def copy_to_clipboard(text: str) -> bool:
    """Copy *text* to the system clipboard.

    Returns:
        ``True`` on success, ``False`` otherwise.
    """
    try:
        pyperclip.copy(text)
        return True
    except pyperclip.PyperclipException:
        return False


def schedule_clipboard_clear() -> None:
    """Schedule a daemon timer to clear the clipboard after the configured delay.

    Cancels any previously scheduled timer before starting a new one.
    """
    prev = _clipboard_state["timer"]
    if prev is not None:
        prev.cancel()

    def _clear() -> None:
        with contextlib.suppress(pyperclip.PyperclipException):
            pyperclip.copy("")

    timer = threading.Timer(CLIPBOARD_CLEAR_SECONDS, _clear)
    timer.daemon = True
    timer.start()
    _clipboard_state["timer"] = timer
