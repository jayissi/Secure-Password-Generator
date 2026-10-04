"""
Tests for secure_password_generator.clipboard module.

Covers:
- copy_to_clipboard success and failure paths
- schedule_clipboard_clear timer behaviour
"""

from unittest.mock import patch

import pyperclip

from secure_password_generator.clipboard import (
    copy_to_clipboard,
    schedule_clipboard_clear,
)


class TestCopyToClipboard:

    def test_success(self):
        with patch.object(pyperclip, "copy") as mock_copy:
            result = copy_to_clipboard("secret")
        assert result is True
        mock_copy.assert_called_once_with("secret")

    def test_failure(self):
        with patch.object(
            pyperclip, "copy",
            side_effect=pyperclip.PyperclipException("no clipboard"),
        ):
            result = copy_to_clipboard("secret")
        assert result is False


class TestScheduleClipboardClear:

    def test_timer_starts(self):
        with patch(
            "secure_password_generator.clipboard.threading.Timer"
        ) as mock_timer:
            mock_instance = mock_timer.return_value
            schedule_clipboard_clear()
            mock_timer.assert_called_once()
            assert mock_instance.daemon is True
            mock_instance.start.assert_called_once()
