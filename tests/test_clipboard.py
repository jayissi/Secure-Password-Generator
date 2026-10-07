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

    def test_previous_timer_cancelled(self):
        """Calling schedule_clipboard_clear twice cancels the first timer."""
        from secure_password_generator.clipboard import _clipboard_state

        with patch(
            "secure_password_generator.clipboard.threading.Timer"
        ) as mock_timer:
            first_timer = mock_timer.return_value
            schedule_clipboard_clear()
            assert _clipboard_state["timer"] is first_timer

            second_timer = type(mock_timer.return_value)()
            mock_timer.return_value = second_timer
            schedule_clipboard_clear()
            first_timer.cancel.assert_called_once()
            assert _clipboard_state["timer"] is second_timer

    def test_no_cancel_when_no_previous(self):
        """First call doesn't crash when no previous timer exists."""
        from secure_password_generator.clipboard import _clipboard_state

        _clipboard_state["timer"] = None
        with patch(
            "secure_password_generator.clipboard.threading.Timer"
        ) as mock_timer:
            mock_instance = mock_timer.return_value
            schedule_clipboard_clear()
            mock_instance.start.assert_called_once()

    def test_clear_callback_calls_pyperclip(self):
        """The timer callback clears the clipboard via pyperclip.copy."""
        with patch(
            "secure_password_generator.clipboard.threading.Timer"
        ) as mock_timer_cls:
            calls = {}
            def capture_timer(delay, fn):
                calls["fn"] = fn
                return type(mock_timer_cls.return_value)()

            mock_timer_cls.side_effect = capture_timer
            schedule_clipboard_clear()

            assert "fn" in calls
            with patch.object(pyperclip, "copy") as mock_copy:
                calls["fn"]()
            mock_copy.assert_called_once_with("")

    def test_clear_callback_suppresses_error(self):
        """The timer callback suppresses PyperclipException."""
        with patch(
            "secure_password_generator.clipboard.threading.Timer"
        ) as mock_timer_cls:
            calls = {}
            def capture_timer(delay, fn):
                calls["fn"] = fn
                return type(mock_timer_cls.return_value)()

            mock_timer_cls.side_effect = capture_timer
            schedule_clipboard_clear()

            with patch.object(
                pyperclip, "copy",
                side_effect=pyperclip.PyperclipException("no clip"),
            ):
                calls["fn"]()
