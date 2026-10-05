"""
Tests for secure_password_generator.qrcode module.

Covers:
- display_qr terminal output
- save_qr file creation
"""

from unittest.mock import MagicMock, patch

from secure_password_generator.qrcode import display_qr, save_qr


class TestDisplayQR:

    def test_display_qr_calls_terminal(self):
        mock_qr = MagicMock()
        with patch("secure_password_generator.qrcode.segno") as mock_segno:
            mock_segno.make.return_value = mock_qr
            display_qr("secret123")
        mock_segno.make.assert_called_once_with("secret123")
        mock_qr.terminal.assert_called_once_with(compact=True)


class TestSaveQR:

    def test_save_qr_calls_save(self):
        mock_qr = MagicMock()
        with patch("secure_password_generator.qrcode.segno") as mock_segno:
            mock_segno.make.return_value = mock_qr
            save_qr("secret123", "/tmp/test.png")
        mock_segno.make.assert_called_once_with("secret123")
        mock_qr.save.assert_called_once_with("/tmp/test.png", scale=5)

    def test_save_qr_custom_scale(self):
        mock_qr = MagicMock()
        with patch("secure_password_generator.qrcode.segno") as mock_segno:
            mock_segno.make.return_value = mock_qr
            save_qr("secret123", "/tmp/test.png", scale=10)
        mock_qr.save.assert_called_once_with("/tmp/test.png", scale=10)
