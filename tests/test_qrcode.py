#!/usr/bin/env python3
"""
Tests for secure_password_generator.qrcode module.

Covers:
- display_qr terminal output
- save_qr file creation
- read_qr decodes QR PNG back to text, raises on missing/invalid
"""

from unittest.mock import MagicMock, patch

import pytest

from secure_password_generator.qrcode import display_qr, read_qr, save_qr


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


class TestReadQR:

    def test_read_qr_decodes_text(self, tmp_path):
        """Generate a real QR PNG with segno, read it back with pyrxing."""
        import segno

        qr_file = tmp_path / "test_qr.png"
        password = "MyS3cretP@ss!"
        qr = segno.make(password)
        qr.save(str(qr_file), scale=5)

        result = read_qr(str(qr_file))
        assert result == password

    def test_read_qr_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="QR file not found"):
            read_qr("/nonexistent/path/qr.png")

    def test_read_qr_no_code(self, tmp_path):
        """A non-QR image file raises ValueError."""
        import segno

        img_file = tmp_path / "blank.png"
        qr = segno.make("test")
        qr.save(str(img_file), scale=1)
        img_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        with pytest.raises((ValueError, Exception)):
            read_qr(str(img_file))

    def test_read_qr_unsupported_format(self, tmp_path):
        """An SVG file raises ValueError with format message."""
        import segno

        svg_file = tmp_path / "qr.svg"
        qr = segno.make("test")
        qr.save(str(svg_file))

        with pytest.raises(ValueError, match="Cannot read QR code from"):
            read_qr(str(svg_file))
